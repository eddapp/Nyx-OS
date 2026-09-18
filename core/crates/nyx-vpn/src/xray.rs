//! Xray-core backend — VLESS, VMess, Trojan, and REALITY all live under one
//! binary (`xray`) and one JSON config schema; REALITY is not a fourth
//! protocol, it's `streamSettings.security = "reality"` plus a
//! `streamSettings.realitySettings` block on a VLESS outbound (confirmed
//! against xray-core's own `main/run.go`: the CLI is `xray run [-c
//! config.json] [-confdir dir]`, `-c`/`-config` being the flag that sets
//! the config file — there is no separate subcommand per protocol).
//!
//! Unlike WireGuard/AmneziaWG, Xray is not a kernel-level tunnel — it's a
//! long-lived userspace process that opens local listener socket(s)
//! (`inbounds` in its config) and relays through whichever outbound
//! protocol the profile configures. There is no kernel object to query for
//! truth the way `wg show`/`awg show` gives WireGuard/AmneziaWG a real
//! handshake signal, and none of VLESS/VMess/Trojan/REALITY expose a
//! handshake-recency concept of their own over a simple CLI query. So,
//! same honesty as `openvpn.rs`'s own documented weaker-signal limitation:
//! "is it really working" here is process-alive (the systemd unit is
//! active) plus a best-effort check that *something* is accepting TCP
//! connections on the configured local inbound port. That does not prove
//! the far end is reachable or that traffic is actually flowing —
//! `handler.rs` never reports this protocol as `Protected`.
//!
//! Lifecycle is a templated systemd unit
//! (`nyx-vpn-xray@<name>.service`, see `packaging/`) rather than nyx-vpn
//! babysitting a raw child process — real supervision/restart behavior,
//! consistent with how `openvpn.rs` drives `openvpn-client@.service`.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

pub(crate) const PROFILE_DIR: &str = "/etc/nyx/xray";

/// Tag of the synthetic Tor outbound `up_via_socks_proxy` splices into a
/// profile's runtime-only copy — arbitrary, but kept out of the tag
/// namespace a real profile would plausibly use on its own.
const TOR_OUTBOUND_TAG: &str = "nyx-tor";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-xray@{profile}.service")
}

fn runtime_config_path(profile: &str) -> String {
    format!("{}/nyx-vpn-xray-{profile}-via-tor.json", crate::socks_override::RUNTIME_DIR)
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                path.file_stem().and_then(|s| s.to_str()).map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// True when this profile still contains an unfilled
/// `WriteProviderTemplate` placeholder — see `util::INCOMPLETE_MARKER`.
pub fn is_incomplete(profile: &str) -> bool {
    crate::util::file_is_incomplete(&format!("{PROFILE_DIR}/{profile}.json"))
}

pub async fn up(conn: &Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await
}

pub async fn down(conn: &Connection, profile: &str) -> NyxResult<()> {
    let unit = unit_name(profile);
    let result = crate::systemd_ctl::stop_unit(conn, &unit).await;
    // Best-effort: undo any VPN-over-Tor override/runtime config so a
    // later plain `up()` doesn't silently keep dialing through Tor.
    crate::socks_override::remove_exec_start_override(&unit);
    let _ = fs::remove_file(runtime_config_path(profile));
    let _ = crate::systemd_ctl::reload(conn).await;
    result
}

/// VPN-over-Tor chaining. Xray-core's own `streamSettings.sockopt.
/// dialerProxy` field (confirmed against `transport/internet/config.pb.go`
/// — `SocketConfig.DialerProxy`, JSON field `dialerProxy` — and
/// `xtls.github.io`'s own sockopt docs: "a string. When the value is not
/// empty, the specified outbound will be used to initiate the connection.
/// Usually used to configure chained proxies.") points an outbound at
/// another outbound's `tag` to dial through instead of dialing directly.
///
/// This reads the profile's own JSON, sets `dialerProxy` on every real
/// outbound (skipping `freedom`/`blackhole`/`dns` passthrough sentinels,
/// which intentionally bypass the configured server and would be a silent
/// behavior change to chain too), appends a `socks` outbound pointing at
/// the given proxy, and writes the result to a *runtime-only* copy — the
/// profile file on disk is never rewritten. The templated unit's
/// `ExecStart=` is then overridden via a drop-in (see `socks_override.rs`)
/// to run against that runtime copy instead of the original.
pub async fn up_via_socks_proxy(
    conn: &Connection,
    profile: &str,
    socks_host: &str,
    socks_port: u16,
) -> NyxResult<()> {
    let original_path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(&original_path)
        .map_err(|e| NyxError::Config(format!("reading Xray profile '{profile}': {e}")))?;
    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| NyxError::Config(format!("parsing Xray profile '{profile}': {e}")))?;

    let outbounds = config
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            NyxError::Config(format!("Xray profile '{profile}' has no outbounds[] to chain through Tor"))
        })?;

    let mut chained_any = false;
    for outbound in outbounds.iter_mut() {
        let protocol = outbound.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
        if matches!(protocol, "freedom" | "blackhole" | "dns") {
            continue;
        }
        let obj = outbound.as_object_mut().ok_or_else(|| {
            NyxError::Config(format!("Xray profile '{profile}' has a malformed outbound entry"))
        })?;
        let stream_settings = obj.entry("streamSettings").or_insert_with(|| serde_json::json!({}));
        let stream_obj = stream_settings.as_object_mut().ok_or_else(|| {
            NyxError::Config(format!("Xray profile '{profile}': streamSettings is not an object"))
        })?;
        let sockopt = stream_obj.entry("sockopt").or_insert_with(|| serde_json::json!({}));
        let sockopt_obj = sockopt.as_object_mut().ok_or_else(|| {
            NyxError::Config(format!("Xray profile '{profile}': streamSettings.sockopt is not an object"))
        })?;
        sockopt_obj.insert("dialerProxy".to_string(), serde_json::Value::String(TOR_OUTBOUND_TAG.to_string()));
        chained_any = true;
    }
    if !chained_any {
        return Err(NyxError::Config(format!(
            "Xray profile '{profile}' has no chainable outbound (only direct/blackhole/dns) — \
             nothing to route through Tor"
        )));
    }

    outbounds.push(serde_json::json!({
        "tag": TOR_OUTBOUND_TAG,
        "protocol": "socks",
        "settings": {
            "servers": [{ "address": socks_host, "port": socks_port }]
        }
    }));

    let runtime_path = runtime_config_path(profile);
    fs::create_dir_all(crate::socks_override::RUNTIME_DIR)
        .map_err(|e| NyxError::Config(format!("creating {}: {e}", crate::socks_override::RUNTIME_DIR)))?;
    let rendered = serde_json::to_vec_pretty(&config).map_err(NyxError::from)?;
    fs::write(&runtime_path, rendered)
        .map_err(|e| NyxError::Config(format!("writing runtime Xray-via-Tor config: {e}")))?;

    let unit = unit_name(profile);
    let exec_start = format!("/usr/bin/xray run -c {runtime_path}");
    if let Err(e) = crate::socks_override::write_exec_start_override(&unit, &exec_start) {
        let _ = fs::remove_file(&runtime_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::reload(conn).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = fs::remove_file(&runtime_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::start_unit(conn, &unit).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = fs::remove_file(&runtime_path);
        let _ = crate::systemd_ctl::reload(conn).await;
        return Err(e);
    }
    Ok(())
}

pub async fn is_active(conn: &Connection, profile: &str) -> NyxResult<bool> {
    crate::systemd_ctl::is_active(conn, &unit_name(profile)).await
}

/// Best-effort discovery of which configured profile (if any) currently
/// has an active systemd unit — used by Status to find a connection this
/// daemon didn't itself start (e.g. after a restart).
pub async fn find_active_profile(conn: &Connection) -> Option<String> {
    for profile in list_profiles() {
        if is_active(conn, &profile).await.unwrap_or(false) {
            return Some(profile);
        }
    }
    None
}

/// Parse the first inbound's `listen`/`port` out of a profile's JSON
/// config — the local address a client (or nyx-vpn's own status probe)
/// would connect to. `None` if the file is missing, isn't valid JSON, or
/// has no usable `inbounds[0]`.
pub fn configured_local_addr(profile: &str) -> Option<SocketAddr> {
    let path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&contents).ok()?;
    let inbound = config.get("inbounds")?.as_array()?.first()?;
    let port = inbound.get("port")?.as_u64()?;
    let port = u16::try_from(port).ok()?;
    let listen = inbound.get("listen").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
    // "0.0.0.0"/"::" bind everywhere, including loopback — connect to
    // loopback rather than to the literal unspecified address.
    let ip: IpAddr = match listen {
        "0.0.0.0" | "" => IpAddr::from([127, 0, 0, 1]),
        "::" => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        other => other.parse().ok()?,
    };
    Some(SocketAddr::new(ip, port))
}

/// Best-effort liveness signal: does *something* accept a TCP connection
/// on the profile's configured inbound port. This proves the process has
/// a listener up, nothing more — it is not a handshake or an end-to-end
/// reachability check of the configured outbound (VLESS/VMess/Trojan/
/// REALITY) server.
pub fn local_proxy_reachable(profile: &str) -> bool {
    let Some(addr) = configured_local_addr(profile) else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}
