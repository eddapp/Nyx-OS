//! shadowsocks-rust backend — `sslocal`/`ssserver`/`ssservice`/`ssurl` are
//! the binaries the `shadowsocks-rust` package (official `extra` repo)
//! ships. Lifecycle here goes through `ssservice local -c <config>.json`
//! under that package's *own* upstream-shipped `shadowsocks-rust@.service`
//! template unit — confirmed against Arch's packaging repo, whose
//! `ExecStart` is `/usr/bin/ssservice local --log-without-time -c
//! /etc/shadowsocks-rust/%i.json`. nyx-vpn does not ship or generate this
//! unit itself; it just starts/stops the instance already provided,
//! exactly the same shape as `openvpn.rs` driving `openvpn-client@.service`.
//! That also fixes the profile directory: it has to be
//! `/etc/shadowsocks-rust/` to match `%i` in that unit, not an nyx-owned
//! path.
//!
//! shadowsocks-rust *does* have a real `"protocol": "tun"` local-server
//! mode (feature `local-tun`, built into Arch's package via its
//! `--features full-extra` build) that creates a genuine TUN interface —
//! but using it means nyx-vpn also owning that TUN device's creation,
//! addressing, and teardown, plus default-route management, the same
//! scope this crate deliberately takes on for the SOCKS5 backend in
//! `dante.rs` and nowhere else this round. Here, profiles use
//! shadowsocks-rust's plain local SOCKS5/HTTP proxy mode instead, so the
//! honesty match is with `xray.rs`, not `wireguard.rs`: no kernel object
//! to query, no handshake-recency concept, so "is it really working" is
//! process-alive plus a best-effort local-port reachability check —
//! `handler.rs` never reports this protocol as `Protected`.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

pub(crate) const PROFILE_DIR: &str = "/etc/shadowsocks-rust";

fn unit_name(profile: &str) -> String {
    format!("shadowsocks-rust@{profile}.service")
}

fn runtime_config_path(profile: &str) -> String {
    format!("{}/nyx-vpn-shadowsocks-{profile}-via-tor.json", crate::socks_override::RUNTIME_DIR)
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            // `.json` only — deliberately excludes the package's own
            // `config_rust.json.example`/`config_ext_rust.json.example`,
            // whose extension is `.example`, not `.json`.
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

/// VPN-over-Tor chaining. shadowsocks-rust's own `outbound_proxy` config
/// field (confirmed against its `crates/shadowsocks-service/src/
/// config.rs`: `SSConfig.outbound_proxy: Option<SSOutboundProxyConfig>`,
/// accepting either a single `"socks5://host:port"` URL string or an
/// array for a multi-hop chain — present in shadowsocks-rust 1.25.0, the
/// version this project ships) routes `sslocal`'s own uplink to the
/// configured Shadowsocks server through another proxy first.
///
/// This reads the profile's own JSON, sets top-level `outbound_proxy` to
/// a single `socks5://` URL for the given proxy, and writes the result to
/// a *runtime-only* copy — the profile file on disk is never rewritten.
/// The vendor-shipped `shadowsocks-rust@.service` unit's `ExecStart=` is
/// then overridden via a drop-in (see `socks_override.rs`) to run against
/// that runtime copy instead of the original.
pub async fn up_via_socks_proxy(
    conn: &Connection,
    profile: &str,
    socks_host: &str,
    socks_port: u16,
) -> NyxResult<()> {
    let original_path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(&original_path)
        .map_err(|e| NyxError::Config(format!("reading Shadowsocks profile '{profile}': {e}")))?;
    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| NyxError::Config(format!("parsing Shadowsocks profile '{profile}': {e}")))?;
    let obj = config
        .as_object_mut()
        .ok_or_else(|| NyxError::Config(format!("Shadowsocks profile '{profile}' is not a JSON object")))?;
    obj.insert(
        "outbound_proxy".to_string(),
        serde_json::Value::String(format!("socks5://{socks_host}:{socks_port}")),
    );

    let runtime_path = runtime_config_path(profile);
    fs::create_dir_all(crate::socks_override::RUNTIME_DIR)
        .map_err(|e| NyxError::Config(format!("creating {}: {e}", crate::socks_override::RUNTIME_DIR)))?;
    let rendered = serde_json::to_vec_pretty(&config).map_err(NyxError::from)?;
    fs::write(&runtime_path, rendered)
        .map_err(|e| NyxError::Config(format!("writing runtime Shadowsocks-via-Tor config: {e}")))?;

    let unit = unit_name(profile);
    let exec_start = format!("/usr/bin/ssservice local --log-without-time -c {runtime_path}");
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

/// Parse the local proxy's bind address out of a profile's JSON config.
/// shadowsocks-rust accepts either a top-level `local_address`/
/// `local_port` pair, or a `locals` array (first entry used here) — both
/// are real, documented shapes of the same config file.
pub fn configured_local_addr(profile: &str) -> Option<SocketAddr> {
    let path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&contents).ok()?;

    let (addr, port) = if let Some(port) = config.get("local_port").and_then(|v| v.as_u64()) {
        let addr = config.get("local_address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
        (addr.to_string(), port)
    } else {
        let first = config.get("locals")?.as_array()?.first()?;
        let port = first.get("local_port")?.as_u64()?;
        let addr = first.get("local_address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
        (addr.to_string(), port)
    };

    let port = u16::try_from(port).ok()?;
    let ip: IpAddr = match addr.as_str() {
        "0.0.0.0" | "" => IpAddr::from([127, 0, 0, 1]),
        "::" => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        other => other.parse().ok()?,
    };
    Some(SocketAddr::new(ip, port))
}

/// Best-effort liveness signal: does *something* accept a TCP connection
/// on the profile's configured local port. Proves a listener exists,
/// nothing about the encrypted link to the remote `ssserver` actually
/// working.
pub fn local_proxy_reachable(profile: &str) -> bool {
    let Some(addr) = configured_local_addr(profile) else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}
