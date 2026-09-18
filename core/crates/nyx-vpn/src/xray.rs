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

use nyx_core::NyxResult;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

const PROFILE_DIR: &str = "/etc/nyx/xray";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-xray@{profile}.service")
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

pub async fn up(conn: &Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await
}

pub async fn down(conn: &Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::stop_unit(conn, &unit_name(profile)).await
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
