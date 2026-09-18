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

use nyx_core::NyxResult;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

const PROFILE_DIR: &str = "/etc/shadowsocks-rust";

fn unit_name(profile: &str) -> String {
    format!("shadowsocks-rust@{profile}.service")
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
