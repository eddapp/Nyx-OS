//! Hysteria2 backend — `hysteria-bin` (AUR, prebuilt release, matching this
//! project's established preference for `-bin` AUR packages in an ISO
//! pipeline, e.g. `zen-browser-bin`) ships the upstream `hysteria` binary
//! verbatim. Confirmed against apernet/hysteria's own `app/cmd/root.go` and
//! `client.go`: the CLI is Cobra-based with a `client` subcommand
//! (`Use: "client"`) and a persistent `-c`/`--config` flag
//! (`StringVarP(&cfgFile, "config", "c", "", ...)`), so `hysteria client -c
//! <config>.yaml` is the real invocation — config is YAML, not JSON.
//!
//! hysteria's client also has a real `tun:` config section that creates a
//! genuine TUN interface (there's a `internal/tun` package backing it) —
//! same reasoning as `shadowsocks.rs`: taking that on means owning TUN
//! creation/addressing/teardown and default-route management, which this
//! crate deliberately scopes to the SOCKS5 backend in `dante.rs` only.
//! Here, profiles use hysteria's plain `socks5:`/`http:` local proxy
//! listener instead. QUIC's own handshake isn't exposed over a simple CLI
//! query the way WireGuard/AmneziaWG's is, so — same honesty as
//! `xray.rs`/`shadowsocks.rs` — status is process-alive plus a
//! best-effort local-port reachability check; `handler.rs` never reports
//! this protocol as `Protected`.
//!
//! Lifecycle is a templated systemd unit (`nyx-vpn-hysteria@<name>.service`,
//! see `packaging/`), for real process supervision rather than nyx-vpn
//! babysitting a raw child process.

use nyx_core::NyxResult;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

const PROFILE_DIR: &str = "/etc/nyx/hysteria";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-hysteria@{profile}.service")
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            match path.extension().and_then(|s| s.to_str()) {
                Some("yaml") | Some("yml") => {
                    path.file_stem().and_then(|s| s.to_str()).map(str::to_string)
                }
                _ => None,
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

fn config_path(profile: &str) -> Option<String> {
    for ext in ["yaml", "yml"] {
        let path = format!("{PROFILE_DIR}/{profile}.{ext}");
        if std::path::Path::new(&path).is_file() {
            return Some(path);
        }
    }
    None
}

/// Deliberately minimal YAML scan — not a full YAML parser (this crate
/// doesn't carry a YAML dependency for a single best-effort status check).
/// Finds the `listen:` value nested one level under a given top-level key
/// (`socks5:` or `http:`), tracking indentation the same crude way
/// `openvpn.rs`'s `configured_device` scans for a single `dev` directive
/// rather than parsing OpenVPN's config format properly. Good enough for
/// "does this profile even have a local listener configured", nothing
/// more.
fn scan_listen_under(contents: &str, top_key: &str) -> Option<String> {
    let mut in_block = false;
    let mut block_indent = 0usize;
    for line in contents.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !in_block {
            if indent == 0 && trimmed.trim_end_matches(':') == top_key.trim_end_matches(':') {
                in_block = true;
                block_indent = indent;
            }
            continue;
        }
        // Left the block once we're back at or above its own indent level
        // on a non-empty line that isn't itself the block's own key.
        if indent <= block_indent {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("listen:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Parse the client's local `socks5:`/`http:` listener address, if
/// configured, preferring `socks5:` when both are present.
pub fn configured_local_addr(profile: &str) -> Option<SocketAddr> {
    let path = config_path(profile)?;
    let contents = fs::read_to_string(path).ok()?;

    let listen = scan_listen_under(&contents, "socks5")
        .or_else(|| scan_listen_under(&contents, "http"))?;

    // "host:port" — host may be empty (":1080" meaning "all interfaces").
    let (host, port) = listen.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = match host {
        "" | "0.0.0.0" => IpAddr::from([127, 0, 0, 1]),
        "::" => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        other => other.parse().ok()?,
    };
    Some(SocketAddr::new(ip, port))
}

/// Best-effort liveness signal: does *something* accept a TCP connection
/// on the profile's configured local proxy port. Proves a listener
/// exists, nothing about the QUIC link to the remote Hysteria2 server
/// actually working — Hysteria2 doesn't expose a handshake-recency
/// concept over a simple CLI query the way WireGuard/AmneziaWG do.
pub fn local_proxy_reachable(profile: &str) -> bool {
    let Some(addr) = configured_local_addr(profile) else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}
