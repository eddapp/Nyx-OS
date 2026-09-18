//! OpenVPN backend — the `openvpn-client@.service` systemd template unit
//! for lifecycle. OpenVPN doesn't expose a handshake-recency concept the
//! way WireGuard does over a simple CLI query, so "is it really up" here
//! relies on a weaker pair of signals: the systemd unit is active, and its
//! declared `dev` interface (parsed from the profile itself) exists with an
//! address assigned — see `route::interface_has_address`. That's a real
//! limitation, not glossed over: `handler.rs` reports OpenVPN connections
//! as `Degraded` rather than `Protected` unless both signals line up.

use nyx_core::NyxResult;
use std::fs;

const PROFILE_DIR: &str = "/etc/openvpn/client";

fn unit_name(profile: &str) -> String {
    format!("openvpn-client@{profile}.service")
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                path.file_stem().and_then(|s| s.to_str()).map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// Parse the `dev <name>` directive out of a profile's config file, if
/// present. `None` means we genuinely don't know which interface this
/// profile uses — reported as such rather than guessing "tun0".
pub fn configured_device(profile: &str) -> Option<String> {
    let path = format!("{PROFILE_DIR}/{profile}.conf");
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        if parts.next()? == "dev" {
            parts.next().map(str::to_string)
        } else {
            None
        }
    })
}

pub async fn up(conn: &zbus::Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await
}

pub async fn down(conn: &zbus::Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::stop_unit(conn, &unit_name(profile)).await
}

pub async fn is_active(conn: &zbus::Connection, profile: &str) -> NyxResult<bool> {
    crate::systemd_ctl::is_active(conn, &unit_name(profile)).await
}

/// Best-effort discovery of which configured profile (if any) currently
/// has an active systemd unit — used by Status to find a connection this
/// daemon didn't itself start (e.g. after a restart).
pub async fn find_active_profile(conn: &zbus::Connection) -> Option<String> {
    for profile in list_profiles() {
        if is_active(conn, &profile).await.unwrap_or(false) {
            return Some(profile);
        }
    }
    None
}
