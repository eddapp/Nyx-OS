//! OpenVPN backend — the `openvpn-client@.service` systemd template unit
//! for lifecycle. OpenVPN doesn't expose a handshake-recency concept the
//! way WireGuard does over a simple CLI query, so "is it really up" here
//! relies on a weaker pair of signals: the systemd unit is active, and its
//! declared `dev` interface (parsed from the profile itself) exists with an
//! address assigned — see `route::interface_has_address`. That's a real
//! limitation, not glossed over: `handler.rs` reports OpenVPN connections
//! as `Degraded` rather than `Protected` unless both signals line up.

use nyx_core::{NyxError, NyxResult};
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

/// Parse the `proto <value>` directive out of a profile's config file, if
/// present. `None` means no explicit `proto` line, which means OpenVPN
/// defaults to `udp` — a `--socks-proxy` connection needs the profile to
/// already declare `tcp-client`/`tcp4-client`/`tcp6-client` explicitly, so
/// this is checked before ever attempting to chain through Tor.
pub fn configured_proto(profile: &str) -> Option<String> {
    let path = format!("{PROFILE_DIR}/{profile}.conf");
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        if parts.next()? == "proto" {
            parts.next().map(str::to_string)
        } else {
            None
        }
    })
}

pub async fn up(conn: &zbus::Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await
}

/// VPN-over-Tor chaining. OpenVPN's own `--socks-proxy <host> [<port>]`
/// client directive (confirmed against `openvpn(8)`) is real and
/// documented, but SOCKS5 only carries TCP, and `openvpn(8)`'s own
/// `--bind` entry groups `--socks-proxy` with `--proto tcp-client` and
/// `--http-proxy` as the options that mean "the peer connection is
/// established by dialing out over TCP" — so this refuses to run unless
/// the profile already declares an explicit TCP-client `proto`, rather
/// than silently overriding the profile's own transport choice.
///
/// Implemented as a systemd drop-in on `openvpn-client@<profile>.service`
/// appending `--socks-proxy` to the vendor unit's own `ExecStart=` (see
/// `socks_override.rs`) — the profile's `.conf` file itself is never
/// rewritten.
pub async fn up_via_socks_proxy(
    conn: &zbus::Connection,
    profile: &str,
    socks_host: &str,
    socks_port: u16,
) -> NyxResult<()> {
    match configured_proto(profile) {
        Some(proto) if matches!(proto.as_str(), "tcp-client" | "tcp4-client" | "tcp6-client") => {}
        Some(proto) => {
            return Err(NyxError::Config(format!(
                "OpenVPN profile '{profile}' uses 'proto {proto}' — chaining through a SOCKS \
                 proxy needs the profile to already declare 'proto tcp-client' (or \
                 tcp4-client/tcp6-client), since SOCKS5 only carries TCP; edit the profile first"
            )));
        }
        None => {
            return Err(NyxError::Config(format!(
                "OpenVPN profile '{profile}' has no explicit 'proto' line (defaults to udp) — \
                 chaining through a SOCKS proxy needs 'proto tcp-client' (or \
                 tcp4-client/tcp6-client) added to the profile first, since SOCKS5 only carries \
                 TCP"
            )));
        }
    }

    let unit = unit_name(profile);
    let exec_start = format!(
        "/usr/bin/openvpn --suppress-timestamps --nobind --config {profile}.conf --socks-proxy {socks_host} {socks_port}"
    );
    crate::socks_override::write_exec_start_override(&unit, &exec_start)?;
    if let Err(e) = crate::systemd_ctl::reload(conn).await {
        crate::socks_override::remove_exec_start_override(&unit);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::start_unit(conn, &unit).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = crate::systemd_ctl::reload(conn).await;
        return Err(e);
    }
    Ok(())
}

pub async fn down(conn: &zbus::Connection, profile: &str) -> NyxResult<()> {
    let unit = unit_name(profile);
    let result = crate::systemd_ctl::stop_unit(conn, &unit).await;
    // Best-effort: undo any VPN-over-Tor override so a later plain
    // `up()` doesn't silently keep dialing through a stale proxy.
    crate::socks_override::remove_exec_start_override(&unit);
    let _ = crate::systemd_ctl::reload(conn).await;
    result
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
