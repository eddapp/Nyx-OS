//! WireGuard backend — `wg-quick` for lifecycle, `wg show` for real state.
//! `wg-quick up <name>` names the interface after the profile, so there is
//! never any guessing about which interface a given profile becomes.
//!
//! No `up_via_socks_proxy` here, deliberately: WireGuard is a UDP-only
//! in-kernel tunnel, and Tor's SocksPort is TCP-only — it does not
//! implement the SOCKS5 UDP ASSOCIATE command (confirmed against
//! `tor(1)`'s own `SocksPort` documentation, which describes it purely as
//! a stream/TCP proxy). There is no way to carry a UDP tunnel through a
//! TCP-only SOCKS proxy at all; this is a protocol-layer limitation, not a
//! missing feature. See `nyx_core::VpnCommand::ConnectViaSocksProxy`.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_DIR: &str = "/etc/wireguard";

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

pub fn up(name: &str) -> NyxResult<()> {
    let status = Command::new("wg-quick")
        .args(["up", name])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn wg-quick: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("wg-quick up {name} exited with {status}")));
    }
    Ok(())
}

pub fn down(name: &str) -> NyxResult<()> {
    let status = Command::new("wg-quick")
        .args(["down", name])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn wg-quick: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("wg-quick down {name} exited with {status}")));
    }
    Ok(())
}

/// Every WireGuard interface currently present, regardless of who brought
/// it up — this is a live kernel query (`wg show interfaces`), not
/// nyx-vpn's own memory of what it started.
pub fn active_interfaces() -> Vec<String> {
    let output = Command::new("wg").arg("show").arg("interfaces").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Seconds since the most recent cryptographic handshake on `iface`,
/// across all peers. `None` means either the interface doesn't exist or no
/// peer has ever handshaked — the latter is normal right after `wg-quick
/// up` on a config with no traffic yet, not necessarily a fault.
pub fn handshake_age_secs(iface: &str) -> Option<u64> {
    let output = Command::new("wg")
        .args(["show", iface, "latest-handshakes"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // One line per peer: "<pubkey>\t<unix-epoch-seconds>". 0 = never.
    let latest_epoch = text
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|s| s.parse::<u64>().ok())
        .max()?;
    if latest_epoch == 0 {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(latest_epoch))
}
