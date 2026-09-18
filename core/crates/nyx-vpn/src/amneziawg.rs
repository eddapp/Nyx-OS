//! AmneziaWG backend — `awg-quick`/`awg` mirror `wg-quick`/`wg`'s CLI
//! exactly (AmneziaWG's own tooling is a fork of wireguard-tools that adds
//! a handful of extra `[Interface]`/`[Peer]` config keys — `Jc`, `Jmin`,
//! `Jmax`, `S1`, `S2`, `H1`-`H4` — for traffic obfuscation; the command
//! surface itself is untouched). Same as `wireguard.rs`: `awg-quick up
//! <name>` names the interface after the profile, and `awg show` is a live
//! kernel-module query, not nyx-vpn's own memory of what it started.
//!
//! The one real difference from upstream WireGuard is the config
//! directory: AmneziaWG's `awg-quick` looks under `/etc/amnezia/amneziawg/`
//! for a bare profile name, not `/etc/wireguard/` — confirmed against
//! `amneziawg-tools`' own `wg-quick/linux.bash`, which hardcodes that path
//! rather than reusing `wg-quick`'s.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_DIR: &str = "/etc/amnezia/amneziawg";

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
    let status = Command::new("awg-quick")
        .args(["up", name])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn awg-quick: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("awg-quick up {name} exited with {status}")));
    }
    Ok(())
}

pub fn down(name: &str) -> NyxResult<()> {
    let status = Command::new("awg-quick")
        .args(["down", name])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn awg-quick: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("awg-quick down {name} exited with {status}")));
    }
    Ok(())
}

/// Every AmneziaWG interface currently present, regardless of who brought
/// it up — a live kernel-module query (`awg show interfaces`), not
/// nyx-vpn's own memory of what it started.
pub fn active_interfaces() -> Vec<String> {
    let output = Command::new("awg").arg("show").arg("interfaces").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Seconds since the most recent cryptographic handshake on `iface`,
/// across all peers — same semantics as `wireguard::handshake_age_secs`.
/// `None` means either the interface doesn't exist or no peer has ever
/// handshaked, which is normal right after `awg-quick up` on a config with
/// no traffic yet, not necessarily a fault.
pub fn handshake_age_secs(iface: &str) -> Option<u64> {
    let output = Command::new("awg")
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
