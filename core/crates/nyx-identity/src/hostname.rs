//! Hostname control via `hostnamectl` — systemd's real API for this,
//! persists to `/etc/hostname` and takes effect immediately.

use nyx_core::{NyxError, NyxResult};
use rand::seq::SliceRandom;
use rand::Rng;
use std::process::Command;

/// Common real-world auto-generated hostname prefixes, dominated by
/// Windows' own `DESKTOP-XXXXXXX` scheme — deliberately unremarkable on a
/// LAN rather than distinctively "this machine runs NyxOS".
const PREFIXES: &[&str] = &["DESKTOP", "LAPTOP", "WORKSTATION", "PC", "WIN"];

pub fn generate() -> String {
    let mut rng = rand::thread_rng();
    let prefix = *PREFIXES.choose(&mut rng).unwrap_or(&"DESKTOP");
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let suffix: String = (0..7).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect();
    format!("{prefix}-{suffix}")
}

pub fn current() -> Option<String> {
    let output = Command::new("hostnamectl").arg("--static").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn set(name: &str) -> NyxResult<()> {
    let status = Command::new("hostnamectl")
        .args(["set-hostname", name])
        .status()
        .map_err(|e| NyxError::Config(format!("failed to spawn hostnamectl: {e}")))?;
    if !status.success() {
        return Err(NyxError::Config(format!("hostnamectl set-hostname exited with {status}")));
    }
    Ok(())
}
