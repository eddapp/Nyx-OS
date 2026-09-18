//! Package file-integrity verification via `pacman -Qkk` — the supported way
//! to ask pacman "does every file this package installed still match what it
//! shipped", same mechanism `pacman -Qkk` documents for manual use. We shell
//! out rather than parsing the local sync database ourselves.

use nyx_core::{NyxError, NyxResult};
use std::collections::HashSet;
use std::process::Command;

/// Packages checked in "quick" mode — the ones whose file integrity actually
/// bears on Nyx's own security posture. Full mode instead checks every
/// explicitly-installed package (`pacman -Qqe`), which can take minutes.
pub const CRITICAL_PACKAGES: &[&str] = &[
    "nyx-health",
    "nyx-dns",
    "nyx-integrity",
    "nyx-dashboard",
    "nftables",
    "tor",
    "dnscrypt-proxy",
    "wireguard-tools",
    "openvpn",
    "systemd",
];

pub struct PacmanCheck {
    pub scanned: usize,
    pub mismatches: Vec<String>,
}

fn run(args: &[&str]) -> NyxResult<String> {
    let output = Command::new("pacman")
        .args(args)
        .output()
        .map_err(|e| NyxError::Config(format!("failed to spawn pacman: {e}")))?;
    Ok(format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn installed_packages() -> NyxResult<HashSet<String>> {
    Ok(run(&["-Qq"])?.lines().map(str::to_string).collect())
}

/// Run `pacman -Qkk` (full checksum verification) against either the fixed
/// critical set or every explicitly-installed package, skipping anything not
/// actually installed on this system.
pub fn check(quick: bool) -> NyxResult<PacmanCheck> {
    let installed = installed_packages()?;

    let candidates: Vec<String> = if quick {
        CRITICAL_PACKAGES.iter().map(|s| s.to_string()).collect()
    } else {
        run(&["-Qqe"])?.lines().map(str::to_string).collect()
    };

    let targets: Vec<String> = candidates.into_iter().filter(|p| installed.contains(p)).collect();
    if targets.is_empty() {
        return Ok(PacmanCheck {
            scanned: 0,
            mismatches: Vec::new(),
        });
    }

    let mut args = vec!["-Qkk"];
    args.extend(targets.iter().map(String::as_str));
    let combined = run(&args)?;

    // pacman prints one summary line per package ("<pkg>: N total files, M
    // altered files") and one "warning: <pkg>: <path> (<reason>)" line per
    // altered/unreadable file. We surface every warning line as a mismatch —
    // it's the operator's job to tell an intentional edit from real drift,
    // this daemon's job is only to never hide the signal.
    let mismatches: Vec<String> = combined
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("warning:"))
        .map(|l| l.trim().to_string())
        .collect();

    Ok(PacmanCheck {
        scanned: targets.len(),
        mismatches,
    })
}
