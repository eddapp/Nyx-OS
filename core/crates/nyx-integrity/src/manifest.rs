//! Self-owned checksum manifest for Nyx-critical files. Independent of
//! pacman: some of these (the baked-in `/etc/nftables.conf`, `torrc`,
//! `dnscrypt-proxy.toml`) may not even be tracked by any installed package on
//! a live/ISO system, so pacman's own `-Qkk` can't see drift in them at all.

use nyx_core::{NyxError, NyxResult, INTEGRITY_MANIFEST_PATH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Files whose integrity nyx-integrity tracks itself, regardless of whether
/// pacman owns them. Missing entries at baseline time are silently skipped
/// (a server profile has no `nyx-dashboard`, for instance).
pub const MANIFEST_TARGETS: &[&str] = &[
    "/usr/bin/nyx-health",
    "/usr/bin/nyx-vpn",
    "/usr/bin/nyx-identity",
    "/usr/bin/nyx-devices",
    "/usr/bin/nyx-telemetry",
    "/usr/bin/nyx-diagnostics",
    "/usr/bin/nyx-dns",
    "/usr/bin/nyx-integrity",
    "/usr/bin/nyx-wipe",
    "/usr/bin/nyx-isolation",
    "/usr/bin/nyx-workflow",
    "/usr/bin/nyx-dashboard",
    "/usr/bin/nyx-hardening",
    "/usr/bin/nyx-clipboard-clear",
    "/usr/bin/nyx-watch",
    "/usr/bin/nyx-browser",
    "/usr/bin/nyx-oniux-browser",
    "/usr/bin/nyx-tor-browser",
    "/usr/bin/nyx-disposable-browser",
    "/usr/lib/systemd/system/nyx-health.service",
    "/usr/lib/systemd/system/nyx-vpn.service",
    "/usr/lib/systemd/system/nyx-vpn-xray@.service",
    "/usr/lib/systemd/system/nyx-vpn-hysteria@.service",
    "/usr/lib/systemd/system/nyx-vpn-socks5@.service",
    "/usr/lib/systemd/system/nyx-vpn-mieru@.service",
    "/usr/lib/systemd/system/nyx-vpn-cloak@.service",
    "/usr/lib/systemd/system/nyx-identity.service",
    "/usr/lib/systemd/system/nyx-devices.service",
    "/usr/lib/systemd/system/nyx-telemetry.service",
    "/usr/lib/systemd/system/nyx-dns.service",
    "/usr/lib/systemd/system/nyx-integrity.service",
    "/usr/lib/systemd/system/nyx-watch.service",
    "/usr/lib/systemd/user/nyx-clipboard-clear.service",
    "/etc/xdg/Thunar/uca.xml",
    "/usr/lib/nyx/thunar/nyx-thunar-gpg-encrypt.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-gpg-decrypt.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-gpg-sign.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-gpg-verify.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-openssl.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-hexview.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-entropy.sh",
    "/usr/lib/nyx/thunar/nyx-thunar-compare.sh",
    "/usr/lib/nyx/conky/nyx-conky-status.sh",
    "/etc/nftables.conf",
    "/etc/tor/torrc",
    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
    "/etc/polkit-1/rules.d/90-nyx-dashboard.rules",
    "/etc/nyx/conky/conky.conf",
];

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    /// path -> lowercase hex SHA-256
    entries: BTreeMap<String, String>,
}

fn sha256_hex(path: &Path) -> NyxResult<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Recompute and persist the manifest from what's on disk right now. This is
/// trust-on-first-use: call it once, right after a known-good install or
/// update — never routinely, or it will happily "baseline" a compromise.
pub fn write_baseline() -> NyxResult<usize> {
    let mut manifest = Manifest::default();
    for target in MANIFEST_TARGETS {
        let path = Path::new(target);
        if !path.exists() {
            continue;
        }
        manifest.entries.insert(target.to_string(), sha256_hex(path)?);
    }

    if let Some(parent) = Path::new(INTEGRITY_MANIFEST_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| NyxError::Config(format!("failed to serialize manifest: {e}")))?;
    fs::write(INTEGRITY_MANIFEST_PATH, json)?;
    Ok(manifest.entries.len())
}

pub struct VerifyOutcome {
    pub present: bool,
    pub checked: usize,
    pub mismatches: Vec<String>,
}

/// Compare every manifest entry against what's on disk now.
pub fn verify() -> NyxResult<VerifyOutcome> {
    let path = Path::new(INTEGRITY_MANIFEST_PATH);
    if !path.exists() {
        return Ok(VerifyOutcome {
            present: false,
            checked: 0,
            mismatches: Vec::new(),
        });
    }

    let raw = fs::read_to_string(path)?;
    let manifest: Manifest = serde_json::from_str(&raw)
        .map_err(|e| NyxError::Config(format!("manifest at {INTEGRITY_MANIFEST_PATH} is corrupt: {e}")))?;

    let mut mismatches = Vec::new();
    for (target, expected) in &manifest.entries {
        let target_path = Path::new(target);
        if !target_path.exists() {
            mismatches.push(format!("{target}: file missing (present at baseline time)"));
            continue;
        }
        match sha256_hex(target_path) {
            Ok(actual) if &actual == expected => {}
            Ok(_) => mismatches.push(format!("{target}: SHA-256 no longer matches baseline")),
            Err(e) => mismatches.push(format!("{target}: unreadable ({e})")),
        }
    }

    Ok(VerifyOutcome {
        present: true,
        checked: manifest.entries.len(),
        mismatches,
    })
}
