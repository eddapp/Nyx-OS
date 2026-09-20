//! LUKS nuke — `cryptsetup erase` (the current spelling of `luksErase`)
//! against one named LUKS container, which destroys every keyslot's key
//! material in the on-disk header. Once that has happened the volume key can
//! no longer be derived from any passphrase, so the ciphertext is
//! permanently unreadable unless a header backup (`cryptsetup
//! luksHeaderBackup`) exists somewhere else. It is the same primitive
//! Kodachi's "LUKS nuke" panic action is built on, and is the whole point:
//! this is a duress/panic control, not a cleanup one.
//!
//! What it deliberately does NOT do:
//! - overwrite the ciphertext (that would take hours; erasing the keyslots
//!   is what actually makes the data unrecoverable, and is instant);
//! - touch a device that isn't a LUKS header (`cryptsetup isLuks` is
//!   checked first);
//! - touch the container backing `/` unless the caller explicitly opts in
//!   with `include_root` — the running system keeps working from RAM/page
//!   cache until reboot, but it will never unlock again.
//!
//! Every fact reported here comes from `lsblk --json`, `cryptsetup isLuks`
//! and `cryptsetup luksDump` on the real device, never from a settings flag.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct BlockDevice {
    name: String,
    path: Option<String>,
    fstype: Option<String>,
    mountpoint: Option<String>,
    #[serde(default)]
    children: Vec<BlockDevice>,
}

#[derive(Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

/// One LUKS container as `lsblk` sees it right now.
pub struct LuksDevice {
    /// `/dev/...` path.
    pub path: String,
    /// Every mountpoint of every unlocked filesystem stacked on top of this
    /// container (empty if it's locked or holds nothing mounted).
    pub mountpoints: Vec<String>,
    /// True if one of those mountpoints is `/`.
    pub backs_root: bool,
}

fn tree() -> Result<Vec<BlockDevice>, String> {
    let output = Command::new("lsblk")
        .args(["-J", "-o", "NAME,PATH,FSTYPE,MOUNTPOINT"])
        .output()
        .map_err(|e| format!("failed to run lsblk: {e}"))?;
    if !output.status.success() {
        return Err(format!("lsblk exited with {}", output.status));
    }
    let parsed: LsblkOutput =
        serde_json::from_slice(&output.stdout).map_err(|e| format!("bad lsblk JSON: {e}"))?;
    Ok(parsed.blockdevices)
}

fn collect_mountpoints(dev: &BlockDevice, out: &mut Vec<String>) {
    if let Some(m) = &dev.mountpoint {
        out.push(m.clone());
    }
    for child in &dev.children {
        collect_mountpoints(child, out);
    }
}

fn collect_luks(devices: &[BlockDevice], out: &mut Vec<LuksDevice>) {
    for dev in devices {
        if dev.fstype.as_deref() == Some("crypto_LUKS") {
            let mut mountpoints = Vec::new();
            for child in &dev.children {
                collect_mountpoints(child, &mut mountpoints);
            }
            let backs_root = mountpoints.iter().any(|m| m == "/");
            out.push(LuksDevice {
                path: dev.path.clone().unwrap_or_else(|| format!("/dev/{}", dev.name)),
                mountpoints,
                backs_root,
            });
        }
        collect_luks(&dev.children, out);
    }
}

/// Every `crypto_LUKS` container currently visible to the kernel.
pub fn list() -> Result<Vec<LuksDevice>, String> {
    let mut out = Vec::new();
    collect_luks(&tree()?, &mut out);
    Ok(out)
}

/// Accepts `sda3`, `/dev/sda3`, `nvme0n1p2`, or a `/dev/disk/by-*` link and
/// returns the canonical `/dev/...` path — the same spelling `lsblk`'s
/// `PATH` column reports, so it can be matched against [`list`].
pub fn canonical_device(input: &str) -> Result<String, String> {
    let raw = if input.starts_with('/') {
        PathBuf::from(input)
    } else {
        Path::new("/dev").join(input)
    };
    let resolved = std::fs::canonicalize(&raw)
        .map_err(|e| format!("{}: {e}", raw.display()))?;
    Ok(resolved.to_string_lossy().into_owned())
}

fn is_luks(path: &str) -> Result<bool, String> {
    let status = Command::new("cryptsetup")
        .args(["isLuks", path])
        .status()
        .map_err(|e| format!("failed to run cryptsetup isLuks: {e}"))?;
    Ok(status.success())
}

/// Number of populated keyslots per `cryptsetup luksDump`: LUKS2 prints a
/// `Keyslots:` section with one `  <n>: luks2` line per slot; LUKS1 prints
/// `Key Slot <n>: ENABLED|DISABLED`. Both shapes are counted here.
pub fn keyslot_count(path: &str) -> Result<usize, String> {
    let output = Command::new("cryptsetup")
        .args(["luksDump", path])
        .output()
        .map_err(|e| format!("failed to run cryptsetup luksDump: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cryptsetup luksDump exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_keyslots(&String::from_utf8_lossy(&output.stdout)))
}

/// Counts populated keyslots in `cryptsetup luksDump` output — see
/// [`keyslot_count`] for the two on-disk-format shapes handled.
fn parse_keyslots(dump: &str) -> usize {
    let mut count = 0;
    let mut in_keyslots = false;
    for line in dump.lines() {
        // LUKS1: `Key Slot 0: ENABLED` / `Key Slot 1: DISABLED`
        if line.starts_with("Key Slot ") {
            if line.trim_end().ends_with("ENABLED") && !line.trim_end().ends_with("DISABLED") {
                count += 1;
            }
            continue;
        }
        // LUKS2: section headers are unindented and end with ':'; the
        // `Keyslots:` section lists `  0: luks2` per populated slot.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_keyslots = line.trim_end() == "Keyslots:";
            continue;
        }
        if in_keyslots {
            let t = line.trim_start();
            if t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains(": luks") {
                count += 1;
            }
        }
    }
    count
}

pub struct NukeOutcome {
    pub device: LuksDevice,
    pub keyslots_before: usize,
    pub keyslots_after: usize,
    pub warnings: Vec<String>,
}

/// Validates `input` (must resolve to a `crypto_LUKS` device; must not back
/// `/` unless `include_root`) and returns it without touching anything —
/// the `plan` half.
pub fn plan(input: &str, include_root: bool) -> Result<(LuksDevice, usize), String> {
    let path = canonical_device(input)?;
    if !is_luks(&path)? {
        return Err(format!("{path} does not carry a LUKS header (cryptsetup isLuks failed)"));
    }
    let device = list()?
        .into_iter()
        .find(|d| d.path == path)
        .ok_or_else(|| format!("{path} is LUKS but lsblk does not list it as a crypto_LUKS device"))?;
    if device.backs_root && !include_root {
        return Err(format!(
            "{path} backs the running root filesystem — refusing without --include-root-device \
             (the system will keep running from memory until reboot, then never unlock again)"
        ));
    }
    let keyslots = keyslot_count(&path)?;
    Ok((device, keyslots))
}

/// `cryptsetup erase -q <device>`, then re-count keyslots to report what
/// actually happened rather than assuming success.
pub fn execute(device: LuksDevice, keyslots_before: usize) -> NukeOutcome {
    let mut warnings = Vec::new();
    let status = Command::new("cryptsetup")
        .args(["erase", "-q", &device.path])
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => warnings.push(format!("cryptsetup erase exited with {s}")),
        Err(e) => warnings.push(format!("failed to run cryptsetup erase: {e}")),
    }
    let keyslots_after = match keyslot_count(&device.path) {
        Ok(n) => n,
        Err(e) => {
            warnings.push(format!("could not re-read keyslots after erase: {e}"));
            keyslots_before
        }
    };
    if keyslots_after > 0 {
        warnings.push(format!(
            "{keyslots_after} keyslot(s) still present — the container may still be unlockable"
        ));
    }
    if device.backs_root {
        warnings.push(
            "the root container's keyslots are gone: this system will not unlock on next boot"
                .to_string(),
        );
    }
    NukeOutcome { device, keyslots_before, keyslots_after, warnings }
}

#[cfg(test)]
mod tests {
    use super::parse_keyslots;

    const LUKS2_DUMP: &str = "\
LUKS header information
Version:       \t2
Epoch:         \t5
Metadata area: \t16384 [bytes]
Keyslots area: \t16744448 [bytes]
UUID:          \t2f1a5d3e-0000-4c1a-9c1e-000000000000
Label:         \t(no label)
Subsystem:     \t(no subsystem)
Flags:       \t(no flags)

Data segments:
  0: crypt
\toffset: 16777216 [bytes]
\tlength: (whole device)
\tcipher: aes-xts-plain64
\tsector: 512 [bytes]

Keyslots:
  0: luks2
\tKey:        512 bits
\tPriority:   normal
\tCipher:     aes-xts-plain64
\tPBKDF:      argon2id
  1: luks2
\tKey:        512 bits
\tPriority:   normal
Tokens:
Digests:
  0: pbkdf2
\tHash:       sha256
";

    const LUKS2_ERASED: &str = "\
LUKS header information
Version:       \t2

Data segments:
  0: crypt
\toffset: 16777216 [bytes]

Keyslots:
Tokens:
Digests:
  0: pbkdf2
\tHash:       sha256
";

    const LUKS1_DUMP: &str = "\
LUKS header information for /dev/sda2

Version:       \t1
Cipher name:   \taes
Cipher mode:   \txts-plain64
Hash spec:     \tsha256
Payload offset:\t4096
MK bits:       \t512
UUID:          \t9c6c0a3a-0000-4e59-8f2a-000000000000

Key Slot 0: ENABLED
\tIterations:         \t1234567
\tSalt:               \t00 00 00 00
Key Slot 1: DISABLED
Key Slot 2: ENABLED
Key Slot 3: DISABLED
Key Slot 4: DISABLED
Key Slot 5: DISABLED
Key Slot 6: DISABLED
Key Slot 7: DISABLED
";

    #[test]
    fn counts_luks2_slots() {
        assert_eq!(parse_keyslots(LUKS2_DUMP), 2);
    }

    #[test]
    fn erased_luks2_has_zero_slots() {
        // The `0: pbkdf2` line under `Digests:` must not be mistaken for a
        // keyslot — only the `Keyslots:` section counts.
        assert_eq!(parse_keyslots(LUKS2_ERASED), 0);
    }

    #[test]
    fn counts_luks1_enabled_slots_only() {
        assert_eq!(parse_keyslots(LUKS1_DUMP), 2);
    }
}
