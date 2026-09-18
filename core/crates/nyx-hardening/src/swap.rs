//! Swap-device discovery and plaintext -> LUKS-random-key conversion.
//!
//! NyxOS's own install process (`iso/build.sh`) never provisions a swap
//! partition itself — the "Profile-directory swap bookkeeping" comment in
//! that file is unrelated build-profile-file juggling (swapping which
//! `packages.x86_64` archiso reads for `--profile server`), not disk swap.
//! So this module's job, per the standard dm-crypt swap-encryption
//! technique documented in crypttab(5) and the Arch Wiki
//! (`Dm-crypt/Swap encryption`), is purely reactive: find whatever swap
//! the *installed system* already has (a real partition, a swap file, or
//! zram) and, only for a real plaintext partition, convert it to
//! `crypttab`'s `swap` mode — a fresh random key read from `/dev/urandom`
//! on every boot via `cipher=aes-xts-plain64,size=256,sector-size=4096`.
//! That specific option string is the one documented on the Arch Wiki
//! page for exactly this case (a `/dev/urandom` key file implies `plain`
//! dm-crypt, and the `swap` crypttab option additionally `mkswap`s the
//! mapped device on every activation). It's the standard, correct
//! construction for swap specifically: swap contents never need to
//! survive a reboot, so there's no key-management problem to solve — a
//! fresh key every boot is strictly better than a passphrase-derived one
//! that has to persist.

use nyx_core::{NyxError, NyxResult};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CRYPTTAB_PATH: &str = "/etc/crypttab";
pub const FSTAB_PATH: &str = "/etc/fstab";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapKind {
    /// A real disk partition (or LVM/dm volume reported as one) — the
    /// only kind `encrypt` will act on.
    Partition,
    /// A swap file sitting on top of a filesystem. dm-crypt/crypttab maps
    /// block devices, not regular files — turning a swap file into one
    /// would mean `losetup`-ing it into a loop device first, which this
    /// module deliberately does not automate (see `plan_encrypt`).
    File,
    /// zram — compressed, RAM-backed swap. It never touches persistent
    /// storage, so a disk-forensics/cold-boot attack against a powered
    /// -off machine has nothing to recover from it; encrypting it would
    /// defend against precisely nothing extra.
    Zram,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwapEntry {
    pub device: PathBuf,
    pub kind: SwapKind,
    pub size_kib: u64,
    pub used_kib: u64,
    /// True if the device is already a live dm-crypt mapping (LUKS or
    /// plain) — e.g. a whole-disk-encryption layout where swap lives
    /// inside the same LUKS container as root. Nothing to convert.
    pub already_encrypted: bool,
    pub crypt_mapper_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EncryptPlan {
    pub device: PathBuf,
    pub mapper_name: String,
    pub partuuid: Option<String>,
    pub crypttab_line: String,
    pub fstab_line: String,
}

fn classify(raw_type: &str, filename: &str) -> SwapKind {
    if filename.starts_with("/dev/zram") {
        SwapKind::Zram
    } else {
        match raw_type {
            "partition" => SwapKind::Partition,
            "file" => SwapKind::File,
            _ => SwapKind::Other,
        }
    }
}

/// Resolves `/dev/dm-N` (or a symlink to it, e.g. `/dev/mapper/foo`) to the
/// device-mapper name systemd/cryptsetup know it by, via the same sysfs
/// attribute `dmsetup` itself reads (`/sys/class/block/<dm-N>/dm/name`).
/// Unlike `dmsetup`/`cryptsetup status`, this needs no root — useful for
/// `swap status` even when run read-only.
fn dm_name(device: &Path) -> Option<String> {
    let real = fs::canonicalize(device).ok()?;
    let base = real.file_name()?.to_str()?;
    if !base.starts_with("dm-") {
        return None;
    }
    fs::read_to_string(format!("/sys/class/block/{base}/dm/name"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Whether `name` (from `dm_name`) is a live dm-crypt mapping, per
/// `cryptsetup status` — the same primitive `nyx-devices`'s LUKS
/// reporting and this crate's cold-boot hook both key off. Requires root.
fn is_crypt_mapping(name: &str) -> bool {
    Command::new("cryptsetup")
        .args(["status", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Real, live swap topology from `/proc/swaps` — not a config file's idea
/// of what swap should exist.
pub fn discover() -> NyxResult<Vec<SwapEntry>> {
    let text = fs::read_to_string("/proc/swaps")?;
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let filename = fields[0];
        let raw_type = fields[1];
        let size_kib: u64 = fields[2].parse().unwrap_or(0);
        let used_kib: u64 = fields[3].parse().unwrap_or(0);
        let device = PathBuf::from(filename);
        let kind = classify(raw_type, filename);

        let (already_encrypted, crypt_mapper_name) = match dm_name(&device) {
            Some(name) if is_crypt_mapping(&name) => (true, Some(name)),
            Some(name) => (false, Some(name)),
            None => (false, None),
        };

        out.push(SwapEntry {
            device,
            kind,
            size_kib,
            used_kib,
            already_encrypted,
            crypt_mapper_name,
        });
    }
    Ok(out)
}

fn blkid_value(device: &Path, tag: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-s", tag, "-o", "value", device.to_str()?])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Plans (but does not execute) converting `device` to encrypted swap.
/// Refuses — with an honest, specific reason — for zram, swap files,
/// already-encrypted swap, or anything not currently an active swap
/// device at all.
pub fn plan_encrypt(device: &Path) -> NyxResult<EncryptPlan> {
    let entries = discover()?;
    let entry = entries.iter().find(|e| e.device == device).ok_or_else(|| {
        NyxError::Config(format!(
            "{} is not currently an active swap device (see /proc/swaps)",
            device.display()
        ))
    })?;

    match entry.kind {
        SwapKind::Zram => {
            return Err(NyxError::Config(format!(
                "{} is zram — RAM-backed, never touches persistent storage, so encrypting it \
                 defends against nothing a cold-boot/disk attack could recover; refusing",
                device.display()
            )));
        }
        SwapKind::File => {
            return Err(NyxError::Config(format!(
                "{} is a swap FILE, not a partition — dm-crypt/crypttab maps block devices, so \
                 encrypting a swap file would first need it losetup'd into a loop device, which \
                 this tool deliberately does not automate; convert it to a real partition first, \
                 or drop it in favor of zram",
                device.display()
            )));
        }
        SwapKind::Other => {
            return Err(NyxError::Config(format!(
                "{} has an unrecognized /proc/swaps type — refusing to guess",
                device.display()
            )));
        }
        SwapKind::Partition => {}
    }

    if entry.already_encrypted {
        return Err(NyxError::Config(format!(
            "{} is already dm-crypt-backed (mapper '{}') — nothing to do",
            device.display(),
            entry.crypt_mapper_name.clone().unwrap_or_default()
        )));
    }

    // PARTUUID lives on the partition-table entry, not the swap
    // filesystem signature that `swap,cipher=...` overwrites every boot —
    // it's stable across every re-`mkswap`, unlike a UUID= or LABEL=
    // reference to the (about to be destroyed) plaintext swap signature.
    // The Arch Wiki explicitly warns to get this right: "make sure the
    // underlying block device is specified correctly" because crypttab's
    // `swap` option destroys the named device's contents on every boot.
    let partuuid = blkid_value(device, "PARTUUID");
    let source_field = match &partuuid {
        Some(u) => format!("/dev/disk/by-partuuid/{u}"),
        None => device.display().to_string(),
    };

    let base = device.file_name().and_then(|s| s.to_str()).unwrap_or("swap");
    let mapper_name = format!("nyxswap-{base}");

    let crypttab_line = format!(
        "{mapper_name}\t{source_field}\t/dev/urandom\tswap,cipher=aes-xts-plain64,size=256,sector-size=4096"
    );
    let fstab_line = format!("/dev/mapper/{mapper_name}\tnone\tswap\tdefaults\t0\t0");

    Ok(EncryptPlan { device: device.to_path_buf(), mapper_name, partuuid, crypttab_line, fstab_line })
}

fn run(cmd: &str, args: &[&str]) -> NyxResult<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| NyxError::Config(format!("failed to spawn {cmd}: {e}")))?;
    if !status.success() {
        return Err(NyxError::Config(format!("{cmd} {} exited with {status}", args.join(" "))));
    }
    Ok(())
}

fn systemd_escape(name: &str) -> NyxResult<String> {
    let output = Command::new("systemd-escape")
        .arg(name)
        .output()
        .map_err(|e| NyxError::Config(format!("failed to spawn systemd-escape: {e}")))?;
    if !output.status.success() {
        return Err(NyxError::Config("systemd-escape failed".into()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn append_line_if_absent(path: &str, line: &str) -> NyxResult<bool> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line.trim()) {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(f)?;
    }
    writeln!(f, "{line}")?;
    Ok(true)
}

fn fstab_field_matches_device(
    field: &str,
    device: &Path,
    uuid: &Option<String>,
    partuuid: &Option<String>,
    label: &Option<String>,
) -> bool {
    if let Some(rest) = field.strip_prefix("UUID=") {
        return uuid.as_deref() == Some(rest);
    }
    if let Some(rest) = field.strip_prefix("PARTUUID=") {
        return partuuid.as_deref() == Some(rest);
    }
    if let Some(rest) = field.strip_prefix("LABEL=") {
        return label.as_deref() == Some(rest);
    }
    Path::new(field) == device || fs::canonicalize(field).ok().as_deref() == Some(device)
}

/// Comments out (never deletes — this stays recoverable by hand) any
/// `/etc/fstab` line whose source field resolves to `device` and whose
/// fs-type/mount-point field is `swap`.
fn comment_out_fstab_entry(device: &Path) -> NyxResult<bool> {
    let uuid = blkid_value(device, "UUID");
    let partuuid = blkid_value(device, "PARTUUID");
    let label = blkid_value(device, "LABEL");

    let original = fs::read_to_string(FSTAB_PATH)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut changed = false;
    let mut out_lines = Vec::new();

    for line in original.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let is_swap_line = fields.len() >= 3 && fields[2] == "swap";
        if is_swap_line && fstab_field_matches_device(fields[0], device, &uuid, &partuuid, &label) {
            out_lines.push(format!(
                "# {line}  # disabled by `nyx-hardening swap encrypt` at unix time {now} — \
                 replaced by an encrypted swap entry below"
            ));
            changed = true;
        } else {
            out_lines.push(line.to_string());
        }
    }

    if changed {
        let mut new_content = out_lines.join("\n");
        new_content.push('\n');
        fs::write(FSTAB_PATH, new_content)?;
    }
    Ok(changed)
}

/// Executes the plan for real. Every step is a real, individually
/// verifiable system mutation — nothing here is simulated. Order matters:
/// the plaintext swap is turned off *before* anything else is touched, so
/// a failure partway through never leaves plaintext swap active and
/// silently believed-to-be-encrypted; the old fstab line is commented
/// out, never deleted, so a failure is always recoverable by hand.
///
/// Steps taken (real commands, run in this order):
///   1. `swapoff <device>`                                — disable the plaintext swap now.
///   2. comment out its `/etc/fstab` line (if any)          — never deleted, just disabled.
///   3. append the new `/etc/fstab` line for `/dev/mapper/<mapper>`.
///   4. append the new `/etc/crypttab` line (see `plan_encrypt`).
///   5. `systemctl daemon-reload`                            — makes systemd re-read crypttab.
///   6. `systemctl start systemd-cryptsetup@<escaped mapper>.service` — opens+mkswaps it now.
///   7. `swapon /dev/mapper/<mapper>`                        — re-enable swap, now encrypted.
pub fn execute_encrypt(plan: &EncryptPlan) -> NyxResult<Vec<String>> {
    let mut done = Vec::new();
    let device_str = plan.device.to_string_lossy().into_owned();

    run("swapoff", &[device_str.as_str()])?;
    done.push(format!("swapoff {device_str}"));

    if comment_out_fstab_entry(&plan.device)? {
        done.push(format!("commented out the plaintext swap line for {device_str} in {FSTAB_PATH}"));
    }

    if append_line_if_absent(FSTAB_PATH, &plan.fstab_line)? {
        done.push(format!("appended '{}' to {FSTAB_PATH}", plan.fstab_line));
    }

    if append_line_if_absent(CRYPTTAB_PATH, &plan.crypttab_line)? {
        done.push(format!("appended '{}' to {CRYPTTAB_PATH}", plan.crypttab_line));
    }

    run("systemctl", &["daemon-reload"])?;
    done.push("systemctl daemon-reload".to_string());

    let escaped = systemd_escape(&plan.mapper_name)?;
    let unit = format!("systemd-cryptsetup@{escaped}.service");
    run("systemctl", &["start", &unit])?;
    done.push(format!("systemctl start {unit}"));

    let mapper_path = format!("/dev/mapper/{}", plan.mapper_name);
    run("swapon", &[mapper_path.as_str()])?;
    done.push(format!("swapon {mapper_path}"));

    Ok(done)
}
