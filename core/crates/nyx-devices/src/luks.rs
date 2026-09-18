//! Real block-device topology via `lsblk --json` — whether `/` is actually
//! sitting on a `crypto_LUKS` device, not a settings flag anywhere claiming
//! "disk encryption: on".

use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
struct BlockDevice {
    name: String,
    fstype: Option<String>,
    mountpoint: Option<String>,
    #[serde(default)]
    children: Vec<BlockDevice>,
}

#[derive(Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

fn tree() -> Option<Vec<BlockDevice>> {
    let output = Command::new("lsblk")
        .args(["-J", "-o", "NAME,FSTYPE,MOUNTPOINT"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let parsed: LsblkOutput = serde_json::from_slice(&output.stdout).ok()?;
    Some(parsed.blockdevices)
}

/// LUKS containers hold their unlocked filesystem as a `children` entry
/// (e.g. `sda3` fstype `crypto_LUKS` -> child `luks-<uuid>` fstype `ext4`
/// mountpoint `/`), so "is `/` encrypted" means walking down until the
/// mountpoint matches, then checking whether its *parent* was the LUKS
/// container.
fn find_root_parent_fstype(devices: &[BlockDevice], parent_fstype: Option<&str>) -> Option<Option<String>> {
    for dev in devices {
        if dev.mountpoint.as_deref() == Some("/") {
            return Some(parent_fstype.map(str::to_string));
        }
        if let Some(found) = find_root_parent_fstype(&dev.children, dev.fstype.as_deref()) {
            return Some(found);
        }
    }
    None
}

pub fn root_is_encrypted() -> Option<bool> {
    let devices = tree()?;
    let parent_fstype = find_root_parent_fstype(&devices, None)?;
    Some(parent_fstype.as_deref() == Some("crypto_LUKS"))
}

fn collect_luks(devices: &[BlockDevice], out: &mut Vec<String>) {
    for dev in devices {
        if dev.fstype.as_deref() == Some("crypto_LUKS") {
            out.push(dev.name.clone());
        }
        collect_luks(&dev.children, out);
    }
}

pub fn luks_devices() -> Vec<String> {
    let Some(devices) = tree() else { return Vec::new() };
    let mut out = Vec::new();
    collect_luks(&devices, &mut out);
    out
}
