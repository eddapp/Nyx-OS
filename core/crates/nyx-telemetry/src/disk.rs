//! Real disk usage via `statvfs` on every real (non-pseudo) mounted
//! filesystem found in `/proc/mounts` — an allowlist of actual disk
//! filesystem types, not a blocklist that could let a new pseudo-fs slip
//! through and get reported as "disk space".

use nix::sys::statvfs::statvfs;
use nyx_core::DiskTelemetry;
use std::collections::HashSet;
use std::fs;

const REAL_FILESYSTEMS: &[&str] = &[
    "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "iso9660",
    "udf", "overlay",
];

pub fn samples() -> Vec<DiskTelemetry> {
    let Ok(contents) = fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(_device) = fields.next() else { continue };
        let Some(mountpoint) = fields.next() else { continue };
        let Some(fstype) = fields.next() else { continue };

        if !REAL_FILESYSTEMS.contains(&fstype) {
            continue;
        }
        // The same overlay/bind mount can appear more than once in
        // /proc/mounts (containers, bind mounts); report each mountpoint
        // only once.
        if !seen.insert(mountpoint.to_string()) {
            continue;
        }

        if let Ok(stat) = statvfs(mountpoint) {
            let block_size = stat.fragment_size();
            let total = stat.blocks() * block_size;
            let free = stat.blocks_free() * block_size;
            let available = stat.blocks_available() * block_size;
            out.push(DiskTelemetry {
                mountpoint: mountpoint.to_string(),
                total_bytes: total,
                used_bytes: total.saturating_sub(free),
                available_bytes: available,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_root_filesystem() {
        let disks = samples();
        assert!(!disks.is_empty(), "expected at least one real filesystem from /proc/mounts");
        for d in &disks {
            assert!(d.total_bytes > 0, "{} reported zero total size", d.mountpoint);
            assert!(d.used_bytes <= d.total_bytes, "{} used > total", d.mountpoint);
        }
    }
}
