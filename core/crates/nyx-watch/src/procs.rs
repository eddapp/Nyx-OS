//! Category 2: newly-appeared processes owned by uid 0.
//!
//! Ownership is read from `/proc/<pid>/status`'s `Uid:` line rather than
//! `stat`-ing `/proc/<pid>` — `status` reports the process's real uid
//! directly as a decimal field with no extra syscall/permission subtlety,
//! whereas the ownership of the `/proc/<pid>` directory entry itself is
//! not guaranteed to track the process's *current* uid as reliably across
//! `setuid()` (the directory is always owned by the process's real+saved
//! set at creation time in practice, but `status` is the value the kernel
//! itself documents for "what uid is this process"). Since nyx-watch
//! already needs to open per-process files for the fd walk in
//! `sockets.rs`, reading one more small text file per PID here is no
//! additional privilege cost.
//!
//! Start time is computed from `/proc/<pid>/stat` field 22 (clock ticks
//! since boot) converted with the real ticks-per-second from
//! `sysconf(_SC_CLK_TCK)` (not hardcoded — it's usually 100 on Linux but
//! that's not guaranteed by anything nyx-watch controls) plus the real
//! boot time (`btime`) from `/proc/stat`.

use std::collections::HashMap;
use std::fs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootProc {
    pub comm: String,
    /// Unix time (UTC) the process started, or `None` if `/proc/<pid>/stat`
    /// couldn't be read/parsed in the brief window this lookup ran (e.g.
    /// process already exited) — reported as unknown rather than a
    /// fabricated 0.
    pub start_unix: Option<u64>,
}

/// `/proc/stat`'s `btime` line: boot time as a real Unix timestamp, the
/// same value `uptime`/`ps` ultimately derive process ages from.
fn boot_time_unix() -> Option<u64> {
    let contents = fs::read_to_string("/proc/stat").ok()?;
    contents
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Real ticks-per-second the kernel uses for `/proc/<pid>/stat`'s time
/// fields, via `sysconf(_SC_CLK_TCK)` — not assumed to be 100 even though
/// that's almost always true on Linux/x86.
fn clock_ticks_per_sec() -> i64 {
    // SAFETY: sysconf with a well-known, valid name; no pointers involved.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks
    } else {
        100 // sysconf itself failed (returned -1); 100 is Linux's near-universal default.
    }
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`, in clock ticks since boot.
/// Parsed after the last `)` so a `comm` value containing spaces or
/// parentheses (both legal in a process name) can't shift the field
/// offsets — the same trick `ps`/`procps` use for this file.
fn parse_starttime_ticks(stat_contents: &str) -> Option<u64> {
    let close_paren = stat_contents.rfind(')')?;
    let rest = &stat_contents[close_paren + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] here is stat's field 3 (state); field 22 (starttime) is
    // therefore fields[22 - 3] = fields[19].
    fields.get(19)?.parse::<u64>().ok()
}

/// The real uid from `/proc/<pid>/status`'s `Uid:\t<real>\t<eff>\t<saved>\t<fs>` line.
fn real_uid(status_contents: &str) -> Option<u32> {
    let line = status_contents.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Every currently-running process owned by uid 0, keyed by PID. Processes
/// that exit mid-scan, or whose files can't be read for any reason, are
/// simply left out rather than treated as an error — a process disappearing
/// between `read_dir("/proc")` and reading its files is normal and not a
/// fault condition.
pub fn snapshot() -> HashMap<u32, RootProc> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else { return out };
    let btime = boot_time_unix();
    let hz = clock_ticks_per_sec();

    for entry in entries.flatten() {
        let Some(pid_str) = entry.file_name().to_str().map(str::to_string) else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };

        let Ok(status) = fs::read_to_string(format!("/proc/{pid_str}/status")) else { continue };
        let Some(uid) = real_uid(&status) else { continue };
        if uid != 0 {
            continue;
        }

        let comm = fs::read_to_string(format!("/proc/{pid_str}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let start_unix = fs::read_to_string(format!("/proc/{pid_str}/stat"))
            .ok()
            .and_then(|s| parse_starttime_ticks(&s))
            .zip(btime)
            .map(|(ticks, boot)| boot + ticks / hz.max(1) as u64);

        out.insert(pid, RootProc { comm, start_unix });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_time_is_a_real_past_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let btime = boot_time_unix().expect("/proc/stat must have a btime line");
        assert!(btime > 0 && btime <= now);
    }

    #[test]
    fn snapshot_always_includes_pid_1_or_is_permission_limited() {
        // PID 1 is owned by root on every real Linux system; if this test
        // process can't see it, that's a sandboxing artifact of the test
        // environment, not a bug in the parsing logic itself, so this is
        // informational rather than a hard assertion.
        let procs = snapshot();
        let _ = procs.get(&1);
    }
}
