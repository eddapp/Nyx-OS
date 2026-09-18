//! Categories 1 and 3: new listening sockets and new outbound
//! (ESTABLISHED, non-loopback-remote) connections, both diffed from the
//! same `/proc/net/{tcp,tcp6,udp,udp6}` source `proc_net` parses.
//!
//! Inode -> PID mapping (`inode_to_pid`) requires root: `/proc/<pid>/fd`
//! is `dr-x--x--x`, and reading the fd symlinks of a process you don't own
//! is gated by the same check as `ptrace()` (`ptrace_may_access` in the
//! kernel), not plain DAC file permissions — an unprivileged nyx-watch
//! could only ever resolve its *own* sockets' owning PID. Root (as this
//! daemon requires, and runs as, with no capability bounding set applied
//! in its systemd unit) carries `CAP_SYS_PTRACE` and can resolve any
//! process's sockets, at the cost of walking every PID's fd table on each
//! lookup — acceptable here because it's only ever done for sockets that
//! just showed up as new, not for every socket on every poll.

use crate::proc_net::{self, SocketEntry, TCP_ESTABLISHED, TCP_LISTEN};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;

/// (protocol label, local address, local port) — identity of a listening
/// socket. Keyed on address+port, not inode: a service that restarts and
/// rebinds the exact same port is a continuation of the same *listener*
/// from an external observer's point of view, not a new one. A genuinely
/// different process taking over a port shows up instead as a new/changed
/// entry in category 2 (new root process) or is visible via the reported
/// PID if it differs.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ListenKey {
    pub proto: &'static str,
    pub addr: IpAddr,
    pub port: u16,
}

/// Identity of an outbound connection: the full local+remote 4-tuple, since
/// unlike a listener, two different connections can legitimately share a
/// local port (e.g. an outbound TCP connection's ephemeral source port) and
/// are genuinely different events.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ConnKey {
    pub proto: &'static str,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

const TABLES: [(&str, &str, bool); 4] = [
    ("tcp", "/proc/net/tcp", false),
    ("tcp6", "/proc/net/tcp6", true),
    ("udp", "/proc/net/udp", false),
    ("udp6", "/proc/net/udp6", true),
];

fn is_tcp(proto: &str) -> bool {
    proto == "tcp" || proto == "tcp6"
}

/// Current set of outbound connections: TCP entries in ESTABLISHED state
/// whose remote address is not loopback. UDP is excluded here — it has no
/// real "established" concept in this table (a bound UDP socket looks the
/// same whether or not it has ever exchanged a packet with anyone), so
/// treating any UDP entry as an "outbound connection" would be a fabricated
/// signal rather than a real one.
pub fn snapshot_established(
    entries_by_table: &[(&'static str, Vec<SocketEntry>)],
) -> (HashSet<ConnKey>, HashMap<ConnKey, u64>) {
    let mut out = HashSet::new();
    let mut inodes = HashMap::new();
    for (proto, entries) in entries_by_table {
        if !is_tcp(proto) {
            continue;
        }
        for entry in entries {
            if entry.state != TCP_ESTABLISHED {
                continue;
            }
            if entry.remote_addr.is_loopback() || entry.remote_addr.is_unspecified() {
                continue;
            }
            let key = ConnKey {
                proto,
                local_addr: entry.local_addr,
                local_port: entry.local_port,
                remote_addr: entry.remote_addr,
                remote_port: entry.remote_port,
            };
            out.insert(key.clone());
            inodes.insert(key, entry.inode);
        }
    }
    (out, inodes)
}

/// Everything one poll needs from `/proc/net/*`: the listening-socket and
/// outbound-connection identity sets to diff against the previous poll,
/// plus each one's inode so a caller can resolve a *newly* appeared
/// entry's owning PID without carrying the inode in the identity key
/// itself (see `ListenKey`/`ConnKey`'s docs on why identity excludes it).
#[derive(Default)]
pub struct SocketSnapshot {
    pub listening: HashSet<ListenKey>,
    pub listening_inodes: HashMap<ListenKey, u64>,
    pub established: HashSet<ConnKey>,
    pub established_inodes: HashMap<ConnKey, u64>,
}

/// Parses every table exactly once (`/proc/net/*` is read a single time
/// per table, not once per category) and builds the full snapshot above.
pub fn snapshot_all() -> SocketSnapshot {
    let mut by_table: Vec<(&'static str, Vec<SocketEntry>)> = Vec::with_capacity(TABLES.len());
    let mut listening = HashSet::new();
    let mut listening_inodes = HashMap::new();

    for (proto, path, is_v6) in TABLES {
        let entries = proc_net::parse_table(path, is_v6);
        for entry in &entries {
            let is_listen_worthy = if is_tcp(proto) { entry.state == TCP_LISTEN } else { true };
            if is_listen_worthy {
                let key = ListenKey { proto, addr: entry.local_addr, port: entry.local_port };
                listening.insert(key.clone());
                listening_inodes.insert(key, entry.inode);
            }
        }
        by_table.push((proto, entries));
    }

    let (established, established_inodes) = snapshot_established(&by_table);
    SocketSnapshot { listening, listening_inodes, established, established_inodes }
}

/// Best-effort inode -> (pid, comm) lookup by walking every process's
/// `/proc/<pid>/fd` and reading each symlink, looking for
/// `socket:[<inode>]`. Returns `None` if not found (process exited between
/// the /proc/net read and this lookup, or genuinely unmappable) or if this
/// process lacks permission to read another user's fd table (shouldn't
/// happen when running as root — see module docs — but degrades to "no
/// PID resolved" rather than erroring if it ever does, e.g. a kernel
/// namespace edge case).
pub fn inode_to_pid(target_inode: u64) -> Option<(u32, String)> {
    if target_inode == 0 {
        return None;
    }
    let target_link = format!("socket:[{target_inode}]");

    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let pid_str = entry.file_name().to_str()?.to_string();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid_str}/fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else { continue };
            if link.to_str() == Some(target_link.as_str()) {
                let pid: u32 = pid_str.parse().unwrap_or(0);
                let comm = fs::read_to_string(format!("/proc/{pid_str}/comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                return Some((pid, comm));
            }
        }
    }
    None
}
