//! Ties the six categories together: gather current state, diff it
//! against whatever `AppState` is holding from the previous poll, turn
//! real differences into `WatchEvent`s, and hand the new snapshot back to
//! `AppState` to hold until next time.

use crate::protocol::{WatchCategory, WatchEvent};
use crate::sockets::SocketSnapshot;
use crate::state::{AppState, Snapshot};
use crate::{dns_watch, firewall, procs, routes, sockets};
use nyx_core::DnsReport;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Runs one full poll cycle and records whatever it finds into `state`.
pub async fn poll_once(state: &AppState) {
    let poll_unix = unix_now();

    // The DNS query is its own async round-trip over a Unix socket; every
    // other category is synchronous fs/Command work, so it runs on a
    // blocking-pool thread rather than tying up an async worker thread.
    let dns_report = dns_watch::query().await;

    let blocking_result = tokio::task::spawn_blocking(|| {
        let sockets = sockets::snapshot_all();
        let root_procs = procs::snapshot();
        let route_lines = routes::snapshot();
        let fw_tables = firewall::snapshot();
        (sockets, root_procs, route_lines, fw_tables)
    })
    .await;

    let Ok((sockets, root_procs, route_lines, fw_tables)) = blocking_result else {
        tracing::error!("nyx-watch: blocking poll task panicked; skipping this poll");
        return;
    };

    state
        .run_poll(poll_unix, move |prev| {
            build_diff(prev, poll_unix, sockets, root_procs, route_lines, fw_tables, dns_report)
        })
        .await;
}

fn describe_pid(inode: u64) -> String {
    match sockets::inode_to_pid(inode) {
        Some((pid, comm)) if !comm.is_empty() => format!(" (pid {pid}, {comm}, inode {inode})"),
        Some((pid, _)) => format!(" (pid {pid}, inode {inode})"),
        None => format!(" (inode {inode}, owning pid not resolved — process likely exited already)"),
    }
}

fn build_diff(
    prev: &Snapshot,
    poll_unix: u64,
    sockets: SocketSnapshot,
    root_procs: HashMap<u32, procs::RootProc>,
    routes: HashSet<String>,
    fw_tables: HashMap<String, String>,
    dns: Option<DnsReport>,
) -> (Snapshot, Vec<WatchEvent>) {
    let mut events = Vec::new();
    let priming = !prev.primed;

    if !priming {
        // --- Category 1: new listening sockets --------------------------
        for key in sockets.listening.difference(&prev.listening) {
            let pid_desc = sockets.listening_inodes.get(key).map(|i| describe_pid(*i)).unwrap_or_default();
            events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::ListeningSocket,
                description: format!(
                    "new {} listener on {}:{}{}",
                    key.proto, key.addr, key.port, pid_desc
                ),
            });
        }

        // --- Category 3: new outbound connections ------------------------
        for key in sockets.established.difference(&prev.established) {
            let pid_desc = sockets.established_inodes.get(key).map(|i| describe_pid(*i)).unwrap_or_default();
            events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::OutboundConnection,
                description: format!(
                    "new outbound {} connection {}:{} -> {}:{}{}",
                    key.proto, key.local_addr, key.local_port, key.remote_addr, key.remote_port, pid_desc
                ),
            });
        }

        // --- Category 2: new root-owned processes ------------------------
        for (pid, proc_info) in &root_procs {
            if prev.root_procs.contains_key(pid) {
                continue;
            }
            let when = match proc_info.start_unix {
                Some(t) => format!("started at unix time {t}"),
                None => "start time unavailable (process may have exited already)".to_string(),
            };
            let comm = if proc_info.comm.is_empty() { "<unknown>" } else { &proc_info.comm };
            events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::RootProcess,
                description: format!("new root-owned process pid {pid} ({comm}), {when}"),
            });
        }

        // --- Category 4: DNS posture changes ------------------------------
        events.extend(diff_dns(prev.dns.as_ref(), dns.as_ref(), poll_unix));

        // --- Category 5: route table changes ------------------------------
        for line in routes.difference(&prev.routes) {
            events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::Route,
                description: format!("route added: {line}"),
            });
        }
        for line in prev.routes.difference(&routes) {
            events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::Route,
                description: format!("route removed: {line}"),
            });
        }

        // --- Category 6: firewall table changes ---------------------------
        events.extend(diff_firewall(&prev.firewall_tables, &fw_tables, poll_unix));
    }

    let new_snapshot = Snapshot {
        listening: sockets.listening,
        established: sockets.established,
        root_procs,
        dns,
        routes,
        firewall_tables: fw_tables,
        primed: true,
    };

    (new_snapshot, events)
}

fn diff_dns(prev: Option<&DnsReport>, current: Option<&DnsReport>, poll_unix: u64) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    match (prev, current) {
        (None, None) => {}
        (Some(_), None) => events.push(WatchEvent {
            unix_time: poll_unix,
            category: WatchCategory::Dns,
            description: "nyx-dns became unreachable (was answering at the previous poll)".to_string(),
        }),
        (None, Some(_)) => events.push(WatchEvent {
            unix_time: poll_unix,
            category: WatchCategory::Dns,
            description: "nyx-dns became reachable".to_string(),
        }),
        (Some(p), Some(c)) => {
            if p.resolver_addrs != c.resolver_addrs {
                events.push(WatchEvent {
                    unix_time: poll_unix,
                    category: WatchCategory::Dns,
                    description: format!(
                        "resolv.conf nameservers changed: {:?} -> {:?}",
                        p.resolver_addrs, c.resolver_addrs
                    ),
                });
            }
            if p.dnscrypt_active != c.dnscrypt_active {
                events.push(WatchEvent {
                    unix_time: poll_unix,
                    category: WatchCategory::Dns,
                    description: format!(
                        "dnscrypt-proxy active state changed: {} -> {}",
                        p.dnscrypt_active, c.dnscrypt_active
                    ),
                });
            }
            if p.foreign_listener_on_53 != c.foreign_listener_on_53 {
                events.push(WatchEvent {
                    unix_time: poll_unix,
                    category: WatchCategory::Dns,
                    description: format!(
                        "foreign (non-loopback) listener on port 53 changed: {} -> {}",
                        p.foreign_listener_on_53, c.foreign_listener_on_53
                    ),
                });
            }
        }
    }
    events
}

fn diff_firewall(
    prev: &HashMap<String, String>,
    current: &HashMap<String, String>,
    poll_unix: u64,
) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    for name in firewall::NYX_TABLES {
        match (prev.get(name), current.get(name)) {
            (None, None) => {}
            (None, Some(_)) => events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::Firewall,
                description: format!("nftables table 'inet {name}' appeared"),
            }),
            (Some(_), None) => events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::Firewall,
                description: format!("nftables table 'inet {name}' was removed"),
            }),
            (Some(old), Some(new)) if old != new => events.push(WatchEvent {
                unix_time: poll_unix,
                category: WatchCategory::Firewall,
                description: format!(
                    "nftables table 'inet {name}' ruleset changed (attribution to nyx-health vs. \
                     something else is not automated — see nyx-watch's design notes)"
                ),
            }),
            _ => {}
        }
    }
    events
}
