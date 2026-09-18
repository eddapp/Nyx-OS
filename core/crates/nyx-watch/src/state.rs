//! In-memory state: the previous poll's snapshot (so the next poll has
//! something real to diff against) and a bounded ring buffer of the
//! events that diffing has produced since startup.

use crate::protocol::{WatchEvent, WatchReport, EVENT_CAPACITY};
use crate::{procs, sockets};
use nyx_core::DnsReport;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::Mutex;

/// Everything compared against the previous poll. `primed` is false only
/// before the very first poll completes — the first poll has nothing real
/// to diff against, so it captures this baseline without emitting any
/// events, the same way `nyx-telemetry`'s network sampling reports `None`
/// for a rate on an interface's first-ever sample rather than fabricating
/// one against a nonexistent prior value.
#[derive(Default)]
pub struct Snapshot {
    pub listening: HashSet<sockets::ListenKey>,
    pub established: HashSet<sockets::ConnKey>,
    pub root_procs: HashMap<u32, procs::RootProc>,
    pub dns: Option<DnsReport>,
    pub routes: HashSet<String>,
    pub firewall_tables: HashMap<String, String>,
    pub primed: bool,
}

struct Inner {
    snapshot: Snapshot,
    events: VecDeque<WatchEvent>,
    poll_count: u64,
    total_events: u64,
    last_poll_unix: u64,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            snapshot: Snapshot::default(),
            events: VecDeque::with_capacity(EVENT_CAPACITY),
            poll_count: 0,
            total_events: 0,
            last_poll_unix: 0,
        }
    }
}

#[derive(Default)]
pub struct AppState {
    inner: Mutex<Inner>,
}

impl AppState {
    /// Runs `poll` with exclusive access to the previous snapshot, records
    /// whatever events it returns, advances bookkeeping, and stores the
    /// new snapshot it produced — all under one lock so a concurrent
    /// `Status` call never observes a half-updated state.
    pub async fn run_poll<F>(&self, poll_unix: u64, poll: F)
    where
        F: FnOnce(&Snapshot) -> (Snapshot, Vec<WatchEvent>),
    {
        let mut inner = self.inner.lock().await;
        let (new_snapshot, new_events) = poll(&inner.snapshot);

        inner.poll_count += 1;
        inner.last_poll_unix = poll_unix;
        inner.total_events += new_events.len() as u64;
        for event in new_events {
            if inner.events.len() == EVENT_CAPACITY {
                inner.events.pop_front();
            }
            inner.events.push_back(event);
        }
        inner.snapshot = new_snapshot;
    }

    pub async fn report(&self) -> WatchReport {
        let inner = self.inner.lock().await;
        let events: Vec<WatchEvent> = inner.events.iter().cloned().collect();
        let detail = if inner.poll_count == 0 {
            "no poll has completed yet".to_string()
        } else {
            format!(
                "{} poll(s) completed, {} event(s) recorded since start, {} currently retained",
                inner.poll_count,
                inner.total_events,
                events.len()
            )
        };
        WatchReport {
            last_poll_unix: inner.last_poll_unix,
            poll_count: inner.poll_count,
            total_events: inner.total_events,
            events,
            detail,
        }
    }
}
