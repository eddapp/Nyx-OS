//! Wire protocol for nyx-watch. Kept entirely local to this crate rather
//! than added to `nyx_core::protocol` — nyx-watch is a pure observer over
//! state other daemons (and `nyx_core`) already own, so it doesn't need a
//! shared type any other binary has to agree on. Transport is the same
//! newline-delimited JSON over a Unix socket every other Nyx daemon uses.

use serde::{Deserialize, Serialize};

/// Socket path for nyx-watch. Same trust boundary as every other
/// root-owned Nyx daemon socket (owned by root, group `wheel`, mode 0660):
/// this daemon's own report can reveal which processes/ports/routes exist
/// on the system, which is not information to hand out without at least
/// the "can already sudo" bar every other daemon uses.
pub const WATCH_SOCKET: &str = "/run/nyx/watch.sock";

/// How many of the most recent events the daemon keeps in memory. Old
/// events fall off the front once this fills — this is a rolling window
/// for "what changed recently", not a durable audit log.
pub const EVENT_CAPACITY: usize = 200;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum WatchCommand {
    /// Return the most recent window of change events plus poll
    /// bookkeeping. Never triggers a poll itself — polling only happens on
    /// the background timer — so this is cheap to call as often as wanted.
    Status,
}

/// One of the six real, independently-sourced categories of change this
/// daemon watches for. Deliberately not a severity/anomaly score — see
/// `WatchEvent` for why.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchCategory {
    /// A TCP socket entered LISTEN, or a UDP socket newly appeared bound to
    /// a local address:port, per `/proc/net/{tcp,tcp6,udp,udp6}`.
    ListeningSocket,
    /// A process owned by uid 0 that wasn't running at the previous poll,
    /// per `/proc/*/status`.
    RootProcess,
    /// A TCP socket newly entered ESTABLISHED with a non-loopback remote
    /// address, per `/proc/net/{tcp,tcp6}`.
    OutboundConnection,
    /// `nyx-dns`'s own reported resolver/dnscrypt/foreign-listener state
    /// changed between polls.
    Dns,
    /// A line appeared in or disappeared from `ip route show` (v4 or v6).
    Route,
    /// The text of a Nyx-owned nftables table (`nyx`, `nyx_killswitch`,
    /// `nyx_armed`, `nyx_panic`) changed between polls.
    Firewall,
}

/// A single, factual change record — a timestamp, which of the six
/// categories it belongs to, and a plain-English description of exactly
/// what changed. No severity, no "anomaly confidence": every category here
/// is diffed against real, deterministic system state, so the honest
/// output is "X changed", not a guess about whether that's bad.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    /// Unix seconds (UTC) when the poll that detected this change ran.
    pub unix_time: u64,
    pub category: WatchCategory,
    pub description: String,
}

/// `nyx-watch`'s `Status` response. There is no `SecurityState` here on
/// purpose: "did something change" isn't a posture that's Protected or
/// Blocked — it's just a fact with a count and a timestamp. Callers that
/// want a verdict can look at whether `events` is non-empty since their
/// last check; nyx-watch itself doesn't judge.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchReport {
    /// Unix time of the most recently completed poll; 0 if none have
    /// completed yet (should only be visible for a very brief window right
    /// after startup, before the priming poll finishes).
    pub last_poll_unix: u64,
    /// How many polls have completed since this daemon started.
    pub poll_count: u64,
    /// Total events recorded since start — can exceed `events.len()` once
    /// the ring buffer has wrapped past `EVENT_CAPACITY`.
    pub total_events: u64,
    /// The most recent events, oldest first, capped at `EVENT_CAPACITY`.
    pub events: Vec<WatchEvent>,
    pub detail: String,
}
