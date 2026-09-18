//! Category 6: changes to the Nyx-owned nftables tables.
//!
//! Uses `nft list table inet <name>` per table rather than `nft -j list
//! ruleset` (or even `nft list ruleset`): a single table's plain-text
//! listing is deterministic and stable to diff line-for-line for a given
//! ruleset, and scoping the query to exactly the table names Nyx owns
//! means an unrelated table something else on the system created can
//! never show up as noise. `nft`'s JSON output is more complete but
//! encodes each table's rules as entries in one flat top-level array
//! mixed with metadata objects — diffing that reliably would mean either
//! depending on `nft`'s JSON schema staying byte-stable across versions or
//! writing a real JSON-structural differ, neither of which buys anything
//! `nft list table inet <name>`'s plain text doesn't already give for
//! this specific job.
//!
//! Table names match exactly what's already in this codebase: `nyx` is
//! the boot-time baseline table nftables.service loads from
//! `/etc/nftables.conf` (see `iso/airootfs/etc/nftables.conf`);
//! `nyx_killswitch`, `nyx_armed`, and `nyx_panic` are the tables
//! `nyx-health/src/firewall.rs` creates/tears down at runtime for the
//! kill switch and panic lockdown.

use std::collections::HashMap;
use std::process::Command;

pub const NYX_TABLES: [&str; 4] = ["nyx", "nyx_killswitch", "nyx_armed", "nyx_panic"];

/// Current text of every Nyx-owned table that exists right now. A table
/// that doesn't exist (either never created, e.g. `nyx_panic` outside
/// panic mode, or `nft` exits non-zero for any other reason) is simply
/// absent from the map — same "absence is not an error" stance
/// `nyx-health/src/firewall.rs::delete_table` already takes toward a
/// missing table.
pub fn snapshot() -> HashMap<String, String> {
    let mut out = HashMap::new();
    for name in NYX_TABLES {
        let Ok(output) = Command::new("nft").args(["list", "table", "inet", name]).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        out.insert(name.to_string(), String::from_utf8_lossy(&output.stdout).into_owned());
    }
    out
}
