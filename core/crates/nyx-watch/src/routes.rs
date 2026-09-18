//! Category 5: route table changes, via the same "shell out to `ip` and
//! trust its output" approach `nyx-vpn/src/route.rs` already uses for the
//! default route — extended here to the whole table (both address
//! families) rather than just the default route, since any route
//! appearing or disappearing is real, observable information.

use std::collections::HashSet;
use std::process::Command;

/// One line per route, prefixed with its address family so a v4 and v6
/// route that happen to render identically after the prefix are never
/// confused with each other. Each line is `ip -o route show`'s own output
/// verbatim (the same format `nyx-vpn/src/route.rs::default_route_interface`
/// parses for the `dev` token) — nyx-watch doesn't need to parse the
/// fields further, only to detect and report that a specific line
/// appeared or disappeared.
pub fn snapshot() -> HashSet<String> {
    let mut out = HashSet::new();
    for (family_tag, args) in [("inet", vec!["-o", "route", "show"]), ("inet6", vec!["-o", "-6", "route", "show"])] {
        let Ok(output) = Command::new("ip").args(&args).output() else { continue };
        if !output.status.success() {
            continue;
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let line = line.trim();
            if !line.is_empty() {
                out.insert(format!("[{family_tag}] {line}"));
            }
        }
    }
    out
}
