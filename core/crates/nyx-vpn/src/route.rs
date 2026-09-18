//! Real route inspection via `ip route` — the supported way to ask the
//! kernel's routing table anything, same as `ip-route(8)` itself documents.

use std::process::Command;

/// The interface currently carrying the IPv4 default route, if any. Used to
/// answer "is the VPN actually the path my traffic takes", not just "is the
/// VPN interface up".
pub fn default_route_interface() -> Option<String> {
    let output = Command::new("ip")
        .args(["-o", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // Typical line: "default via 10.0.0.1 dev wlan0 proto dhcp metric 600"
    // — possibly several lines (multiple default routes/metrics); take the
    // device from the first one, which is the one actually preferred.
    let first_line = text.lines().next()?;
    let tokens: Vec<&str> = first_line.split_whitespace().collect();
    let dev_pos = tokens.iter().position(|t| *t == "dev")?;
    tokens.get(dev_pos + 1).map(|s| s.to_string())
}

/// True if `iface` has at least one IPv4 address assigned — used as a weak
/// signal that a tunnel interface (especially OpenVPN's, which doesn't
/// expose a handshake-recency concept the way WireGuard does) is actually
/// configured and not just present-but-inert.
pub fn interface_has_address(iface: &str) -> bool {
    let output = Command::new("ip").args(["-o", "-4", "addr", "show", iface]).output();
    match output {
        Ok(o) => o.status.success() && !o.stdout.is_empty(),
        Err(_) => false,
    }
}
