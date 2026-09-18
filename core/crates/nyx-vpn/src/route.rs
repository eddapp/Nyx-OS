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

/// The gateway IP and interface currently carrying the IPv4 default route,
/// if any. Used by the SOCKS5 backend to add a bypass route to the SOCKS5
/// endpoint itself over the *existing* path before replacing the default
/// route with a TUN device that only knows how to reach that endpoint via
/// SOCKS5 — without this, connecting to the SOCKS5 server would recurse
/// through the tunnel that depends on connecting to it.
pub fn default_gateway() -> Option<(String, String)> {
    let output = Command::new("ip")
        .args(["-o", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first_line = text.lines().next()?;
    let tokens: Vec<&str> = first_line.split_whitespace().collect();
    let dev_pos = tokens.iter().position(|t| *t == "dev")?;
    let via_pos = tokens.iter().position(|t| *t == "via")?;
    let dev = tokens.get(dev_pos + 1)?.to_string();
    let via = tokens.get(via_pos + 1)?.to_string();
    Some((dev, via))
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
