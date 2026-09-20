//! Shells out to the already-built `nyx-diagnostics` binary for the two
//! checks it owns that the dashboard has no socket to reach: default-route
//! parsing and the consent-gated public-IP lookup. Parses its existing
//! `NyxOutput<T>` JSON stdout/stderr — never reimplements the checks
//! themselves. `nyx-diagnostics` is a one-shot CLI with no daemon/socket of
//! its own, so a subprocess call is the only way to reuse it; DNS status,
//! by contrast, has a real daemon socket and is called directly (see
//! `client::send_dns`).

use nyx_core::{NyxOutput, Status};
use serde::Deserialize;
use std::process::Command;

const BINARY: &str = "nyx-diagnostics";

#[derive(Deserialize)]
struct NetworkDump {
    interfaces: String,
    routes: String,
}

#[derive(Default, Clone)]
pub struct DefaultRoute {
    pub interface: Option<String>,
    pub gateway: Option<String>,
    /// First IPv4 address (without prefix length) configured on
    /// `interface`, from the same `nyx-diagnostics network` dump's
    /// `ip -o addr show` output.
    pub address: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
pub struct PublicIpResult {
    pub endpoint: String,
    pub ip: String,
}

/// Runs `nyx-diagnostics <args>` and returns its reported data, or the
/// message it reported on failure. Its error path can land on stdout (a
/// failed check still prints a normal `NyxOutput`) or stderr (the `--yes`
/// refusal uses `eprintln!`), so both are checked.
fn run_json<T: for<'de> Deserialize<'de>>(args: &[&str]) -> Result<T, String> {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {BINARY}: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stdout
        .lines()
        .next()
        .filter(|l| !l.trim().is_empty())
        .or_else(|| stderr.lines().next())
        .ok_or_else(|| format!("{BINARY} produced no output"))?;

    let parsed: NyxOutput<T> =
        serde_json::from_str(line).map_err(|e| format!("bad output from {BINARY}: {e}"))?;

    match parsed.status {
        Status::Ok | Status::Warning => {
            parsed.data.ok_or_else(|| "no data in response".to_string())
        }
        Status::Error => Err(parsed.message),
    }
}

/// Same `dev`/`via` token parse `nyx-vpn::route::default_route_interface`/
/// `default_gateway` use — duplicated in miniature rather than imported
/// because `nyx-vpn` is a binary crate with no library target, so those
/// functions aren't reachable from here.
fn parse_default_route(routes_text: &str) -> DefaultRoute {
    for line in routes_text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("default") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let interface =
            tokens.iter().position(|t| *t == "dev").and_then(|i| tokens.get(i + 1)).map(|s| s.to_string());
        let gateway =
            tokens.iter().position(|t| *t == "via").and_then(|i| tokens.get(i + 1)).map(|s| s.to_string());
        return DefaultRoute { interface, gateway, address: None };
    }
    DefaultRoute::default()
}

/// `ip -o addr show` prints one line per address:
/// `2: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global ...`.
/// Returns the first `inet` (IPv4) address on `interface`, prefix stripped.
fn parse_interface_ipv4(interfaces_text: &str, interface: &str) -> Option<String> {
    for line in interfaces_text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.get(1) != Some(&interface) {
            continue;
        }
        if let Some(i) = tokens.iter().position(|t| *t == "inet") {
            return tokens.get(i + 1).map(|a| a.split('/').next().unwrap_or(a).to_string());
        }
    }
    None
}

/// Interface/gateway of the current IPv4 default route, via
/// `nyx-diagnostics network`'s existing route-table dump (an ordinary
/// unprivileged `ip route show` — no external service involved).
pub fn fetch_default_route() -> Result<DefaultRoute, String> {
    let dump: NetworkDump = run_json(&["network"])?;
    let mut route = parse_default_route(&dump.routes);
    if let Some(iface) = &route.interface {
        route.address = parse_interface_ipv4(&dump.interfaces, iface);
    }
    Ok(route)
}

/// Runs exactly one `nyx-diagnostics public-ip --yes` — one outbound
/// request to the external endpoint, only when the caller (the dashboard's
/// "Check Public IP" button handler) explicitly invokes this. Never call
/// this from a timer/refresh loop.
pub fn fetch_public_ip() -> Result<PublicIpResult, String> {
    run_json(&["public-ip", "--yes"])
}
