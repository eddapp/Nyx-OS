//! Fresh local checks nyx-diagnostics performs itself, rather than asking
//! an existing daemon — interface/route dumps, a ping-based connectivity
//! test, traceroute, and an explicit, opt-in public-IP lookup.

use serde::Serialize;
use std::process::Command;

fn run_capture(bin: &str, args: &[&str]) -> String {
    match Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Ok(o) => format!(
            "{bin} exited with {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("failed to run {bin}: {e}"),
    }
}

#[derive(Serialize, Default)]
pub struct NetworkDump {
    pub interfaces: String,
    pub routes: String,
}

pub fn network_dump() -> NetworkDump {
    NetworkDump {
        interfaces: run_capture("ip", &["-o", "addr", "show"]),
        routes: run_capture("ip", &["route", "show"]),
    }
}

#[derive(Serialize, Default)]
pub struct PingResult {
    pub host: String,
    pub transmitted: u32,
    pub received: u32,
    /// `None` if the summary line couldn't be parsed — never a
    /// fabricated 0%.
    pub packet_loss_percent: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub raw_output: String,
}

pub fn ping(host: &str, count: u32, timeout_secs: u32) -> Result<PingResult, String> {
    let output = Command::new("ping")
        .args(["-c", &count.to_string(), "-W", &timeout_secs.to_string(), host])
        .output()
        .map_err(|e| format!("failed to spawn ping: {e}"))?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let mut result = PingResult { host: host.to_string(), raw_output: raw.clone(), ..Default::default() };

    for line in raw.lines() {
        if line.contains("packets transmitted") {
            // "4 packets transmitted, 4 received, 0% packet loss, time 3045ms"
            let parts: Vec<&str> = line.split(',').collect();
            result.transmitted = parts
                .first()
                .and_then(|p| p.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            result.received = parts
                .get(1)
                .and_then(|p| p.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            for part in &parts {
                if let Some(pct) = part.trim().strip_suffix("% packet loss") {
                    result.packet_loss_percent = pct.trim().parse().ok();
                }
            }
        }
        let trimmed = line.trim_start();
        let is_rtt_summary =
            trimmed.starts_with("rtt min/avg/max") || trimmed.starts_with("round-trip min/avg/max");
        if is_rtt_summary
            && let Some(values) = line.split('=').nth(1)
        {
            let nums: Vec<&str> = values.trim().split('/').collect();
            if let Some(avg) = nums.get(1) {
                result.avg_rtt_ms = avg.trim().parse().ok();
            }
        }
    }

    Ok(result)
}

#[derive(Serialize, Default)]
pub struct TracerouteResult {
    pub host: String,
    pub output: String,
}

pub fn traceroute(host: &str) -> TracerouteResult {
    TracerouteResult {
        host: host.to_string(),
        output: run_capture("traceroute", &["-w", "2", "-q", "1", host]),
    }
}

#[derive(Serialize, Default)]
pub struct PublicIpResult {
    pub endpoint: String,
    pub ip: String,
}

/// Sends exactly one HTTP request to `endpoint`, which will see this
/// machine's real public IP and know a NyxOS user asked. Deliberately not
/// something any daemon does automatically — see `main.rs`'s `--yes`
/// requirement.
pub fn public_ip(endpoint: &str) -> Result<PublicIpResult, String> {
    let output = Command::new("curl")
        .args(["-s", "--max-time", "5", endpoint])
        .output()
        .map_err(|e| format!("failed to spawn curl: {e}"))?;
    if !output.status.success() {
        return Err(format!("curl exited with {}", output.status));
    }
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.is_empty() {
        return Err(format!("{endpoint} returned an empty response"));
    }
    Ok(PublicIpResult { endpoint: endpoint.to_string(), ip })
}
