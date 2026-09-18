//! Per-interface throughput from `/proc/net/dev`. A byte counter alone
//! isn't a rate — this pairs a fresh sample against whatever was captured
//! last call (kept in `AppState`) to compute real bytes/sec, and reports
//! `None` rather than a fabricated number for any interface with no prior
//! sample yet (first call, or one that just appeared).

use nyx_core::NetworkInterfaceTelemetry;
use std::collections::HashMap;
use std::fs;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct IfaceSample {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn sample() -> HashMap<String, IfaceSample> {
    let Ok(contents) = fs::read_to_string("/proc/net/dev") else {
        return HashMap::new();
    };

    let mut out = HashMap::new();
    for line in contents.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let fields: Vec<u64> = rest.split_whitespace().filter_map(|f| f.parse().ok()).collect();
        // Receive: bytes packets errs drop fifo frame compressed multicast (8)
        // Transmit: bytes packets errs drop fifo colls carrier compressed (8)
        if fields.len() < 16 {
            continue;
        }
        out.insert(name.trim().to_string(), IfaceSample { rx_bytes: fields[0], tx_bytes: fields[8] });
    }
    out
}

pub fn to_reports(
    previous: &HashMap<String, (IfaceSample, Instant)>,
    current: &HashMap<String, IfaceSample>,
    now: Instant,
) -> Vec<NetworkInterfaceTelemetry> {
    current
        .iter()
        .map(|(name, sample)| {
            let rates = previous.get(name).and_then(|(prev, prev_time)| {
                let elapsed = now.saturating_duration_since(*prev_time).as_secs_f64();
                if elapsed <= 0.0 {
                    return None;
                }
                let rx_delta = sample.rx_bytes.checked_sub(prev.rx_bytes)?;
                let tx_delta = sample.tx_bytes.checked_sub(prev.tx_bytes)?;
                Some((rx_delta as f64 / elapsed, tx_delta as f64 / elapsed))
            });

            NetworkInterfaceTelemetry {
                interface: name.clone(),
                rx_bytes_per_sec: rates.map(|(rx, _)| rx),
                tx_bytes_per_sec: rates.map(|(_, tx)| tx),
                rx_bytes_total: sample.rx_bytes,
                tx_bytes_total: sample.tx_bytes,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_loopback_interface() {
        let ifaces = sample();
        assert!(ifaces.contains_key("lo"), "expected a loopback interface in /proc/net/dev");
    }

    #[test]
    fn first_sample_has_no_rate() {
        let current = sample();
        let now = Instant::now();
        let reports = to_reports(&HashMap::new(), &current, now);
        for r in &reports {
            assert_eq!(r.rx_bytes_per_sec, None, "{}: first-ever sample should have no rate", r.interface);
        }
    }
}
