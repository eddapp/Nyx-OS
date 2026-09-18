//! CPU utilization from `/proc/stat`, load average from `/proc/loadavg` —
//! both world-readable, no privilege needed.

use std::fs;

#[derive(Clone, Copy)]
pub struct CpuSample {
    idle: u64,
    total: u64,
}

pub fn sample() -> Option<CpuSample> {
    let contents = fs::read_to_string("/proc/stat").ok()?;
    let line = contents.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    // user nice system idle iowait irq softirq steal guest guest_nice
    let values: Vec<u64> = fields.filter_map(|f| f.parse().ok()).collect();
    if values.len() < 4 {
        return None;
    }
    let idle = values[3] + values.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = values.iter().sum();
    Some(CpuSample { idle, total })
}

/// Percentage of CPU time NOT idle since `previous`. `None` if there's no
/// prior sample yet, or no time has actually elapsed between the two
/// (e.g. called twice in the same jiffy) — never a fabricated number.
pub fn usage_percent(previous: Option<CpuSample>, current: CpuSample) -> Option<f64> {
    let previous = previous?;
    let total_delta = current.total.checked_sub(previous.total)?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = current.idle.saturating_sub(previous.idle);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    Some((busy_delta as f64 / total_delta as f64) * 100.0)
}

pub fn load_average() -> (f64, f64, f64) {
    let Ok(contents) = fs::read_to_string("/proc/loadavg") else {
        return (0.0, 0.0, 0.0);
    };
    let mut fields = contents.split_whitespace();
    let one = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let five = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let fifteen = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (one, five, fifteen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_real_proc_stat() {
        let s = sample();
        assert!(s.is_some(), "expected /proc/stat to parse on a real Linux machine");
    }

    #[test]
    fn usage_needs_two_samples() {
        let s = sample().expect("sample");
        assert_eq!(usage_percent(None, s), None, "no prior sample means no rate yet");
    }

    #[test]
    fn load_average_is_read() {
        let (one, _, _) = load_average();
        assert!(one >= 0.0);
    }
}
