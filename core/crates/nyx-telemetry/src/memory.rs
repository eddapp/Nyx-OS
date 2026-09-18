//! RAM/swap usage from `/proc/meminfo`.

use nyx_core::MemoryTelemetry;
use std::collections::HashMap;
use std::fs;

pub fn sample() -> MemoryTelemetry {
    let Ok(contents) = fs::read_to_string("/proc/meminfo") else {
        return MemoryTelemetry::default();
    };

    let mut values: HashMap<&str, u64> = HashMap::new();
    for line in contents.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        if let Some(value) = rest.split_whitespace().next().and_then(|v| v.parse::<u64>().ok()) {
            values.insert(key, value);
        }
    }

    let total = values.get("MemTotal").copied().unwrap_or(0);
    let available = values.get("MemAvailable").copied().unwrap_or(0);
    let swap_total = values.get("SwapTotal").copied().unwrap_or(0);
    let swap_free = values.get("SwapFree").copied().unwrap_or(0);

    MemoryTelemetry {
        total_kb: total,
        available_kb: available,
        used_kb: total.saturating_sub(available),
        swap_total_kb: swap_total,
        swap_used_kb: swap_total.saturating_sub(swap_free),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_real_meminfo() {
        let mem = sample();
        assert!(mem.total_kb > 0, "MemTotal should be nonzero on a real machine");
        assert!(mem.available_kb <= mem.total_kb);
        assert!(mem.used_kb <= mem.total_kb);
    }
}
