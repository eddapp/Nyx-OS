//! Uptime and process count — both plain `/proc` reads.

use std::fs;

pub fn uptime_secs() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

/// Every numeric entry under `/proc` is a live process — the same
/// convention `ps`/`top` rely on.
pub fn process_count() -> usize {
    let Ok(entries) = fs::read_dir("/proc") else { return 0 };
    entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_is_positive() {
        assert!(uptime_secs() > 0);
    }

    #[test]
    fn sees_running_processes() {
        // At minimum, this test process itself is /proc/<pid>.
        assert!(process_count() > 0);
    }
}
