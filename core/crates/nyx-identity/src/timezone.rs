//! Timezone control via `timedatectl` — the real systemd API, backed by
//! whatever zoneinfo is actually installed rather than a hardcoded list
//! that could drift out of sync with what the system will actually accept.

use nyx_core::{NyxError, NyxResult};
use rand::seq::SliceRandom;
use std::process::Command;

pub fn current() -> Option<String> {
    let output = Command::new("timedatectl")
        .args(["show", "--property=Timezone", "--value"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn available_zones() -> Vec<String> {
    let output = Command::new("timedatectl").arg("list-timezones").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Picks a random zone from `available_zones()`, avoiding the current one
/// when there's more than one candidate.
pub fn generate_random(current: Option<&str>) -> NyxResult<String> {
    let zones = available_zones();
    if zones.is_empty() {
        return Err(NyxError::Config("no timezones reported by timedatectl".to_string()));
    }

    let others: Vec<&String> = zones.iter().filter(|z| Some(z.as_str()) != current).collect();
    let pool: Vec<&String> = if others.is_empty() { zones.iter().collect() } else { others };

    let mut rng = rand::thread_rng();
    pool.choose(&mut rng)
        .map(|s| (*s).clone())
        .ok_or_else(|| NyxError::Config("no timezone candidates".to_string()))
}

pub fn set(zone: &str) -> NyxResult<()> {
    let status = Command::new("timedatectl")
        .args(["set-timezone", zone])
        .status()
        .map_err(|e| NyxError::Config(format!("failed to spawn timedatectl: {e}")))?;
    if !status.success() {
        return Err(NyxError::Config(format!("timedatectl set-timezone exited with {status}")));
    }
    Ok(())
}
