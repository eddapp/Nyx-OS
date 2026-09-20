//! Shells out to `nyx-wipe luks-nuke` via `pkexec`. `nyx-wipe` is a
//! one-shot root CLI with no socket (see its `main.rs` for why), and it is
//! deliberately NOT in `90-nyx-dashboard.rules`' passwordless list — a
//! duress action that permanently destroys a LUKS container should cost a
//! real password prompt, unlike the low-risk schedule/open-directory calls
//! that rule covers. Same `pkexec env DISPLAY=... XAUTHORITY=...` shape
//! `schedule.rs::call` uses, duplicated for the same reason given there.

use nyx_core::{NyxOutput, Status, WipeReport};
use std::process::{Command, Stdio};

const BINARY: &str = "nyx-wipe";

pub struct NukeResult {
    pub message: String,
    pub warnings: Vec<String>,
    /// `WipeReport::executed` — true only if the re-read after erase showed
    /// zero keyslots left.
    pub complete: bool,
}

fn call(args: &[&str]) -> Result<String, String> {
    let display = std::env::var("DISPLAY").unwrap_or_default();
    let xauthority = std::env::var("XAUTHORITY")
        .unwrap_or_else(|_| format!("{}/.Xauthority", std::env::var("HOME").unwrap_or_default()));

    let output = Command::new("pkexec")
        .arg("env")
        .arg(format!("DISPLAY={display}"))
        .arg(format!("XAUTHORITY={xauthority}"))
        .arg(BINARY)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run pkexec {BINARY}: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout
        .lines()
        .next()
        .filter(|l| !l.trim().is_empty())
        .or_else(|| stderr.lines().next())
        .map(|l| l.to_string())
        .ok_or_else(|| format!("{BINARY} produced no output"))
}

/// `pkexec nyx-wipe luks-nuke --device <dev> --yes [--include-root-device]`.
pub fn luks_nuke(device: &str, include_root: bool) -> Result<NukeResult, String> {
    let mut args = vec!["luks-nuke", "--device", device, "--yes"];
    if include_root {
        args.push("--include-root-device");
    }
    let line = call(&args)?;
    let parsed: NyxOutput<WipeReport> =
        serde_json::from_str(&line).map_err(|e| format!("bad output from {BINARY}: {e}"))?;
    match parsed.status {
        Status::Ok | Status::Warning => {
            let report = parsed.data.ok_or_else(|| "no data in response".to_string())?;
            Ok(NukeResult {
                message: parsed.message,
                warnings: report.warnings,
                complete: report.executed,
            })
        }
        Status::Error => Err(parsed.message),
    }
}
