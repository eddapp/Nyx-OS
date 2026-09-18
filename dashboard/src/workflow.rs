//! Shells out to the already-built `nyx-workflow` binary for the Hardening
//! tab. Same subprocess-plus-parse-JSON convention `diagnostics.rs` uses for
//! `nyx-diagnostics` (see its module doc for why): `nyx-workflow`, like
//! `nyx-diagnostics`, is a binary crate with no library target reachable
//! from here, so a subprocess call is the only way to reuse it.

use nyx_core::{NyxOutput, Status};
use serde::Deserialize;
use std::process::{Command, Stdio};

const BINARY: &str = "nyx-workflow";

#[derive(Deserialize, Clone)]
pub struct WorkflowListEntry {
    pub id: String,
    pub description: String,
}

#[derive(Deserialize, Clone)]
pub struct StepResult {
    pub description: String,
    pub ran: bool,
    pub ok: bool,
    pub message: String,
}

#[derive(Deserialize, Clone)]
pub struct WorkflowReport {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub description: String,
    pub results: Vec<StepResult>,
}

/// Same stdout-then-stderr first-line parse `diagnostics.rs::run_json` uses
/// — a failed check can land its `NyxOutput` on stdout (Status::Error, no
/// data) just as easily as on stderr, so both are checked.
fn run_json<T: for<'de> Deserialize<'de>>(args: &[&str]) -> Result<T, String> {
    let output = Command::new(BINARY)
        .args(args)
        // `nyx-workflow`'s Paranoid posture has one interactive confirm step
        // before Arming the kill switch (see posture.rs). This dashboard
        // call has no terminal for the operator to answer through, so
        // stdin is explicitly nulled rather than left inherited: the
        // confirm step reads EOF, is declined, and shows up as a normal
        // "declined by operator" result the operator can see and re-run
        // interactively from a terminal if they actually want Paranoid's
        // kill-switch step applied.
        .stdin(Stdio::null())
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

/// The three posture ids/descriptions, straight from `nyx-workflow list
/// --json` rather than duplicating `Posture::description()`'s text here —
/// `nyx-workflow` isn't a library this crate can call into directly (see
/// module doc), so this is the one place that text is fetched from, not
/// hand-copied.
pub fn fetch_postures() -> Result<Vec<WorkflowListEntry>, String> {
    let entries: Vec<WorkflowListEntry> = run_json(&["list", "--json"])?;
    Ok(entries.into_iter().filter(|e| e.id.starts_with("posture-")).collect())
}

/// Runs `nyx-workflow posture --level <level> --apply --json` and returns
/// its per-step results — the same report shape `nyx-workflow run` prints,
/// per `main.rs`'s `run_and_report`.
pub fn apply_posture(level: &str) -> Result<WorkflowReport, String> {
    run_json(&["posture", "--level", level, "--apply", "--json"])
}
