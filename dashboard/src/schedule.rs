//! Shells out to `nyx-hardening schedule ...` via `pkexec`. Unlike
//! `workflow.rs`'s `nyx-workflow` calls, every one of these — including the
//! read-only `status` — needs root: `nyx-hardening`'s own `main.rs` calls
//! `exit_with_error` unconditionally in `main()` for every subcommand
//! unless `Uid::effective().is_root()`, before it ever looks at which
//! subcommand was requested. So `schedule status` gets exactly the same
//! `pkexec` treatment as `schedule install`/`schedule remove`, not the
//! plain unprivileged subprocess call `diagnostics.rs`/`workflow.rs` use.
//!
//! `nyx-hardening` has no `--json` flag because it doesn't need one: every
//! subcommand prints through `NyxOutput::print()` (see
//! `nyx_core::output::NyxOutput::print`), which always emits one JSON line
//! on stdout unconditionally — there is no plain-text mode to opt out of.
//!
//! The `pkexec env DISPLAY=... XAUTHORITY=...` wrapping is the same shape
//! `ui.rs::spawn_show_config_dir` already uses for its own privileged
//! action, duplicated here rather than shared because that helper spawns
//! detached and never reads output, while every call here needs to block
//! and capture stdout/stderr to parse the JSON result.

use nyx_core::{NyxOutput, Status};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::process::{Command, Stdio};

const BINARY: &str = "nyx-hardening";

#[derive(Deserialize, Clone)]
pub struct TaskStatus {
    pub task: String,
    #[allow(dead_code)]
    pub scope: String,
    pub installed: bool,
    pub enabled: bool,
    pub interval_secs: Option<u64>,
}

/// Runs `pkexec env DISPLAY=... XAUTHORITY=... nyx-hardening <args>` and
/// returns its first non-empty stdout line, or its first stderr line if
/// stdout was empty (a `pkexec` authorization refusal, or the target
/// binary's own root-check failure, can both land on stderr instead of the
/// JSON-on-stdout convention `nyx-hardening` itself always follows once it
/// actually runs).
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

fn run_json<T: DeserializeOwned>(args: &[&str]) -> Result<T, String> {
    let line = call(args)?;
    let parsed: NyxOutput<T> =
        serde_json::from_str(&line).map_err(|e| format!("bad output from {BINARY}: {e}"))?;
    match parsed.status {
        Status::Ok | Status::Warning => {
            parsed.data.ok_or_else(|| "no data in response".to_string())
        }
        Status::Error => Err(parsed.message),
    }
}

/// For `install`/`remove`, which report success/failure as a human-readable
/// `message` rather than structured `data` — the caller only ever shows
/// that message in a status label, never parses it.
fn run_action(args: &[&str]) -> Result<String, String> {
    let line = call(args)?;
    let parsed: NyxOutput<serde_json::Value> =
        serde_json::from_str(&line).map_err(|e| format!("bad output from {BINARY}: {e}"))?;
    match parsed.status {
        Status::Ok | Status::Warning => Ok(parsed.message),
        Status::Error => Err(parsed.message),
    }
}

/// `nyx-hardening schedule status` — the real, on-disk installed/enabled/
/// interval state of every one of `ScheduleTask::ALL`'s 12 tasks.
pub fn status() -> Result<Vec<TaskStatus>, String> {
    run_json(&["schedule", "status"])
}

/// `nyx-hardening schedule install --task <id> --interval-secs <n>
/// [--interface <iface>]`. `interface` is required by `nyx-hardening`
/// itself only for `randomize-mac`; passed as `None` for every other task.
pub fn install(task_id: &str, interval_secs: u64, interface: Option<&str>) -> Result<String, String> {
    let interval = interval_secs.to_string();
    let mut args: Vec<&str> = vec!["schedule", "install", "--task", task_id, "--interval-secs", &interval];
    if let Some(iface) = interface {
        args.push("--interface");
        args.push(iface);
    }
    run_action(&args)
}

/// `nyx-hardening schedule remove --task <id>`.
pub fn remove(task_id: &str) -> Result<String, String> {
    run_action(&["schedule", "remove", "--task", task_id])
}

pub enum ScheduleActionKind {
    Install { interval_secs: u64, interface: Option<String> },
    Remove,
}

pub struct ScheduleAction {
    pub task_id: String,
    pub kind: ScheduleActionKind,
}

/// Runs a batch of install/remove calls sequentially on the background
/// thread the caller already spawned — one `pkexec` prompt per task, same
/// as calling `install`/`remove` one at a time, just chained so the GTK
/// side only waits on a single background job.
pub fn run_actions(actions: Vec<ScheduleAction>) -> Vec<(String, Result<String, String>)> {
    actions
        .into_iter()
        .map(|action| {
            let result = match action.kind {
                ScheduleActionKind::Install { interval_secs, interface } => {
                    install(&action.task_id, interval_secs, interface.as_deref())
                }
                ScheduleActionKind::Remove => remove(&action.task_id),
            };
            (action.task_id, result)
        })
        .collect()
}
