use crate::state::AppState;
use crate::{manifest, pacman};
use nyx_core::{IntegrityCommand, IntegrityReport, NyxOutput, SecurityState};

const BINARY: &str = "nyx-integrity";

/// Run both checks, update the cached report, and return it. Shared by the
/// `Verify` command and the daemon's own periodic background scan so the two
/// paths can never drift apart.
pub async fn run_verify(state: &AppState, quick: bool) -> IntegrityReport {
    let manifest_outcome = manifest::verify();
    let pacman_outcome = tokio::task::spawn_blocking(move || pacman::check(quick)).await;

    let (manifest_present, manifest_checked, manifest_mismatches) = match manifest_outcome {
        Ok(o) => (o.present, o.checked, o.mismatches),
        Err(e) => (false, 0, vec![format!("manifest check failed: {e}")]),
    };

    let (package_scanned, package_mismatches) = match pacman_outcome {
        Ok(Ok(o)) => (o.scanned, o.mismatches),
        Ok(Err(e)) => (0, vec![format!("pacman check failed: {e}")]),
        Err(e) => (0, vec![format!("pacman check task panicked: {e}")]),
    };

    let has_mismatches = !manifest_mismatches.is_empty() || !package_mismatches.is_empty();

    let (state_value, detail) = if !manifest_present {
        (
            SecurityState::Degraded,
            "no baseline manifest yet — run `nyx-integrity baseline` once, right after a \
             known-good install/update, before this check means anything"
                .to_string(),
        )
    } else if has_mismatches {
        (
            SecurityState::Blocked,
            format!(
                "{} manifest mismatch(es), {} package file mismatch(es) — treat this system as \
                 untrusted until investigated",
                manifest_mismatches.len(),
                package_mismatches.len()
            ),
        )
    } else {
        (
            SecurityState::Protected,
            format!(
                "{manifest_checked} manifest file(s) and {package_scanned} package(s) verified \
                 clean"
            ),
        )
    };

    let report = IntegrityReport {
        manifest_present,
        manifest_checked,
        manifest_mismatches,
        package_scanned,
        package_mismatches,
        state: state_value,
        detail,
    };

    *state.last.lock().await = report.clone();
    report
}

pub async fn dispatch(state: &AppState, cmd: IntegrityCommand) -> NyxOutput<IntegrityReport> {
    match cmd {
        IntegrityCommand::Status => {
            let report = state.last.lock().await.clone();
            let detail = report.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(report))
        }
        IntegrityCommand::Baseline => match manifest::write_baseline() {
            Ok(n) => NyxOutput::ok(BINARY, "baseline", format!("baseline written for {n} file(s)"), None),
            Err(e) => NyxOutput::<IntegrityReport>::err(BINARY, "baseline", e.to_string()),
        },
        IntegrityCommand::Verify { quick } => {
            let report = run_verify(state, quick).await;
            let detail = report.detail.clone();
            NyxOutput::ok(BINARY, "verify", detail, Some(report))
        }
    }
}
