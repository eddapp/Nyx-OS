//! nyx-wipe — anti-forensics cleanup CLI.
//!
//! Deliberately a one-shot privileged CLI, not a resident daemon like
//! nyx-health/nyx-dns/nyx-integrity. Every operation here is destructive and
//! irreversible, and this binary can act across every local account's home
//! directory — leaving a socket listening for that around the clock (even at
//! `wheel`-group trust) is strictly more attack surface for a subsystem that
//! is used rarely and on purpose. Invoke it directly with `sudo`/`pkexec`
//! each time instead.

mod targets;
mod users;

use clap::{Parser, Subcommand, ValueEnum};
use nyx_core::{NyxOutput, WipeReport, WipeTarget};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "nyx-wipe",
    about = "NyxOS anti-forensics cleanup — plans, then (only with --yes) executes, \
             irreversible deletions"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dry run: report what would be removed for each target without touching anything.
    Plan {
        #[arg(value_enum)]
        targets: Vec<TargetArg>,
        /// Plan every category target.
        #[arg(long)]
        all: bool,
        /// One or more specific files to plan wiping — e.g. for a file-manager
        /// "Secure Wipe" action. Repeatable. Directories are refused for now.
        #[arg(long = "path")]
        paths: Vec<PathBuf>,
    },
    /// Actually delete. Refuses to run without --yes.
    Execute {
        #[arg(value_enum)]
        targets: Vec<TargetArg>,
        /// Execute every category target.
        #[arg(long)]
        all: bool,
        /// One or more specific files to wipe. Repeatable.
        #[arg(long = "path")]
        paths: Vec<PathBuf>,
        /// Required — acknowledges this is irreversible.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum TargetArg {
    ShellHistory,
    Tmp,
    Thumbnails,
    RecentFiles,
    Logs,
}

impl From<TargetArg> for WipeTarget {
    fn from(t: TargetArg) -> Self {
        match t {
            TargetArg::ShellHistory => WipeTarget::ShellHistory,
            TargetArg::Tmp => WipeTarget::Tmp,
            TargetArg::Thumbnails => WipeTarget::Thumbnails,
            TargetArg::RecentFiles => WipeTarget::RecentFiles,
            TargetArg::Logs => WipeTarget::Logs,
        }
    }
}

const ALL_TARGETS: &[WipeTarget] = &[
    WipeTarget::ShellHistory,
    WipeTarget::Tmp,
    WipeTarget::Thumbnails,
    WipeTarget::RecentFiles,
    WipeTarget::Logs,
];

fn target_name(t: WipeTarget) -> &'static str {
    match t {
        WipeTarget::ShellHistory => "shell_history",
        WipeTarget::Tmp => "tmp",
        WipeTarget::Thumbnails => "thumbnails",
        WipeTarget::RecentFiles => "recent_files",
        WipeTarget::Logs => "logs",
    }
}

fn resolve_targets(targets: Vec<TargetArg>, all: bool) -> Vec<WipeTarget> {
    if all {
        return ALL_TARGETS.to_vec();
    }
    let mut seen = HashSet::new();
    targets
        .into_iter()
        .map(WipeTarget::from)
        .filter(|t| seen.insert(*t))
        .collect()
}

fn require_something(targets: &[WipeTarget], paths: &[PathBuf]) {
    if targets.is_empty() && paths.is_empty() {
        nyx_core::output::print_error(
            "nyx-wipe",
            "args",
            "nothing to do — pass one or more targets, --all, or --path <file>",
        );
        std::process::exit(1);
    }
}

fn run_plan(targets: Vec<WipeTarget>, paths: Vec<PathBuf>) {
    for target in targets {
        let plan = targets::plan(target);
        let message = if target == WipeTarget::Logs {
            "journal disk usage reported in warnings — exact bytes reclaimed are only known \
             after execute"
                .to_string()
        } else {
            format!(
                "{} file(s), {} byte(s) would be removed",
                plan.files.len(),
                plan.bytes
            )
        };
        let report = WipeReport {
            target: target_name(target).to_string(),
            reversible: false,
            files_affected: plan.files.len(),
            bytes_affected: plan.bytes,
            executed: false,
            warnings: plan.warnings,
        };
        NyxOutput::ok("nyx-wipe", "plan", message, Some(report)).print();
    }

    for outcome in targets::plan_paths(&paths) {
        let report = WipeReport {
            target: format!("path:{}", outcome.path.display()),
            reversible: false,
            files_affected: if outcome.refused.is_some() { 0 } else { 1 },
            bytes_affected: outcome.bytes,
            executed: false,
            warnings: outcome.refused.iter().cloned().collect(),
        };
        let message = match report.warnings.first() {
            Some(reason) => reason.clone(),
            None => format!("{} byte(s) would be removed", outcome.bytes),
        };
        NyxOutput::ok("nyx-wipe", "plan", message, Some(report)).print();
    }
}

fn run_execute(targets: Vec<WipeTarget>, paths: Vec<PathBuf>, yes: bool) {
    if !yes {
        nyx_core::output::print_error(
            "nyx-wipe",
            "execute",
            "refusing to run without --yes — this is irreversible; run `nyx-wipe plan` first to \
             see what would be affected",
        );
        std::process::exit(1);
    }

    for target in targets {
        let plan = targets::plan(target);
        let (removed, freed, mut warnings) = targets::execute(target, &plan);
        warnings.extend(plan.warnings);

        let message = if target == WipeTarget::Logs {
            "journal rotated and vacuumed to the last few seconds".to_string()
        } else {
            format!("removed {removed} file(s), freed {freed} byte(s)")
        };

        let report = WipeReport {
            target: target_name(target).to_string(),
            reversible: false,
            files_affected: removed,
            bytes_affected: freed,
            executed: true,
            warnings,
        };
        NyxOutput::ok("nyx-wipe", "execute", message, Some(report)).print();
    }

    if !paths.is_empty() {
        let planned = targets::plan_paths(&paths);
        for (path, removed, warnings) in targets::execute_paths(&planned) {
            let bytes = planned
                .iter()
                .find(|o| o.path == path)
                .map(|o| o.bytes)
                .unwrap_or(0);
            let report = WipeReport {
                target: format!("path:{}", path.display()),
                reversible: false,
                files_affected: usize::from(removed),
                bytes_affected: if removed { bytes } else { 0 },
                executed: removed,
                warnings,
            };
            let message = if removed {
                format!("removed {} ({} byte(s))", path.display(), bytes)
            } else {
                format!("refused: {}", path.display())
            };
            NyxOutput::ok("nyx-wipe", "execute", message, Some(report)).print();
        }
    }
}

fn main() {
    nyx_core::logging::init();

    if !nix::unistd::Uid::effective().is_root() {
        nyx_core::output::print_error(
            "nyx-wipe",
            "root-check",
            "nyx-wipe must run as root — it reads and deletes other local accounts' files",
        );
        std::process::exit(1);
    }

    let cli = Cli::parse();
    match cli.command {
        Cmd::Plan { targets, all, paths } => {
            let targets = resolve_targets(targets, all);
            require_something(&targets, &paths);
            run_plan(targets, paths);
        }
        Cmd::Execute { targets, all, paths, yes } => {
            let targets = resolve_targets(targets, all);
            require_something(&targets, &paths);
            run_execute(targets, paths, yes);
        }
    }
}
