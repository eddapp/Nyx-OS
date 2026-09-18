//! nyx-workflow — a small, typed workflow engine for multi-step Nyx
//! security operations. Unprivileged CLI: every step calls into an
//! already-privileged daemon over its own socket (same trust boundary the
//! dashboard uses), so this binary itself never needs root.

mod catalog;
mod client;
mod executor;
mod model;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nyx-workflow", about = "NyxOS multi-step security workflow runner")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List available workflows.
    List,
    /// Run a workflow by id.
    Run {
        id: String,
    },
}

fn main() {
    nyx_core::logging::init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::List => {
            for workflow in catalog::catalog() {
                println!("{}\t{}", workflow.id, workflow.description);
            }
        }
        Cmd::Run { id } => {
            let Some(workflow) = catalog::find(&id) else {
                nyx_core::output::print_error(
                    "nyx-workflow",
                    "run",
                    &format!("no such workflow: {id} — see `nyx-workflow list`"),
                );
                std::process::exit(1);
            };

            println!("=== {} ===\n{}\n", workflow.id, workflow.description);
            let report = executor::run(&workflow);

            let failed = report.results.iter().filter(|r| r.ran && !r.ok).count();
            println!("\n--- {} ---", report.id);
            for result in &report.results {
                let mark = if !result.ran {
                    "skip"
                } else if result.ok {
                    " ok "
                } else {
                    "FAIL"
                };
                println!("[{mark}] {} — {}", result.description, result.message);
            }

            if failed > 0 {
                std::process::exit(1);
            }
        }
    }
}
