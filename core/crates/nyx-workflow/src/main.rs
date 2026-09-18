//! nyx-workflow — a small, typed workflow engine for multi-step Nyx
//! security operations. Unprivileged CLI: every step calls into an
//! already-privileged daemon over its own socket (same trust boundary the
//! dashboard uses), so this binary itself never needs root.

mod catalog;
mod client;
mod executor;
mod model;
mod posture;

use clap::{Parser, Subcommand, ValueEnum};
use nyx_core::VpnProtocol;

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
        /// Required by `connect-vpn-with-verification`.
        #[arg(long, value_enum)]
        protocol: Option<ProtocolArg>,
        /// Required by `connect-vpn-with-verification`.
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ProtocolArg {
    Wireguard,
    Openvpn,
}

impl From<ProtocolArg> for VpnProtocol {
    fn from(p: ProtocolArg) -> Self {
        match p {
            ProtocolArg::Wireguard => VpnProtocol::WireGuard,
            ProtocolArg::Openvpn => VpnProtocol::OpenVpn,
        }
    }
}

fn run_and_report(workflow: model::Workflow) {
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

fn main() {
    nyx_core::logging::init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::List => {
            for workflow in catalog::catalog() {
                println!("{}\t{}", workflow.id, workflow.description);
            }
            println!(
                "{}\t{}",
                catalog::PARAMETRIZED_WORKFLOW_ID,
                catalog::PARAMETRIZED_WORKFLOW_DESCRIPTION
            );
            for p in posture::Posture::all() {
                println!("{}\t{}", p.id(), p.description());
            }
        }
        Cmd::Run { id, protocol, profile } => {
            if id == catalog::PARAMETRIZED_WORKFLOW_ID {
                let (Some(protocol), Some(profile)) = (protocol, profile) else {
                    nyx_core::output::print_error(
                        "nyx-workflow",
                        "run",
                        &format!("{} requires --protocol and --profile", catalog::PARAMETRIZED_WORKFLOW_ID),
                    );
                    std::process::exit(1);
                };
                run_and_report(catalog::connect_vpn_with_verification(protocol.into(), profile));
                return;
            }

            if let Some(p) = posture::Posture::parse(&id) {
                run_and_report(posture::build(p));
                return;
            }

            let Some(workflow) = catalog::find(&id) else {
                nyx_core::output::print_error(
                    "nyx-workflow",
                    "run",
                    &format!("no such workflow: {id} — see `nyx-workflow list`"),
                );
                std::process::exit(1);
            };
            run_and_report(workflow);
        }
    }
}
