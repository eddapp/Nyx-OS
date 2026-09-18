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
use nyx_core::{NyxOutput, VpnProtocol};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "nyx-workflow", about = "NyxOS multi-step security workflow runner")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
    /// Print one line of structured `NyxOutput` JSON to stdout instead of
    /// human-readable text — the same convention every other Nyx CLI uses
    /// (see nyx-diagnostics). All live step narration still goes to stderr
    /// in either mode (see executor.rs), so stdout carries exactly that one
    /// line when this is set.
    #[arg(long, global = true)]
    json: bool,
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
    /// Build one of the three named security postures (Standard/Medium/
    /// Paranoid — see `posture.rs`) and either print its plan (the
    /// default) or actually run it with `--apply`.
    Posture {
        #[arg(long, value_enum)]
        level: PostureArg,
        /// Actually execute the posture's steps. Without this, only the
        /// plan is printed — nothing is touched.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ProtocolArg {
    Wireguard,
    Openvpn,
    /// Only meaningful for `vpn-over-tor` — see `catalog.rs`.
    Xray,
    /// Only meaningful for `vpn-over-tor` — see `catalog.rs`.
    Shadowsocks,
}

impl From<ProtocolArg> for VpnProtocol {
    fn from(p: ProtocolArg) -> Self {
        match p {
            ProtocolArg::Wireguard => VpnProtocol::WireGuard,
            ProtocolArg::Openvpn => VpnProtocol::OpenVpn,
            ProtocolArg::Xray => VpnProtocol::Xray,
            ProtocolArg::Shadowsocks => VpnProtocol::Shadowsocks,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum PostureArg {
    Standard,
    Medium,
    Paranoid,
}

impl From<PostureArg> for posture::Posture {
    fn from(p: PostureArg) -> Self {
        match p {
            PostureArg::Standard => posture::Posture::Standard,
            PostureArg::Medium => posture::Posture::Medium,
            PostureArg::Paranoid => posture::Posture::Paranoid,
        }
    }
}

#[derive(Serialize)]
struct WorkflowListEntry {
    id: String,
    description: String,
}

/// Every id `Cmd::Run` accepts, in the same order `Cmd::List` has always
/// printed them: the plain catalog, the three protocol/profile-parametrized
/// workflows, then the three named postures.
fn workflow_list_entries() -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> =
        catalog::catalog().into_iter().map(|w| (w.id.to_string(), w.description.to_string())).collect();
    entries.push((catalog::PARAMETRIZED_WORKFLOW_ID.to_string(), catalog::PARAMETRIZED_WORKFLOW_DESCRIPTION.to_string()));
    entries.push((catalog::TOR_OVER_VPN_WORKFLOW_ID.to_string(), catalog::TOR_OVER_VPN_WORKFLOW_DESCRIPTION.to_string()));
    entries.push((catalog::VPN_OVER_TOR_WORKFLOW_ID.to_string(), catalog::VPN_OVER_TOR_WORKFLOW_DESCRIPTION.to_string()));
    for p in posture::Posture::all() {
        entries.push((p.id().to_string(), p.description().to_string()));
    }
    entries
}

#[derive(Serialize)]
struct StepPlan {
    description: String,
    danger: String,
    confirm: bool,
}

#[derive(Serialize)]
struct PosturePlan {
    id: String,
    description: String,
    steps: Vec<StepPlan>,
}

fn run_and_report(workflow: model::Workflow, json: bool) {
    if !json {
        println!("=== {} ===\n{}\n", workflow.id, workflow.description);
    }

    let report = executor::run(&workflow);
    let failed = report.results.iter().filter(|r| r.ran && !r.ok).count();

    if json {
        let message = if failed > 0 {
            format!("workflow {} completed with {failed} failed step(s)", report.id)
        } else {
            format!("workflow {} completed", report.id)
        };
        let out = if failed > 0 {
            NyxOutput::warn("nyx-workflow", "run", message, Some(report))
        } else {
            NyxOutput::ok("nyx-workflow", "run", message, Some(report))
        };
        out.print();
    } else {
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
            if cli.json {
                let data: Vec<WorkflowListEntry> = workflow_list_entries()
                    .into_iter()
                    .map(|(id, description)| WorkflowListEntry { id, description })
                    .collect();
                let message = format!("{} workflow(s)", data.len());
                NyxOutput::ok("nyx-workflow", "list", message, Some(data)).print();
            } else {
                for (id, description) in workflow_list_entries() {
                    println!("{id}\t{description}");
                }
            }
        }
        Cmd::Run { id, protocol, profile } => {
            let workflow = if id == catalog::PARAMETRIZED_WORKFLOW_ID
                || id == catalog::TOR_OVER_VPN_WORKFLOW_ID
                || id == catalog::VPN_OVER_TOR_WORKFLOW_ID
            {
                let (Some(protocol), Some(profile)) = (protocol, profile) else {
                    nyx_core::output::print_error(
                        "nyx-workflow",
                        "run",
                        &format!("{id} requires --protocol and --profile"),
                    );
                    std::process::exit(1);
                };
                if id == catalog::PARAMETRIZED_WORKFLOW_ID {
                    catalog::connect_vpn_with_verification(protocol.into(), profile)
                } else if id == catalog::TOR_OVER_VPN_WORKFLOW_ID {
                    catalog::tor_over_vpn(protocol.into(), profile)
                } else {
                    catalog::vpn_over_tor(protocol.into(), profile)
                }
            } else if let Some(p) = posture::Posture::parse(&id) {
                posture::build(p)
            } else if let Some(workflow) = catalog::find(&id) {
                workflow
            } else {
                nyx_core::output::print_error(
                    "nyx-workflow",
                    "run",
                    &format!("no such workflow: {id} — see `nyx-workflow list`"),
                );
                std::process::exit(1);
            };
            run_and_report(workflow, cli.json);
        }
        Cmd::Posture { level, apply } => {
            let posture: posture::Posture = level.into();
            let workflow = posture::build(posture);

            if !apply {
                let steps: Vec<StepPlan> = workflow
                    .steps
                    .iter()
                    .map(|s| StepPlan {
                        description: s.description.to_string(),
                        danger: format!("{:?}", s.danger),
                        confirm: s.confirm,
                    })
                    .collect();

                if cli.json {
                    let data = PosturePlan {
                        id: workflow.id.to_string(),
                        description: workflow.description.to_string(),
                        steps,
                    };
                    let message = format!("dry run of {} — pass --apply to execute", workflow.id);
                    NyxOutput::ok("nyx-workflow", "posture", message, Some(data)).print();
                } else {
                    println!(
                        "=== {} (DRY RUN — pass --apply to execute) ===\n{}\n",
                        workflow.id, workflow.description
                    );
                    println!("Planned steps:");
                    for step in &steps {
                        let note = if step.confirm { " [asks for confirmation]" } else { "" };
                        println!("  [{}] {}{}", step.danger, step.description, note);
                    }
                }
                return;
            }

            run_and_report(workflow, cli.json);
        }
    }
}
