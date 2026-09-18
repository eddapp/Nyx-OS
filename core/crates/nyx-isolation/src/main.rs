//! nyx-isolation — application sandbox launcher.
//!
//! Unprivileged, one-shot CLI (like nyx-wipe): it never runs as root and
//! never elevates — with exactly one narrow, documented exception (see
//! `Cmd::Container(ContainerCmd::BuildImage)` below). Two identity sources
//! for the Firejail/native runtimes:
//!   - `app:<id>`     — the small, hand-reviewed table in `allowlist.rs`.
//!   - `profile:<name>` — any program that already has a root-owned
//!     Firejail profile at `/etc/firejail/<name>.profile`, resolved against
//!     a fixed safe PATH (never the caller's own `$PATH`).
//!
//! Three runtimes: `native` (exec the validated path directly — offered
//! only so a user/desktop can compare behaviour against the sandboxed run,
//! never the default), `firejail` (the default — resolves its own
//! per-program profile from `/etc/firejail/<basename>.profile` by binary
//! name automatically; nyx-isolation's job ends at proving the path it
//! hands to Firejail is the one it claims to be), and Podman-based
//! container isolation (see `containers.rs` and the `container` subcommand
//! tree) — a single pinned "workbench" image, never a general container
//! manager.

mod allowlist;
mod containers;
mod validate;

use clap::{Parser, Subcommand, ValueEnum};
use nyx_core::NyxOutput;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "nyx-isolation", about = "NyxOS application sandbox launcher")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the curated app allowlist.
    List,
    /// Launch a program under the chosen isolation runtime.
    Launch {
        /// "app:<id>", "<id>" (same as app:<id>), or "profile:<name>".
        identity: String,
        #[arg(long, value_enum, default_value = "firejail")]
        runtime: Runtime,
        /// Extra arguments passed through to the launched program.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Podman-based container isolation — a single pinned "workbench"
    /// image, never a general container manager.
    Container {
        #[command(subcommand)]
        command: ContainerCmd,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Runtime {
    /// Never the default — exists so a user can compare against Firejail.
    Native,
    Firejail,
}

#[derive(Subcommand)]
enum ContainerCmd {
    /// Build (or rebuild) the workbench image and pin its digest into
    /// `/etc/nyx/workbench-image.json`. The one nyx-isolation operation
    /// that must run as root — it writes that root-owned metadata file,
    /// which every other container command below verifies against before
    /// launching anything. Equivalent to running
    /// `containers/build-workbench.sh` directly.
    BuildImage {
        /// Directory containing `workbench.Containerfile` and
        /// `entrypoint.sh` — e.g. `core/crates/nyx-isolation/containers`
        /// from a source checkout.
        #[arg(long)]
        context: PathBuf,
    },
    /// Launch a brand-new, disposable sandbox shell. `--rm` from the
    /// moment it is created — stopping it destroys it, by design.
    DisposableShell {
        /// Give the shell a network namespace (Podman's `pasta` rootless
        /// backend). Default is no network at all.
        #[arg(long)]
        network: bool,
    },
    /// Attach an interactive shell to the single persistent workbench,
    /// creating and/or starting it first if needed.
    PersistentWorkbench,
    /// List every container nyx-isolation manages
    /// (`io.nyxos.managed=true`), its profile, and its current state.
    Status,
    /// Start every stopped persistent-profile managed container.
    StartAll,
    /// Stop every running persistent-profile managed container. Never
    /// touches disposable containers — stopping one destroys it.
    StopAll,
    /// Remove the persistent workbench container entirely, destroying
    /// everything inside it. Irreversible — refuses to run without `--yes`.
    ResetWorkbench {
        /// Required — acknowledges this is irreversible.
        #[arg(long)]
        yes: bool,
    },
}

fn resolve_identity(identity: &str) -> Result<PathBuf, String> {
    if let Some(name) = identity.strip_prefix("profile:") {
        validate::require_firejail_profile(name)?;
        validate::resolve_in_safe_path(name)
    } else {
        let id = identity.strip_prefix("app:").unwrap_or(identity);
        let spec = allowlist::find(id)
            .ok_or_else(|| format!("'{id}' is not in the curated app allowlist — try profile:<name>"))?;
        validate::validate_ownership_chain(std::path::Path::new(spec.executable))
    }
}

fn exit_with_error(command: &str, message: &str) -> ! {
    nyx_core::output::print_error("nyx-isolation", command, message);
    std::process::exit(1);
}

fn main() {
    nyx_core::logging::init();

    let cli = Cli::parse();
    let is_root = nix::unistd::Uid::effective().is_root();
    // `container build-image` is the one deliberate exception to
    // nyx-isolation's otherwise-universal "never root" rule: it provisions
    // the root-owned digest metadata every other container command trusts,
    // exactly like nyx-wipe requiring root for its own destructive
    // operations. Every other subcommand — including every other container
    // command — still hard-refuses root, so none of the actual
    // sandbox-launching code ever runs elevated.
    let requires_root = matches!(
        cli.command,
        Cmd::Container { command: ContainerCmd::BuildImage { .. } }
    );

    if is_root && !requires_root {
        exit_with_error("root-check", "refusing to sandbox anything while running as root");
    }
    if requires_root && !is_root {
        exit_with_error(
            "root-check",
            "building the workbench image requires root (it writes the root-owned digest \
             metadata file) — run via sudo",
        );
    }

    match cli.command {
        Cmd::List => {
            for spec in allowlist::APP_SPECS {
                println!("{}\t{}", spec.id, spec.executable);
            }
        }
        Cmd::Launch { identity, runtime, args } => {
            let resolved = match resolve_identity(&identity) {
                Ok(p) => p,
                Err(e) => {
                    nyx_core::output::print_error("nyx-isolation", "launch", &e);
                    std::process::exit(1);
                }
            };

            let mut cmd = match runtime {
                Runtime::Native => Command::new(&resolved),
                Runtime::Firejail => {
                    let mut c = Command::new("/usr/bin/firejail");
                    c.arg("--quiet").arg(&resolved);
                    c
                }
            };
            cmd.args(&args);

            // Replace this process rather than spawn+wait, so the sandboxed
            // program becomes the direct child of whatever invoked
            // nyx-isolation (desktop launcher, terminal, Thunar action)
            // instead of leaving a wrapper process sitting around.
            let err = cmd.exec();
            nyx_core::output::print_error(
                "nyx-isolation",
                "launch",
                &format!("exec failed: {err}"),
            );
            std::process::exit(1);
        }
        Cmd::Container { command } => handle_container(command),
    }
}

/// Exec the given already-built `podman` command, replacing this process —
/// the same convention `Cmd::Launch` uses above, so the interactive
/// container becomes the direct child of whatever invoked nyx-isolation.
fn exec_podman(command: &str, mut cmd: Command) -> ! {
    let err = cmd.exec();
    exit_with_error(command, &format!("exec failed: {err}"));
}

fn handle_container(command: ContainerCmd) {
    match command {
        ContainerCmd::BuildImage { context } => match containers::build_image(&context) {
            Ok(digest) => {
                NyxOutput::ok(
                    "nyx-isolation",
                    "container build-image",
                    format!("built {} and pinned digest {digest}", containers::WORKBENCH_IMAGE),
                    Some(digest),
                )
                .print();
            }
            Err(e) => exit_with_error("container build-image", &e),
        },
        ContainerCmd::DisposableShell { network } => {
            let network = if network { containers::Network::Pasta } else { containers::Network::None };
            match containers::launch_disposable(network) {
                Ok(cmd) => exec_podman("container disposable-shell", cmd),
                Err(e) => exit_with_error("container disposable-shell", &e),
            }
        }
        ContainerCmd::PersistentWorkbench => match containers::launch_persistent() {
            Ok(cmd) => exec_podman("container persistent-workbench", cmd),
            Err(e) => exit_with_error("container persistent-workbench", &e),
        },
        ContainerCmd::Status => match containers::status() {
            Ok(statuses) => {
                let message = format!("{} managed container(s)", statuses.len());
                NyxOutput::ok("nyx-isolation", "container status", message, Some(statuses)).print();
            }
            Err(e) => exit_with_error("container status", &e),
        },
        ContainerCmd::StartAll => match containers::start_all() {
            Ok(names) => {
                let message = format!("started {} container(s)", names.len());
                NyxOutput::ok("nyx-isolation", "container start-all", message, Some(names)).print();
            }
            Err(e) => exit_with_error("container start-all", &e),
        },
        ContainerCmd::StopAll => match containers::stop_all() {
            Ok(names) => {
                let message = format!("stopped {} container(s)", names.len());
                NyxOutput::ok("nyx-isolation", "container stop-all", message, Some(names)).print();
            }
            Err(e) => exit_with_error("container stop-all", &e),
        },
        ContainerCmd::ResetWorkbench { yes } => match containers::reset_workbench(yes) {
            Ok(removed) => {
                let message = if removed {
                    "persistent workbench removed".to_string()
                } else {
                    "no persistent workbench existed — nothing to remove".to_string()
                };
                NyxOutput::ok("nyx-isolation", "container reset-workbench", message, Some(removed))
                    .print();
            }
            Err(e) => exit_with_error("container reset-workbench", &e),
        },
    }
}
