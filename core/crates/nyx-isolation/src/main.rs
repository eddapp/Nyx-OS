//! nyx-isolation — application sandbox launcher.
//!
//! Unprivileged, one-shot CLI (like nyx-wipe): it never runs as root and
//! never elevates. Two identity sources:
//!   - `app:<id>`     — the small, hand-reviewed table in `allowlist.rs`.
//!   - `profile:<name>` — any program that already has a root-owned
//!     Firejail profile at `/etc/firejail/<name>.profile`, resolved against
//!     a fixed safe PATH (never the caller's own `$PATH`).
//!
//! Two runtimes: `native` (exec the validated path directly — offered only
//! so a user/desktop can compare behaviour against the sandboxed run, never
//! the default) and `firejail` (the default). Firejail resolves its own
//! per-program profile from `/etc/firejail/<basename>.profile` by binary
//! name automatically; nyx-isolation's job ends at proving the path it hands
//! to Firejail is the one it claims to be.

mod allowlist;
mod validate;

use clap::{Parser, Subcommand, ValueEnum};
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
}

#[derive(Copy, Clone, ValueEnum)]
enum Runtime {
    /// Never the default — exists so a user can compare against Firejail.
    Native,
    Firejail,
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

fn main() {
    nyx_core::logging::init();

    if nix::unistd::Uid::effective().is_root() {
        nyx_core::output::print_error(
            "nyx-isolation",
            "root-check",
            "refusing to sandbox anything while running as root",
        );
        std::process::exit(1);
    }

    let cli = Cli::parse();
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
    }
}
