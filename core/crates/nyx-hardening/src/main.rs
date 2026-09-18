//! nyx-hardening — root-privileged one-shot CLI for hardening features that
//! don't justify a resident daemon: swap encryption, the cold-boot-defense
//! systemd-sleep hook, and the shutdown-time RAM-wipe unit. Same shape as
//! `nyx-wipe`/`nyx-isolation`: every operation here mutates root-owned
//! system state (crypttab, fstab, systemd units) and is invoked directly
//! with `sudo`, not through a socket.
//!
//! The clipboard auto-clear feature lives in the separate `nyx-clipboard-
//! clear` binary in this same crate (`src/bin/nyx-clipboard-clear.rs`),
//! because it must run as the logged-in desktop user under a
//! `systemd --user` service, never as root.

mod coldboot;
mod ramwipe;
mod swap;

use clap::{Parser, Subcommand};
use nyx_core::NyxOutput;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "nyx-hardening",
    about = "NyxOS hardening CLI — swap encryption, cold-boot defense, shutdown RAM wipe"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report current swap devices and whether the cold-boot and
    /// RAM-wipe hooks are installed.
    Status,
    /// Swap-device discovery and encryption.
    Swap {
        #[command(subcommand)]
        command: SwapCmd,
    },
    /// Install the systemd-sleep hook that evicts non-root LUKS keys from
    /// kernel memory before every suspend/hibernate.
    InstallColdbootHook,
    /// Remove it.
    RemoveColdbootHook,
    /// Install the systemd unit that overwrites free RAM with `sdmem -f`
    /// immediately before poweroff.
    InstallRamWipeHook,
    /// Remove it.
    RemoveRamWipeHook,
}

#[derive(Subcommand)]
enum SwapCmd {
    /// List current swap devices and whether each is already encrypted.
    Status,
    /// Convert a real (non-zram) plaintext swap partition to LUKS
    /// random-per-boot-key encrypted swap. Plans by default; pass --yes
    /// to actually swapoff/edit crypttab+fstab/swapon.
    Encrypt {
        device: PathBuf,
        /// Required to actually execute — without it, only the plan
        /// (exact commands and file edits) is printed.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Serialize)]
struct StatusReport {
    swap: Vec<swap::SwapEntry>,
    coldboot_hook_installed: bool,
    ram_wipe_hook_installed: bool,
}

fn exit_with_error(command: &str, message: &str) -> ! {
    nyx_core::output::print_error("nyx-hardening", command, message);
    std::process::exit(1);
}

fn main() {
    nyx_core::logging::init();

    if !nix::unistd::Uid::effective().is_root() {
        exit_with_error(
            "root-check",
            "nyx-hardening must run as root — every subcommand mutates root-owned system state \
             (crypttab, fstab, systemd units)",
        );
    }

    let cli = Cli::parse();
    match cli.command {
        Cmd::Status => run_status(),
        Cmd::Swap { command } => run_swap(command),
        Cmd::InstallColdbootHook => match coldboot::install() {
            Ok(()) => {
                NyxOutput::<()>::ok(
                    "nyx-hardening",
                    "install-coldboot-hook",
                    format!("installed {}", coldboot::HOOK_PATH),
                    None,
                )
                .print();
            }
            Err(e) => exit_with_error("install-coldboot-hook", &e.to_string()),
        },
        Cmd::RemoveColdbootHook => match coldboot::remove() {
            Ok(removed) => {
                let message = if removed {
                    format!("removed {}", coldboot::HOOK_PATH)
                } else {
                    "hook was not installed — nothing to remove".to_string()
                };
                NyxOutput::ok("nyx-hardening", "remove-coldboot-hook", message, Some(removed)).print();
            }
            Err(e) => exit_with_error("remove-coldboot-hook", &e.to_string()),
        },
        Cmd::InstallRamWipeHook => match ramwipe::install() {
            Ok(()) => {
                NyxOutput::<()>::ok(
                    "nyx-hardening",
                    "install-ram-wipe-hook",
                    format!("installed and enabled {}", ramwipe::UNIT_PATH),
                    None,
                )
                .print();
            }
            Err(e) => exit_with_error("install-ram-wipe-hook", &e.to_string()),
        },
        Cmd::RemoveRamWipeHook => match ramwipe::remove() {
            Ok(removed) => {
                let message = if removed {
                    format!("disabled and removed {}", ramwipe::UNIT_PATH)
                } else {
                    "unit was not installed — nothing to remove".to_string()
                };
                NyxOutput::ok("nyx-hardening", "remove-ram-wipe-hook", message, Some(removed)).print();
            }
            Err(e) => exit_with_error("remove-ram-wipe-hook", &e.to_string()),
        },
    }
}

fn run_status() {
    let swap_entries = match swap::discover() {
        Ok(s) => s,
        Err(e) => exit_with_error("status", &e.to_string()),
    };
    let report = StatusReport {
        swap: swap_entries,
        coldboot_hook_installed: coldboot::is_installed(),
        ram_wipe_hook_installed: ramwipe::is_installed(),
    };
    let message = format!(
        "{} swap device(s); cold-boot hook {}; RAM-wipe hook {}",
        report.swap.len(),
        if report.coldboot_hook_installed { "installed" } else { "not installed" },
        if report.ram_wipe_hook_installed { "installed" } else { "not installed" },
    );
    NyxOutput::ok("nyx-hardening", "status", message, Some(report)).print();
}

fn run_swap(command: SwapCmd) {
    match command {
        SwapCmd::Status => match swap::discover() {
            Ok(entries) => {
                let message = format!("{} swap device(s)", entries.len());
                NyxOutput::ok("nyx-hardening", "swap status", message, Some(entries)).print();
            }
            Err(e) => exit_with_error("swap status", &e.to_string()),
        },
        SwapCmd::Encrypt { device, yes } => {
            let plan = match swap::plan_encrypt(&device) {
                Ok(p) => p,
                Err(e) => exit_with_error("swap encrypt", &e.to_string()),
            };

            if !yes {
                let message = format!(
                    "plan only (pass --yes to execute): swapoff {}; comment out its fstab line; \
                     append fstab line '{}'; append crypttab line '{}'; systemctl daemon-reload; \
                     systemctl start systemd-cryptsetup@<escaped {}>.service; swapon \
                     /dev/mapper/{}",
                    device.display(),
                    plan.fstab_line,
                    plan.crypttab_line,
                    plan.mapper_name,
                    plan.mapper_name
                );
                NyxOutput::ok("nyx-hardening", "swap encrypt", message, Some(plan)).print();
                return;
            }

            match swap::execute_encrypt(&plan) {
                Ok(steps) => {
                    let message = format!("encrypted swap on {} — {} step(s) applied", device.display(), steps.len());
                    NyxOutput::ok("nyx-hardening", "swap encrypt", message, Some(steps)).print();
                }
                Err(e) => exit_with_error("swap encrypt", &e.to_string()),
            }
        }
    }
}
