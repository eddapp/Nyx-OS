use crate::state::AppState;
use crate::{firewall, systemd_ctl};
use nyx_core::{HealthCommand, HealthState, KillSwitchLevel, NyxOutput, Toggle};
use zbus::Connection;

const BINARY: &str = "nyx-health";
const TOR_UNIT: &str = "tor.service";

pub async fn dispatch(
    conn: &Connection,
    state: &AppState,
    cmd: HealthCommand,
) -> NyxOutput<HealthState> {
    let command_name = match &cmd {
        HealthCommand::Status => "status",
        HealthCommand::Panic => "panic",
        HealthCommand::Tor { .. } => "tor",
        HealthCommand::KillSwitch { .. } => "kill_switch",
        HealthCommand::TorRestart => "tor_restart",
    };

    let mut health = state.health.lock().await;

    if health.panic_mode && !matches!(cmd, HealthCommand::Status) {
        return NyxOutput::<HealthState>::err(
            BINARY,
            command_name,
            "panic mode is active — restart nyx-health to clear it",
        );
    }

    // Set when a command succeeded but didn't do quite what was asked
    // (currently only `KillSwitch { level: Medium }` with no tunnel
    // interface found) — surfaced as Status::Warning rather than Ok so
    // callers can't miss it.
    let mut warning: Option<String> = None;

    let result = match cmd {
        HealthCommand::Status => {
            health.tor_active = systemd_ctl::is_active(conn, TOR_UNIT).await.unwrap_or(false);
            Ok(())
        }
        HealthCommand::Panic => {
            let outcome = firewall::panic_lockdown();
            let _ = systemd_ctl::stop_unit(conn, TOR_UNIT).await;
            if outcome.is_ok() {
                health.panic_mode = true;
                health.tor_active = false;
                health.kill_switch_level = KillSwitchLevel::Armed;
                health.kill_switch_tunnel_iface = None;
                health.kill_switch_warning = None;
            }
            outcome
        }
        HealthCommand::Tor { action } => match action {
            Toggle::On => systemd_ctl::start_unit(conn, TOR_UNIT).await.map(|_| {
                health.tor_active = true;
            }),
            Toggle::Off => systemd_ctl::stop_unit(conn, TOR_UNIT).await.map(|_| {
                health.tor_active = false;
            }),
        },
        HealthCommand::KillSwitch { level } => firewall::kill_switch_set(level).map(|(iface, warn)| {
            health.kill_switch_level = level;
            health.kill_switch_tunnel_iface = iface;
            health.kill_switch_warning = warn.clone();
            warning = warn;
        }),
        HealthCommand::TorRestart => systemd_ctl::restart_unit(conn, TOR_UNIT).await.map(|_| {
            health.tor_active = true;
        }),
    };

    match result {
        Ok(()) => match warning {
            Some(w) => NyxOutput::warn(BINARY, command_name, w, Some(health.clone())),
            None => NyxOutput::ok(BINARY, command_name, "ok", Some(health.clone())),
        },
        Err(e) => NyxOutput::<HealthState>::err(BINARY, command_name, e.to_string()),
    }
}
