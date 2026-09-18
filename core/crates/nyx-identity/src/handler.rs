use crate::state::AppState;
use crate::{hostname, ipv6, mac, persisted, timezone};
use nyx_core::{IdentityCommand, IdentityReport, InterfaceIdentity, NyxOutput};

const BINARY: &str = "nyx-identity";

async fn report(state: &AppState) -> IdentityReport {
    let snapshot = state.persisted.lock().await.clone();
    let interfaces = mac::interfaces()
        .into_iter()
        .map(|(interface, mac_address)| InterfaceIdentity { interface, mac_address })
        .collect();

    IdentityReport {
        hostname: hostname::current(),
        original_hostname: snapshot.original_hostname,
        timezone: timezone::current(),
        original_timezone: snapshot.original_timezone,
        ipv6_enabled: ipv6::enabled(),
        interfaces,
        detail: "live values re-read on every call".to_string(),
    }
}

pub async fn dispatch(state: &AppState, cmd: IdentityCommand) -> NyxOutput<IdentityReport> {
    match cmd {
        IdentityCommand::Status => {
            let r = report(state).await;
            let detail = r.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(r))
        }

        IdentityCommand::RandomizeMac { interface } => match mac::randomize(&interface) {
            Ok(()) => {
                let r = report(state).await;
                NyxOutput::ok(
                    BINARY,
                    "randomize_mac",
                    format!("{interface}: cloned MAC set to random"),
                    Some(r),
                )
            }
            Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "randomize_mac", e.to_string()),
        },

        IdentityCommand::RestoreMac { interface } => match mac::restore(&interface) {
            Ok(()) => {
                let r = report(state).await;
                NyxOutput::ok(
                    BINARY,
                    "restore_mac",
                    format!("{interface}: cloned MAC restored to the hardware's permanent address"),
                    Some(r),
                )
            }
            Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "restore_mac", e.to_string()),
        },

        IdentityCommand::RandomizeHostname => {
            capture_original_hostname(state).await;
            let new_name = hostname::generate();
            match hostname::set(&new_name) {
                Ok(()) => {
                    let r = report(state).await;
                    NyxOutput::ok(
                        BINARY,
                        "randomize_hostname",
                        format!("hostname set to {new_name}"),
                        Some(r),
                    )
                }
                Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "randomize_hostname", e.to_string()),
            }
        }

        IdentityCommand::RestoreHostname => {
            let original = state.persisted.lock().await.original_hostname.clone();
            let Some(original) = original else {
                return NyxOutput::<IdentityReport>::err(
                    BINARY,
                    "restore_hostname",
                    "no original hostname was ever captured on this install — nothing to restore to",
                );
            };
            match hostname::set(&original) {
                Ok(()) => {
                    let r = report(state).await;
                    NyxOutput::ok(
                        BINARY,
                        "restore_hostname",
                        format!("hostname restored to {original}"),
                        Some(r),
                    )
                }
                Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "restore_hostname", e.to_string()),
            }
        }

        IdentityCommand::RandomizeTimezone => {
            let current = timezone::current();
            capture_original_timezone(state, current.clone()).await;
            match timezone::generate_random(current.as_deref()) {
                Ok(zone) => match timezone::set(&zone) {
                    Ok(()) => {
                        let r = report(state).await;
                        NyxOutput::ok(
                            BINARY,
                            "randomize_timezone",
                            format!("timezone set to {zone}"),
                            Some(r),
                        )
                    }
                    Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "randomize_timezone", e.to_string()),
                },
                Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "randomize_timezone", e.to_string()),
            }
        }

        IdentityCommand::RestoreTimezone => {
            let original = state.persisted.lock().await.original_timezone.clone();
            let Some(original) = original else {
                return NyxOutput::<IdentityReport>::err(
                    BINARY,
                    "restore_timezone",
                    "no original timezone was ever captured on this install — nothing to restore to",
                );
            };
            match timezone::set(&original) {
                Ok(()) => {
                    let r = report(state).await;
                    NyxOutput::ok(
                        BINARY,
                        "restore_timezone",
                        format!("timezone restored to {original}"),
                        Some(r),
                    )
                }
                Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "restore_timezone", e.to_string()),
            }
        }

        IdentityCommand::SetIpv6 { enabled } => match ipv6::set(enabled) {
            Ok(()) => {
                let r = report(state).await;
                let word = if enabled { "enabled" } else { "disabled" };
                NyxOutput::ok(BINARY, "set_ipv6", format!("IPv6 {word}"), Some(r))
            }
            Err(e) => NyxOutput::<IdentityReport>::err(BINARY, "set_ipv6", e.to_string()),
        },
    }
}

async fn capture_original_hostname(state: &AppState) {
    let mut snapshot = state.persisted.lock().await;
    if snapshot.original_hostname.is_none() {
        snapshot.original_hostname = hostname::current();
        let _ = persisted::save(&snapshot);
    }
}

async fn capture_original_timezone(state: &AppState, current: Option<String>) {
    let mut snapshot = state.persisted.lock().await;
    if snapshot.original_timezone.is_none() {
        snapshot.original_timezone = current;
        let _ = persisted::save(&snapshot);
    }
}
