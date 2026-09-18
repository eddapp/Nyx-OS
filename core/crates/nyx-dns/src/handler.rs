use crate::state::AppState;
use crate::{checks, dnscrypt_config, providers, systemd_ctl};
use nyx_core::{DnsCommand, DnsProvider, DnsReport, NyxOutput, SecurityState};
use std::time::Duration;
use zbus::Connection;

const BINARY: &str = "nyx-dns";
const DNSCRYPT_UNIT: &str = "dnscrypt-proxy.service";

/// How many times to re-probe after a restart before giving up. Restarting
/// dnscrypt-proxy means it has to rebind :53 and, for a DNSCrypt/DoH
/// upstream, complete a fresh handshake before it can answer anything —
/// worth a few short retries rather than judging success/failure off a
/// single query fired the instant `RestartUnit` returns.
const VERIFY_ATTEMPTS: u32 = 5;
const VERIFY_RETRY_DELAY: Duration = Duration::from_millis(600);

pub async fn dispatch(conn: &Connection, state: &AppState, cmd: DnsCommand) -> NyxOutput<DnsReport> {
    match cmd {
        DnsCommand::Status => {
            let report = compute_report(conn).await;
            let detail = report.detail.clone();
            *state.last.lock().await = report.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(report))
        }

        DnsCommand::ListProviders => {
            let mut report = compute_report(conn).await;
            report.providers = provider_list();
            let count = report.providers.len();
            let base_detail = report.detail.clone();
            let detail = format!("{count} curated provider(s); {base_detail}");
            *state.last.lock().await = report.clone();
            NyxOutput::ok(BINARY, "list_providers", detail, Some(report))
        }

        DnsCommand::SwitchProvider { provider } => switch_provider(conn, state, &provider).await,
    }
}

/// The same live checks `Status` and `ListProviders` both report from —
/// kept in one place so every command shows a consistent picture of the
/// DNS path, not just whatever it individually touched.
async fn compute_report(conn: &Connection) -> DnsReport {
    let nameservers = checks::resolv_conf_nameservers();
    let resolver_is_local = checks::resolver_is_local(&nameservers);
    let dnscrypt_active = systemd_ctl::is_active(conn, DNSCRYPT_UNIT).await.unwrap_or(false);
    let foreign_listener_on_53 = checks::foreign_listener_on_53();
    let resolves = checks::probe_local_resolver();

    let (state_value, detail) = if !resolver_is_local {
        (
            SecurityState::Blocked,
            format!(
                "/etc/resolv.conf lists non-loopback nameserver(s): {}",
                nameservers.join(", ")
            ),
        )
    } else if foreign_listener_on_53 {
        (
            SecurityState::Blocked,
            "a listener bound to a non-loopback address on port 53 was found — DNS can bypass \
             dnscrypt-proxy"
                .to_string(),
        )
    } else if !dnscrypt_active {
        (
            SecurityState::Blocked,
            format!("{DNSCRYPT_UNIT} is not active — nothing is enforcing the DNS policy"),
        )
    } else if !resolves {
        (
            SecurityState::Degraded,
            "resolv.conf and dnscrypt-proxy are correctly enforced, but a live query to \
             127.0.0.1:53 did not complete — no upstream route yet (expected if Tor/VPN is down)"
                .to_string(),
        )
    } else {
        (
            SecurityState::Protected,
            "resolv.conf is loopback-only, dnscrypt-proxy is active, no foreign listener on \
             port 53, and a live query resolved"
                .to_string(),
        )
    };

    DnsReport {
        resolver_is_local,
        resolver_addrs: nameservers,
        dnscrypt_active,
        resolves,
        foreign_listener_on_53,
        state: state_value,
        detail,
        providers: Vec::new(),
    }
}

/// The curated list, each entry's `active` flag read live from the
/// deployed config rather than anything cached — `active_stamps` failing
/// (e.g. the file is unreadable) is reported as "nothing active" instead
/// of failing the whole call, since `ListProviders` should still show the
/// menu even if it can't currently tell what's selected.
fn provider_list() -> Vec<DnsProvider> {
    let active_stamps = dnscrypt_config::active_stamps().unwrap_or_default();
    providers::PROVIDERS
        .iter()
        .map(|p| DnsProvider {
            id: p.id.to_string(),
            display_name: p.display_name.to_string(),
            active: active_stamps.iter().any(|s| s == p.stamp),
        })
        .collect()
}

async fn probe_with_retries() -> bool {
    for attempt in 0..VERIFY_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(VERIFY_RETRY_DELAY).await;
        }
        if checks::probe_local_resolver() {
            return true;
        }
    }
    false
}

async fn switch_provider(conn: &Connection, state: &AppState, provider_id: &str) -> NyxOutput<DnsReport> {
    const COMMAND: &str = "switch_provider";

    let Some(provider) = providers::find(provider_id) else {
        let ids: Vec<&str> = providers::PROVIDERS.iter().map(|p| p.id).collect();
        return NyxOutput::err(
            BINARY,
            COMMAND,
            format!("'{provider_id}' is not a curated provider — valid ids: {}", ids.join(", ")),
        );
    };

    let original_line = match dnscrypt_config::set_server_names(&[provider.stamp]) {
        Ok(line) => line,
        Err(e) => {
            return NyxOutput::err(
                BINARY,
                COMMAND,
                format!("failed to update {}: {e}", dnscrypt_config::DNSCRYPT_TOML),
            );
        }
    };

    if let Err(e) = systemd_ctl::restart_unit(conn, DNSCRYPT_UNIT).await {
        // The config file already changed even though the restart didn't
        // happen; put it back so a crashed/stuck restart doesn't leave a
        // provider selected that was never actually loaded.
        let _ = dnscrypt_config::restore_server_names_line(&original_line);
        let _ = systemd_ctl::restart_unit(conn, DNSCRYPT_UNIT).await;
        return NyxOutput::err(
            BINARY,
            COMMAND,
            format!(
                "wrote '{}' to server_names but failed to restart {DNSCRYPT_UNIT} ({e}) — rolled \
                 back",
                provider.stamp
            ),
        );
    }

    if probe_with_retries().await {
        let mut report = compute_report(conn).await;
        report.providers = provider_list();
        let detail = format!(
            "switched to {} ({}) and a live query still resolves",
            provider.display_name, provider.stamp
        );
        report.detail = detail.clone();
        *state.last.lock().await = report.clone();
        return NyxOutput::ok(BINARY, COMMAND, detail, Some(report));
    }

    // Verification failed — roll back rather than leave DNS on an unproven
    // provider.
    let restore_result = dnscrypt_config::restore_server_names_line(&original_line);
    let restart_result = systemd_ctl::restart_unit(conn, DNSCRYPT_UNIT).await;
    let rolled_back = restore_result.is_ok() && restart_result.is_ok();
    let post_rollback_resolves = if rolled_back { probe_with_retries().await } else { false };

    let detail = match (rolled_back, post_rollback_resolves) {
        (true, true) => format!(
            "switching to {} broke resolution; rolled back server_names to the previous value \
             and resolution is working again",
            provider.display_name
        ),
        (true, false) => format!(
            "switching to {} broke resolution; rolled back server_names and restarted \
             {DNSCRYPT_UNIT}, but a post-rollback query still did not resolve — check \
             dnscrypt-proxy manually",
            provider.display_name
        ),
        (false, _) => format!(
            "switching to {} broke resolution AND the automatic rollback failed \
             (restore: {}, restart: {}) — DNS may currently be broken, check {DNSCRYPT_UNIT} and \
             {} by hand",
            provider.display_name,
            restore_result.map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string()),
            restart_result.map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string()),
            dnscrypt_config::DNSCRYPT_TOML,
        ),
    };

    let mut report = compute_report(conn).await;
    report.providers = provider_list();
    report.detail = detail.clone();
    *state.last.lock().await = report.clone();
    NyxOutput::err(BINARY, COMMAND, detail)
}
