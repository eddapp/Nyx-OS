use crate::{checks, systemd_ctl};
use crate::state::AppState;
use nyx_core::{DnsCommand, DnsReport, NyxOutput, SecurityState};
use zbus::Connection;

const BINARY: &str = "nyx-dns";
const DNSCRYPT_UNIT: &str = "dnscrypt-proxy.service";

pub async fn dispatch(conn: &Connection, state: &AppState, cmd: DnsCommand) -> NyxOutput<DnsReport> {
    let command_name = "status";
    match cmd {
        DnsCommand::Status => {}
    }

    let nameservers = checks::resolv_conf_nameservers();
    let resolver_is_local = checks::resolver_is_local(&nameservers);
    let dnscrypt_active = systemd_ctl::is_active(conn, DNSCRYPT_UNIT)
        .await
        .unwrap_or(false);
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

    let report = DnsReport {
        resolver_is_local,
        resolver_addrs: nameservers,
        dnscrypt_active,
        resolves,
        foreign_listener_on_53,
        state: state_value,
        detail: detail.clone(),
    };

    *state.last.lock().await = report.clone();

    NyxOutput::ok(BINARY, command_name, detail, Some(report))
}
