//! nyx-diagnostics — one-shot, unprivileged CLI that aggregates every Nyx
//! daemon's live status plus fresh local network checks. It never invents
//! its own privileged operations: everything it reports either comes from
//! an existing daemon's own verified state (over its socket, same trust
//! boundary the dashboard uses) or from ordinary unprivileged reads
//! (`ip addr`/`ip route`) and standard tools (`ping`, `traceroute`).

mod bundle;
mod checks;
mod client;
mod redact;

use clap::{Parser, Subcommand};
use nyx_core::{
    DevicesCommand, DevicesReport, DnsCommand, DnsReport, HealthCommand, HealthState,
    IdentityCommand, IdentityReport, IntegrityCommand, IntegrityReport, NyxOutput,
    TelemetryCommand, TelemetryReport, VpnCommand, VpnReport, DEVICES_SOCKET, DNS_SOCKET,
    HEALTH_SOCKET, IDENTITY_SOCKET, INTEGRITY_SOCKET, TELEMETRY_SOCKET, VPN_SOCKET,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

const BINARY: &str = "nyx-diagnostics";

#[derive(Parser)]
#[command(
    name = "nyx-diagnostics",
    about = "NyxOS network diagnostics — live daemon state plus fresh local checks"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump interfaces and the routing table.
    Network,
    /// Ping a host to check basic connectivity.
    Connectivity {
        #[arg(long, default_value = "1.1.1.1")]
        host: String,
        #[arg(long, default_value_t = 4)]
        count: u32,
        #[arg(long, default_value_t = 2)]
        timeout: u32,
    },
    /// Trace the route to a host.
    Traceroute { host: String },
    /// Fetch this machine's public IP from an external service. That
    /// service will see the real IP and know a NyxOS user asked —
    /// refuses to run without --yes.
    PublicIp {
        #[arg(long, default_value = "https://icanhazip.com")]
        endpoint: String,
        #[arg(long)]
        yes: bool,
    },
    /// Live status from every Nyx daemon, plus interfaces/routes and a
    /// quick connectivity check. Does NOT fetch the public IP — that's
    /// opt-in only via `public-ip`.
    Summary,
    /// Collect a sanitized diagnostics bundle for support/troubleshooting:
    /// the same live daemon statuses `summary` gathers, an
    /// interfaces/routes dump, `uname -a`, and recent systemd/journal
    /// output for the Nyx services, packed into a gzipped tarball. Every
    /// collected item is redacted of secrets/IPs/emails/usernames before
    /// it's written — never includes credentials, browsing history, or
    /// personal file contents.
    Bundle {
        /// Where to write the archive. Defaults to
        /// `~/nyx-diagnostics-bundle-<unix-timestamp>.tar.gz`.
        #[arg(long)]
        output: Option<String>,
    },
}

fn print_local<T: serde::Serialize>(command: &str, message: impl Into<String>, data: T) {
    NyxOutput::ok(BINARY, command, message, Some(data)).print();
}

/// Calls one daemon's `Status` (or other) command and returns its
/// response as a pretty-printed JSON string — either the daemon's own
/// `NyxOutput`, or a synthesized error `NyxOutput` if it couldn't be
/// reached. A daemon that isn't running is itself diagnostic information,
/// not a fatal error for the rest of the report.
fn daemon_status_json<C: Serialize, R: Serialize + DeserializeOwned>(
    label: &str,
    socket: &str,
    cmd: C,
) -> String {
    let out = match client::call::<C, NyxOutput<R>>(socket, &cmd) {
        Ok(out) => serde_json::to_string(&out),
        Err(e) => serde_json::to_string(&NyxOutput::<()>::err(
            BINARY,
            label,
            format!("{label} unreachable: {e}"),
        )),
    };
    out.unwrap_or_else(|_| r#"{"status":"error","message":"output serialization failed"}"#.to_string())
}

fn print_daemon_status<C: Serialize, R: Serialize + DeserializeOwned>(label: &str, socket: &str, cmd: C) {
    println!("{}", daemon_status_json::<C, R>(label, socket, cmd));
}

/// Every Nyx daemon's live status as `(label, json)` pairs — the exact
/// same calls `run_summary` prints, factored out here so `bundle` can
/// reuse them instead of duplicating the daemon-calling logic.
pub(crate) fn gather_daemon_statuses() -> Vec<(&'static str, String)> {
    vec![
        (
            "health",
            daemon_status_json::<HealthCommand, HealthState>("health", HEALTH_SOCKET, HealthCommand::Status),
        ),
        ("vpn", daemon_status_json::<VpnCommand, VpnReport>("vpn", VPN_SOCKET, VpnCommand::Status)),
        ("dns", daemon_status_json::<DnsCommand, DnsReport>("dns", DNS_SOCKET, DnsCommand::Status)),
        (
            "identity",
            daemon_status_json::<IdentityCommand, IdentityReport>(
                "identity",
                IDENTITY_SOCKET,
                IdentityCommand::Status,
            ),
        ),
        (
            "devices",
            daemon_status_json::<DevicesCommand, DevicesReport>(
                "devices",
                DEVICES_SOCKET,
                DevicesCommand::Status,
            ),
        ),
        (
            "integrity",
            daemon_status_json::<IntegrityCommand, IntegrityReport>(
                "integrity",
                INTEGRITY_SOCKET,
                IntegrityCommand::Status,
            ),
        ),
        (
            "telemetry",
            daemon_status_json::<TelemetryCommand, TelemetryReport>(
                "telemetry",
                TELEMETRY_SOCKET,
                TelemetryCommand::Status,
            ),
        ),
    ]
}

fn run_summary() {
    print_daemon_status::<HealthCommand, HealthState>("health", HEALTH_SOCKET, HealthCommand::Status);
    print_daemon_status::<VpnCommand, VpnReport>("vpn", VPN_SOCKET, VpnCommand::Status);
    print_daemon_status::<DnsCommand, DnsReport>("dns", DNS_SOCKET, DnsCommand::Status);
    print_daemon_status::<IdentityCommand, IdentityReport>(
        "identity",
        IDENTITY_SOCKET,
        IdentityCommand::Status,
    );
    print_daemon_status::<DevicesCommand, DevicesReport>(
        "devices",
        DEVICES_SOCKET,
        DevicesCommand::Status,
    );
    print_daemon_status::<IntegrityCommand, IntegrityReport>(
        "integrity",
        INTEGRITY_SOCKET,
        IntegrityCommand::Status,
    );
    print_daemon_status::<TelemetryCommand, TelemetryReport>(
        "telemetry",
        TELEMETRY_SOCKET,
        TelemetryCommand::Status,
    );

    let dump = checks::network_dump();
    print_local("network", "interfaces and routing table", dump);

    match checks::ping("1.1.1.1", 2, 2) {
        Ok(result) => {
            let message = format!(
                "{}/{} received, {}% loss",
                result.received,
                result.transmitted,
                result.packet_loss_percent.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string())
            );
            print_local("connectivity", message, result);
        }
        Err(e) => NyxOutput::<()>::err(BINARY, "connectivity", e).print(),
    }
}

fn main() {
    nyx_core::logging::init();
    let cli = Cli::parse();

    match cli.command {
        Cmd::Network => {
            let dump = checks::network_dump();
            print_local("network", "interfaces and routing table", dump);
        }
        Cmd::Connectivity { host, count, timeout } => match checks::ping(&host, count, timeout) {
            Ok(result) => {
                let message = format!(
                    "{}/{} received, {}% loss",
                    result.received,
                    result.transmitted,
                    result.packet_loss_percent.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string())
                );
                print_local("connectivity", message, result);
            }
            Err(e) => {
                NyxOutput::<()>::err(BINARY, "connectivity", e).print();
                std::process::exit(1);
            }
        },
        Cmd::Traceroute { host } => {
            let result = checks::traceroute(&host);
            print_local("traceroute", format!("traceroute to {host}"), result);
        }
        Cmd::PublicIp { endpoint, yes } => {
            if !yes {
                nyx_core::output::print_error(
                    BINARY,
                    "public_ip",
                    "refusing to run without --yes — this sends one request to an external \
                     service, which will see this machine's real public IP",
                );
                std::process::exit(1);
            }
            match checks::public_ip(&endpoint) {
                Ok(result) => {
                    let message = format!("public IP: {}", result.ip);
                    print_local("public_ip", message, result);
                }
                Err(e) => {
                    NyxOutput::<()>::err(BINARY, "public_ip", e).print();
                    std::process::exit(1);
                }
            }
        }
        Cmd::Summary => run_summary(),
        Cmd::Bundle { output } => match bundle::collect(output) {
            Ok(outcome) => {
                let message = format!(
                    "bundle written to {} — redacted {} IP address(es), {} email(s), {} secret-like \
                     value(s), {} username occurrence(s) ({} total)",
                    outcome.archive_path.display(),
                    outcome.counts.ip_addresses,
                    outcome.counts.emails,
                    outcome.counts.secrets,
                    outcome.counts.usernames,
                    outcome.counts.total(),
                );
                let data = BundleReportData {
                    archive_path: outcome.archive_path.display().to_string(),
                    files_included: outcome.files,
                    redacted_ip_addresses: outcome.counts.ip_addresses,
                    redacted_emails: outcome.counts.emails,
                    redacted_secrets: outcome.counts.secrets,
                    redacted_username_occurrences: outcome.counts.usernames,
                };
                print_local("bundle", message, data);
            }
            Err(e) => {
                NyxOutput::<()>::err(BINARY, "bundle", e).print();
                std::process::exit(1);
            }
        },
    }
}

#[derive(serde::Serialize)]
struct BundleReportData {
    archive_path: String,
    files_included: Vec<String>,
    redacted_ip_addresses: usize,
    redacted_emails: usize,
    redacted_secrets: usize,
    redacted_username_occurrences: usize,
}
