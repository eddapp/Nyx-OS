use crate::client;
use crate::model::{Condition, Workflow, WorkflowCommand};
use nyx_core::{
    DevicesCommand, DevicesReport, DnsCommand, DnsReport, HealthCommand, HealthState,
    IdentityCommand, IdentityReport, IntegrityCommand, IntegrityReport, NyxOutput, SocksProxyAddr,
    Status, Toggle, VpnCommand, VpnReport, DEVICES_SOCKET, DNS_SOCKET, HEALTH_SOCKET,
    IDENTITY_SOCKET, INTEGRITY_SOCKET, VPN_SOCKET,
};
use std::io::Write;

/// Tor's SocksPort, per `iso/airootfs/etc/tor/torrc`'s `SocksPort
/// 127.0.0.1:9050` line — the only upstream SOCKS proxy VPN-over-Tor
/// chaining ever points at in this project.
fn tor_socks_proxy() -> SocksProxyAddr {
    SocksProxyAddr { host: "127.0.0.1".to_string(), port: 9050 }
}

pub struct StepResult {
    pub description: String,
    pub ran: bool,
    pub ok: bool,
    pub message: String,
}

pub struct WorkflowReport {
    pub id: String,
    pub results: Vec<StepResult>,
}

fn ask_yes_no(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn call_health(cmd: HealthCommand) -> (bool, String) {
    match client::call::<HealthCommand, NyxOutput<HealthState>>(HEALTH_SOCKET, &cmd) {
        Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
        Err(e) => (false, e),
    }
}

fn call_identity(cmd: IdentityCommand) -> (bool, String) {
    match client::call::<IdentityCommand, NyxOutput<IdentityReport>>(IDENTITY_SOCKET, &cmd) {
        Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
        Err(e) => (false, e),
    }
}

fn call_devices(cmd: DevicesCommand) -> (bool, String) {
    match client::call::<DevicesCommand, NyxOutput<DevicesReport>>(DEVICES_SOCKET, &cmd) {
        Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
        Err(e) => (false, e),
    }
}

/// Stages `policy_json` to a temp file the invoking user can write, then
/// asks `pkexec` to install it as
/// `/opt/zen-browser-bin/distribution/policies.json` (mode 0644, creating
/// the directory if needed) — the real path this specific AUR package (a
/// prebuilt tarball release under `/opt`, not an `/etc/<vendor>/`-style
/// system package) reads its policy from; there is no merging across
/// multiple policy files, so writing this one file fully determines the
/// browser's policy state.
const ZEN_POLICY_PATH: &str = "/opt/zen-browser-bin/distribution/policies.json";

fn apply_browser_policy(label: &str, policy_json: &str) -> (bool, String) {
    let tmp = std::env::temp_dir().join(format!("nyx-zen-browser-policy-{}.json", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, policy_json) {
        return (false, format!("could not stage {label} Zen Browser policy file: {e}"));
    }

    let result = std::process::Command::new("pkexec")
        .args(["install", "-Dm644", &tmp.to_string_lossy(), ZEN_POLICY_PATH])
        .status();
    let _ = std::fs::remove_file(&tmp);

    match result {
        Ok(status) if status.success() => {
            (true, format!("installed {label} Zen Browser policy to {ZEN_POLICY_PATH}"))
        }
        Ok(status) => (
            false,
            format!(
                "pkexec install exited with {status} — {label} Zen Browser policy was NOT applied \
                 (auth prompt declined, or polkit/pkexec unavailable)"
            ),
        ),
        Err(e) => (false, format!("could not run pkexec: {e}")),
    }
}

/// Tor-over-VPN chaining. Restarts `tor.service` so every circuit is
/// rebuilt from scratch over whatever route currently exists — but only
/// after independently confirming, right now, that the VPN backend really
/// does own the default route. A prior workflow step reporting success
/// only means "nyx-vpn was reachable and didn't error", not that the
/// tunnel is actually carrying traffic — see `VpnReport.default_route_via_vpn`
/// and `handler.rs`'s `probe()` in nyx-vpn for how that's derived from a
/// live route query, not from what nyx-vpn remembers asking for.
fn restart_tor_over_vpn() -> (bool, String) {
    let owns_route = match client::call::<VpnCommand, NyxOutput<VpnReport>>(VPN_SOCKET, &VpnCommand::Status) {
        Ok(out) => out.data.as_ref().map(|d| d.default_route_via_vpn).unwrap_or(false),
        Err(e) => {
            return (false, format!("could not confirm VPN route ownership before restarting Tor: {e}"));
        }
    };
    if !owns_route {
        return (
            false,
            "VPN does not currently own the default route — refusing to restart Tor, since any \
             circuits it rebuilds would just end up on the same route they were already using"
                .to_string(),
        );
    }
    call_health(HealthCommand::TorRestart)
}

fn execute(cmd: &WorkflowCommand) -> (bool, String) {
    match cmd {
        WorkflowCommand::Message(text) => {
            println!("{text}");
            (true, text.clone())
        }
        WorkflowCommand::Confirm(text) => (ask_yes_no(text), "operator confirmation".to_string()),
        WorkflowCommand::HealthStatus => call_health(HealthCommand::Status),
        WorkflowCommand::HealthTor { on } => call_health(HealthCommand::Tor {
            action: if *on { Toggle::On } else { Toggle::Off },
        }),
        WorkflowCommand::HealthKillSwitch { level } => {
            call_health(HealthCommand::KillSwitch { level: *level })
        }
        WorkflowCommand::HealthPanic => call_health(HealthCommand::Panic),
        WorkflowCommand::RestartTorOverVpn => restart_tor_over_vpn(),
        WorkflowCommand::DnsStatus => {
            match client::call::<DnsCommand, NyxOutput<DnsReport>>(DNS_SOCKET, &DnsCommand::Status) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::IntegrityStatus => match client::call::<IntegrityCommand, NyxOutput<IntegrityReport>>(
            INTEGRITY_SOCKET,
            &IntegrityCommand::Status,
        ) {
            Ok(out) => (matches!(out.status, Status::Ok), out.message),
            Err(e) => (false, e),
        },
        WorkflowCommand::IntegrityVerify { quick } => {
            match client::call::<IntegrityCommand, NyxOutput<IntegrityReport>>(
                INTEGRITY_SOCKET,
                &IntegrityCommand::Verify { quick: *quick },
            ) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnStatus => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(VPN_SOCKET, &VpnCommand::Status)
            {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnConnect { protocol, profile } => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(
                VPN_SOCKET,
                &VpnCommand::Connect { protocol: *protocol, profile: profile.clone() },
            ) {
                Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnConnectViaTor { protocol, profile } => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(
                VPN_SOCKET,
                &VpnCommand::ConnectViaSocksProxy {
                    protocol: *protocol,
                    profile: profile.clone(),
                    socks_proxy: tor_socks_proxy(),
                },
            ) {
                Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnDisconnect => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(
                VPN_SOCKET,
                &VpnCommand::Disconnect,
            ) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::IdentityStatus => call_identity(IdentityCommand::Status),
        WorkflowCommand::IdentitySetIpv6 { enabled } => {
            call_identity(IdentityCommand::SetIpv6 { enabled: *enabled })
        }
        WorkflowCommand::IdentityRandomizeMac { interface } => {
            call_identity(IdentityCommand::RandomizeMac { interface: interface.clone() })
        }
        WorkflowCommand::IdentityRandomizeHostname => {
            call_identity(IdentityCommand::RandomizeHostname)
        }
        WorkflowCommand::IdentityRandomizeTimezone => {
            call_identity(IdentityCommand::RandomizeTimezone)
        }
        WorkflowCommand::DevicesStatus => call_devices(DevicesCommand::Status),
        WorkflowCommand::DevicesSetUsbGuard { enabled } => {
            call_devices(DevicesCommand::SetUsbGuard { enabled: *enabled })
        }
        WorkflowCommand::DevicesSetModule { module, enabled } => {
            call_devices(DevicesCommand::SetModule { module: *module, enabled: *enabled })
        }
        WorkflowCommand::DevicesSetMicrophone { enabled } => {
            call_devices(DevicesCommand::SetMicrophone { enabled: *enabled })
        }
        WorkflowCommand::DevicesSetRadio { radio, on } => {
            call_devices(DevicesCommand::SetRadio { radio: *radio, on: *on })
        }
        WorkflowCommand::ApplyBrowserPolicy { label, policy_json } => {
            apply_browser_policy(label, policy_json)
        }
    }
}

/// Run every step of `workflow` in order. `Condition::IfSuccess`/
/// `IfFailure` gate on whether the immediately preceding step (that
/// actually ran) succeeded — a skipped step doesn't count as either.
pub fn run(workflow: &Workflow) -> WorkflowReport {
    let mut results = Vec::new();
    let mut last_ok = true;

    for step in &workflow.steps {
        let gate_satisfied = match step.condition {
            Condition::Always => true,
            Condition::IfSuccess => last_ok,
            Condition::IfFailure => !last_ok,
        };

        if !gate_satisfied {
            results.push(StepResult {
                description: step.description.to_string(),
                ran: false,
                ok: true,
                message: "skipped (condition not met)".to_string(),
            });
            continue;
        }

        if step.confirm {
            let prompt = format!("[{:?}] {} — proceed?", step.danger, step.description);
            if !ask_yes_no(&prompt) {
                results.push(StepResult {
                    description: step.description.to_string(),
                    ran: false,
                    ok: false,
                    message: "declined by operator".to_string(),
                });
                last_ok = false;
                continue;
            }
        }

        println!("-> {}", step.description);
        let (ok, message) = execute(&step.cmd);
        println!("   {}", message);
        if !ok {
            println!("   rollback guidance: {}", step.rollback_hint);
        }

        last_ok = ok;
        results.push(StepResult {
            description: step.description.to_string(),
            ran: true,
            ok,
            message,
        });
    }

    WorkflowReport {
        id: workflow.id.to_string(),
        results,
    }
}
