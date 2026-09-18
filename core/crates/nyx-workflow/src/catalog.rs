//! Built-in NyxOS workflows. Small on purpose — each one composes existing,
//! already-real daemon calls (see `executor.rs`) rather than introducing new
//! privileged behaviour of its own.

use crate::model::{Condition, DangerLevel, Step, Workflow, WorkflowCommand};
use nyx_core::VpnProtocol;

pub(crate) const STATUS_ROLLBACK: &str =
    "Re-run the equivalent status command and compare against the prior state.";
const IRREVERSIBLE_ROLLBACK: &str =
    "No automated rollback exists for this step — restore network/service state manually if needed.";

/// `connect-vpn-with-verification`, `tor-over-vpn`, and `vpn-over-tor` all
/// need a protocol+profile at run time, so none of them are in here with a
/// real target — `main.rs` builds each directly via
/// [`connect_vpn_with_verification`]/[`tor_over_vpn`]/[`vpn_over_tor`] when
/// the operator supplies both. They're still listed by `Cmd::List` in
/// `main.rs` so `nyx-workflow list` shows them.
pub fn catalog() -> Vec<Workflow> {
    vec![
        enable_tor_with_verification(),
        security_checkup(),
        emergency_lockdown(),
        kill_switch_drill(),
    ]
}

pub fn find(id: &str) -> Option<Workflow> {
    catalog().into_iter().find(|w| w.id == id)
}

pub const PARAMETRIZED_WORKFLOW_ID: &str = "connect-vpn-with-verification";
pub const PARAMETRIZED_WORKFLOW_DESCRIPTION: &str =
    "Connect a specific VPN profile, then verify DNS is still enforced and the tunnel is really \
     carrying traffic. Needs --protocol and --profile.";

pub fn connect_vpn_with_verification(protocol: VpnProtocol, profile: String) -> Workflow {
    Workflow {
        id: PARAMETRIZED_WORKFLOW_ID,
        description: PARAMETRIZED_WORKFLOW_DESCRIPTION,
        steps: vec![
            Step {
                description: "Connect the requested VPN profile",
                cmd: WorkflowCommand::VpnConnect { protocol, profile: profile.clone() },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Run `nyx-workflow run` again, or disconnect via the dashboard/`nyx-vpn`.",
            },
            Step {
                description: "Confirm the tunnel is actually up (handshake/route, not just the command exit code)",
                cmd: WorkflowCommand::VpnStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Verify DNS is still enforced over the new route",
                cmd: WorkflowCommand::DnsStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: "If DNS reports Blocked/Degraded, disconnect and investigate before trusting this route.",
            },
            Step {
                description: "DNS check failed — disconnect rather than trust a route that couldn't be verified",
                cmd: WorkflowCommand::VpnDisconnect,
                condition: Condition::IfFailure,
                danger: DangerLevel::Medium,
                confirm: false,
                rollback_hint: "Reconnect manually once the underlying DNS/route issue is understood.",
            },
        ],
    }
}

pub const TOR_OVER_VPN_WORKFLOW_ID: &str = "tor-over-vpn";
pub const TOR_OVER_VPN_WORKFLOW_DESCRIPTION: &str =
    "Tor-over-VPN: connect a VPN profile, confirm it owns the default route, then restart Tor \
     so any circuits built before the VPN connected are discarded and fresh ones are built over \
     the tunnel. Needs --protocol and --profile.";

/// Tor-over-VPN chaining. Once the VPN backend owns the default route,
/// Tor's own traffic already flows over it automatically — Tor makes no
/// routing decisions of its own, so no Tor-side reconfiguration is needed
/// for that part. The one real risk is a circuit built *before* the VPN
/// connected still routing over the old path; `RestartTorOverVpn` is what
/// actually verifies route ownership and restarts Tor (see `executor.rs`'s
/// `restart_tor_over_vpn`) — the `VpnConnect`/`VpnStatus` steps here exist
/// to actually bring the tunnel up and show its state to the operator, not
/// to gate anything themselves (same shape as
/// `connect_vpn_with_verification`'s own steps).
pub fn tor_over_vpn(protocol: VpnProtocol, profile: String) -> Workflow {
    Workflow {
        id: TOR_OVER_VPN_WORKFLOW_ID,
        description: TOR_OVER_VPN_WORKFLOW_DESCRIPTION,
        steps: vec![
            Step {
                description: "Connect the requested VPN profile",
                cmd: WorkflowCommand::VpnConnect { protocol, profile: profile.clone() },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Run `nyx-workflow run` again, or disconnect via the dashboard/`nyx-vpn`.",
            },
            Step {
                description: "Confirm the tunnel is actually up (handshake/route, not just the command exit code)",
                cmd: WorkflowCommand::VpnStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Restart Tor so any circuits built before the VPN connected are \
                               discarded, forcing fresh ones over the new route — but only once \
                               the VPN is independently confirmed to own the default route",
                cmd: WorkflowCommand::RestartTorOverVpn,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Medium,
                confirm: false,
                rollback_hint: "Restart Tor manually (nyx-health Tor off/on) once the VPN is confirmed to own the default route.",
            },
            Step {
                description: "Confirm Tor is active again after the restart",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
        ],
    }
}

pub const VPN_OVER_TOR_WORKFLOW_ID: &str = "vpn-over-tor";
pub const VPN_OVER_TOR_WORKFLOW_DESCRIPTION: &str =
    "VPN-over-Tor: connect a VPN profile with its own uplink dialed through Tor's SocksPort \
     instead of directly. Only real for OpenVPN, Xray, and Shadowsocks profiles — WireGuard, \
     AmneziaWG, Hysteria2, and SOCKS5 are rejected with an explanation (UDP-only tunnels/no \
     chaining mechanism). Needs --protocol and --profile.";

/// VPN-over-Tor chaining. `VpnConnectViaTor` is where the real work (and
/// the real verification that Tor's SocksPort is actually accepting
/// connections, not just that `tor.service` is reported active) happens —
/// see `nyx-vpn`'s `handler.rs` and each backend module for exactly what's
/// supported and why the rest are rejected outright.
pub fn vpn_over_tor(protocol: VpnProtocol, profile: String) -> Workflow {
    Workflow {
        id: VPN_OVER_TOR_WORKFLOW_ID,
        description: VPN_OVER_TOR_WORKFLOW_DESCRIPTION,
        steps: vec![
            Step {
                description: "Connect the requested VPN profile through Tor's SocksPort",
                cmd: WorkflowCommand::VpnConnectViaTor { protocol, profile: profile.clone() },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Run `nyx-workflow run` again once Tor is confirmed reachable, or disconnect via the dashboard/`nyx-vpn`.",
            },
            Step {
                description: "Confirm the tunnel is actually up",
                cmd: WorkflowCommand::VpnStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
        ],
    }
}

fn enable_tor_with_verification() -> Workflow {
    Workflow {
        id: "enable-tor-with-verification",
        description: "Start Tor, then verify DNS is actually enforced before declaring success.",
        steps: vec![
            Step {
                description: "Start Tor",
                cmd: WorkflowCommand::HealthTor { on: true },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Run `nyx-workflow run enable-tor-with-verification` again, or stop Tor via the dashboard.",
            },
            Step {
                description: "Confirm Tor is reported active",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Verify the DNS path is enforced and resolving",
                cmd: WorkflowCommand::DnsStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: "If DNS reports Blocked or Degraded, Tor being active does not mean traffic is protected — check nyx-dns's detail message before trusting this route.",
            },
        ],
    }
}

fn security_checkup() -> Workflow {
    Workflow {
        id: "security-checkup",
        description: "Read-only posture check: package/manifest integrity, DNS enforcement, kill-switch/Tor state.",
        steps: vec![
            Step {
                description: "Quick integrity verification (Nyx-critical packages + file manifest)",
                cmd: WorkflowCommand::IntegrityVerify { quick: true },
                condition: Condition::Always,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "DNS enforcement status",
                cmd: WorkflowCommand::DnsStatus,
                condition: Condition::Always,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Kill switch / Tor / panic status",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::Always,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
        ],
    }
}

fn kill_switch_drill() -> Workflow {
    Workflow {
        id: "kill-switch-drill",
        description: "Briefly raise the kill switch to Medium, verify it took, then restore Off. \
                       Safe to run to confirm nyx-health's firewall control actually works.",
        steps: vec![
            Step {
                description: "Explain what this drill does",
                cmd: WorkflowCommand::Message(
                    "Raising kill switch to Medium for a few seconds, then restoring Off.".to_string(),
                ),
                condition: Condition::Always,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Raise kill switch to Medium",
                cmd: WorkflowCommand::HealthKillSwitch { level: nyx_core::KillSwitchLevel::Medium },
                condition: Condition::Always,
                danger: DangerLevel::Medium,
                confirm: false,
                rollback_hint: "Run `nyx-workflow run kill-switch-drill` again, or set the kill switch to Off from the dashboard.",
            },
            Step {
                description: "Confirm the level actually took (and note if it fell back to Soft)",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "nyx-health could not be reached to raise the kill switch",
                cmd: WorkflowCommand::Message(
                    "Drill aborted before touching the firewall — check that nyx-health is running.".to_string(),
                ),
                condition: Condition::IfFailure,
                danger: DangerLevel::High,
                confirm: false,
                rollback_hint: "Nothing was changed; investigate nyx-health before retrying.",
            },
            Step {
                description: "Restore kill switch to Off",
                cmd: WorkflowCommand::HealthKillSwitch { level: nyx_core::KillSwitchLevel::Off },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Sanity-check system integrity while we're here",
                cmd: WorkflowCommand::IntegrityStatus,
                condition: Condition::Always,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
        ],
    }
}

fn emergency_lockdown() -> Workflow {
    Workflow {
        id: "emergency-lockdown",
        description: "Drop all traffic except loopback and stop Tor. One-way — only a nyx-health restart clears it.",
        steps: vec![
            Step {
                description: "Operator confirmation",
                cmd: WorkflowCommand::Confirm(
                    "This will drop ALL network traffic except loopback and stop Tor. \
                     Only restarting nyx-health clears it. Continue?"
                        .to_string(),
                ),
                condition: Condition::Always,
                danger: DangerLevel::Critical,
                confirm: false,
                rollback_hint: "Declining this step does nothing — nothing has run yet.",
            },
            Step {
                description: "Trigger panic lockdown",
                cmd: WorkflowCommand::HealthPanic,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Critical,
                confirm: false,
                rollback_hint: IRREVERSIBLE_ROLLBACK,
            },
            Step {
                description: "Confirm lockdown took effect",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
        ],
    }
}
