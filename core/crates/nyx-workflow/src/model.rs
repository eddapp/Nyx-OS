//! Workflow step vocabulary. Deliberately typed and closed, not "run this
//! shell string": every step is one of a small set of real calls into an
//! already-privileged Nyx daemon over its own socket, or a purely local
//! message/confirmation step. There is no `Shell(String)` variant — a
//! workflow cannot do anything nyx-health/nyx-dns/nyx-integrity themselves
//! don't already expose, which is the whole point of routing everything
//! through the control plane instead of ad-hoc scripts.

use nyx_core::{DeviceModule, DeviceRadio, KillSwitchLevel, VpnProtocol};

#[derive(Clone)]
pub enum WorkflowCommand {
    HealthStatus,
    HealthTor { on: bool },
    HealthKillSwitch { level: KillSwitchLevel },
    HealthPanic,
    DnsStatus,
    IntegrityStatus,
    IntegrityVerify { quick: bool },
    VpnStatus,
    VpnConnect { protocol: VpnProtocol, profile: String },
    VpnDisconnect,
    IdentityStatus,
    IdentitySetIpv6 { enabled: bool },
    IdentityRandomizeMac { interface: String },
    IdentityRandomizeHostname,
    IdentityRandomizeTimezone,
    DevicesStatus,
    DevicesSetUsbGuard { enabled: bool },
    DevicesSetModule { module: DeviceModule, enabled: bool },
    DevicesSetMicrophone { enabled: bool },
    DevicesSetRadio { radio: DeviceRadio, on: bool },
    /// Purely local — writes `policy_json` to
    /// `/etc/librewolf/policies/policies.json` via `pkexec install`
    /// (LibreWolf reads that exact path and it takes priority over
    /// `/etc/firefox/policies/policies.json`). `label` is only for the
    /// human-readable step result, e.g. "Paranoid".
    ApplyBrowserPolicy { label: &'static str, policy_json: &'static str },
    /// Purely local — print informational text, always succeeds.
    Message(String),
    /// Purely local — block for an interactive yes/no; failing this step
    /// (declining) behaves like any other step failure for `IfSuccess`
    /// gating downstream.
    Confirm(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    Always,
    IfSuccess,
    IfFailure,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DangerLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

pub struct Step {
    pub description: &'static str,
    pub cmd: WorkflowCommand,
    pub condition: Condition,
    pub danger: DangerLevel,
    /// Blocks for an interactive yes/no before running, regardless of
    /// `condition` having already been satisfied.
    pub confirm: bool,
    /// Human guidance shown on failure. Nyx workflows do not implement
    /// automated rollback — every step here is either already idempotent
    /// (status/verify calls) or, where destructive, the guidance says so
    /// plainly instead of pretending an undo exists.
    pub rollback_hint: &'static str,
}

pub struct Workflow {
    pub id: &'static str,
    pub description: &'static str,
    pub steps: Vec<Step>,
}
