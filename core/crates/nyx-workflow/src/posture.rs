//! Named security postures — Standard / Medium / Paranoid.
//!
//! A posture is not a new privileged primitive: it is a bigger, named
//! workflow assembled from exactly the same real daemon calls
//! `catalog.rs`'s built-ins already use (see `model.rs`'s own rule that a
//! workflow step can only be a real socket call into an already-privileged
//! Nyx daemon, or a purely local message/confirmation step).
//!
//! Two things Medium/Paranoid need aren't knowable at compile time — which
//! network interfaces exist, and whether a VPN is actually protecting the
//! machine right now — so this module runs a couple of read-only status
//! calls at *build* time (before the workflow is handed to `executor::run`)
//! to shape the step list, then returns an ordinary `Workflow` the existing
//! executor runs completely unchanged.
//!
//! Deliberately NOT attempted here, for lack of any real backing in this
//! codebase: kernel lockdown, IOMMU/DMA protection, swap encryption,
//! cold-boot defenses, RAM-wipe-on-shutdown, clipboard restriction,
//! screen-capture monitoring, or any process/network anomaly ("watch")
//! monitoring. None of these have a real daemon or verifiable mechanism
//! behind them yet.

use crate::catalog::STATUS_ROLLBACK;
use crate::client;
use crate::model::{Condition, DangerLevel, Step, Workflow, WorkflowCommand};
use nyx_core::{
    DeviceModule, DeviceRadio, IdentityCommand, IdentityReport, KillSwitchLevel, NyxOutput,
    SecurityState, VpnCommand, VpnReport, IDENTITY_SOCKET, VPN_SOCKET,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Posture {
    Standard,
    Medium,
    Paranoid,
}

impl Posture {
    pub const fn id(self) -> &'static str {
        match self {
            Posture::Standard => "posture-standard",
            Posture::Medium => "posture-medium",
            Posture::Paranoid => "posture-paranoid",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Posture::Standard => {
                "Kill switch off; DNS/devices/identity left exactly as configured. \
                 A light-touch baseline, not a hardening pass."
            }
            Posture::Medium => {
                "Kill switch Soft, IPv6 off, MAC/hostname randomized, USBGuard enforced. \
                 Stronger boundaries, still a usable workstation — webcam/mic/Bluetooth untouched."
            }
            Posture::Paranoid => {
                "Kill switch Armed, everything Medium does, plus timezone randomized and \
                 webcam/mic/USB-storage/Bluetooth forced off. Deny by default."
            }
        }
    }

    pub const fn all() -> [Posture; 3] {
        [Posture::Standard, Posture::Medium, Posture::Paranoid]
    }

    pub fn parse(id: &str) -> Option<Posture> {
        Posture::all().into_iter().find(|p| p.id() == id)
    }
}

// ---------------------------------------------------------------------------
// Zen Browser policy payloads. Zen is Firefox-based and reads the same real,
// documented Mozilla enterprise policy schema every Firefox-family browser
// does — no invented schema:
//   - "DisableAppUpdate"                       (documented top-level policy;
//     kept `true` in every tier, matching the zen-browser-bin package's own
//     shipped default — pacman, not Zen's built-in updater, owns updates
//     here, same reasoning the AUR package itself already applies)
//   - "DefaultSerialGuardSetting"              (documented top-level policy;
//     preserved at the package's own shipped default value, unrelated to
//     posture — not something this feature is trying to change)
//   - "DisableTelemetry"                       (documented top-level policy)
//   - "DNSOverHTTPS": {Enabled, Locked}        (documented top-level policy;
//     forced off because nyx-dns already owns DNS enforcement at the OS
//     level, so the browser running its own separate DoH resolver would be
//     a bypass of that, not a second layer of it)
//   - "Preferences": {<pref>: {Value, Status}} (documented generic pref-lock
//     mechanism, used here for `media.peerconnection.enabled` = false to
//     disable WebRTC, and for Paranoid, `browser.privatebrowsing.autostart`
//     = true — the exact pref backing Firefox-family browsers' own "Always
//     use private browsing mode" setting)
//   - "PasswordManagerEnabled"                 (documented top-level policy;
//     Paranoid only)
// Written to `/opt/zen-browser-bin/distribution/policies.json` — the real
// path this specific AUR package (a prebuilt tarball release under /opt,
// not a system-package layout with an /etc/<vendor>/policies.json
// convention) reads its policy from; confirmed against the package's own
// PKGBUILD, which uses this exact mechanism itself to ship
// `DisableAppUpdate`/`DefaultSerialGuardSetting` defaults. There is no
// merging across multiple policy files — whatever this feature writes here
// fully replaces the package's own shipped file, which is why both of its
// original keys are carried forward explicitly below rather than dropped.
// ---------------------------------------------------------------------------

const STANDARD_POLICY_JSON: &str = r#"{
  "policies": {
    "DisableAppUpdate": true,
    "DefaultSerialGuardSetting": 3,
    "DisableTelemetry": true,
    "DNSOverHTTPS": {
      "Enabled": false,
      "Locked": true
    }
  }
}
"#;

const MEDIUM_POLICY_JSON: &str = r#"{
  "policies": {
    "DisableAppUpdate": true,
    "DefaultSerialGuardSetting": 3,
    "DisableTelemetry": true,
    "DNSOverHTTPS": {
      "Enabled": false,
      "Locked": true
    },
    "Preferences": {
      "media.peerconnection.enabled": {
        "Value": false,
        "Status": "locked"
      }
    }
  }
}
"#;

const PARANOID_POLICY_JSON: &str = r#"{
  "policies": {
    "DisableAppUpdate": true,
    "DefaultSerialGuardSetting": 3,
    "DisableTelemetry": true,
    "DNSOverHTTPS": {
      "Enabled": false,
      "Locked": true
    },
    "Preferences": {
      "media.peerconnection.enabled": {
        "Value": false,
        "Status": "locked"
      },
      "browser.privatebrowsing.autostart": {
        "Value": true,
        "Status": "locked"
      }
    },
    "PasswordManagerEnabled": false
  }
}
"#;

/// Every non-loopback interface `nyx-identity` currently reports. Empty
/// (rather than an error) if the daemon can't be reached — the resulting
/// workflow just skips MAC randomization and says why, instead of failing
/// the whole posture over a step that turned out to have nothing to do.
fn discover_interfaces() -> Vec<String> {
    match client::call::<IdentityCommand, NyxOutput<IdentityReport>>(
        IDENTITY_SOCKET,
        &IdentityCommand::Status,
    ) {
        Ok(out) => out
            .data
            .map(|r| r.interfaces.into_iter().map(|i| i.interface).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Whether a VPN is connected AND verified (handshake/route), not merely
/// "a connect command was issued at some point" — same real check
/// `VpnReport.state == Protected` means everywhere else in this codebase.
fn vpn_is_protected() -> bool {
    matches!(
        client::call::<VpnCommand, NyxOutput<VpnReport>>(VPN_SOCKET, &VpnCommand::Status),
        Ok(out) if out.data.as_ref().map(|d| d.state) == Some(SecurityState::Protected)
    )
}

pub fn build(posture: Posture) -> Workflow {
    match posture {
        Posture::Standard => build_standard(),
        Posture::Medium => build_medium(),
        Posture::Paranoid => build_paranoid(),
    }
}

fn intro_step(text: &'static str) -> Step {
    Step {
        description: text,
        cmd: WorkflowCommand::Message(text.to_string()),
        condition: Condition::Always,
        danger: DangerLevel::Safe,
        confirm: false,
        rollback_hint: STATUS_ROLLBACK,
    }
}

fn build_standard() -> Workflow {
    Workflow {
        id: Posture::Standard.id(),
        description: Posture::Standard.description(),
        steps: vec![
            intro_step(
                "Standard posture: kill switch off, minimal browser policy, nothing else touched.",
            ),
            Step {
                description: "Kill switch off",
                cmd: WorkflowCommand::HealthKillSwitch { level: KillSwitchLevel::Off },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Set the kill switch directly via nyx-health or the dashboard.",
            },
            Step {
                description: "Confirm kill switch state took effect",
                cmd: WorkflowCommand::HealthStatus,
                condition: Condition::IfSuccess,
                danger: DangerLevel::Safe,
                confirm: false,
                rollback_hint: STATUS_ROLLBACK,
            },
            Step {
                description: "Apply Standard Zen Browser policy (telemetry off, browser DoH off \
                               so nyx-dns stays the only resolver — everything else default)",
                cmd: WorkflowCommand::ApplyBrowserPolicy {
                    label: "Standard",
                    policy_json: STANDARD_POLICY_JSON,
                },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Re-run this posture, or hand-edit /opt/zen-browser-bin/distribution/policies.json.",
            },
        ],
    }
}

/// Shared Medium-tier identity/device steps, reused verbatim by Paranoid
/// (which is explicitly "everything Medium does, plus...").
fn medium_steps() -> Vec<Step> {
    let mut steps = vec![
        Step {
            description: "Disable IPv6 system-wide",
            cmd: WorkflowCommand::IdentitySetIpv6 { enabled: false },
            condition: Condition::Always,
            danger: DangerLevel::Medium,
            confirm: false,
            rollback_hint: "Restore via IdentityCommand::SetIpv6{enabled:true} through nyx-identity.",
        },
        Step {
            description: "Confirm identity state (IPv6, interfaces) took effect",
            cmd: WorkflowCommand::IdentityStatus,
            condition: Condition::IfSuccess,
            danger: DangerLevel::Safe,
            confirm: false,
            rollback_hint: STATUS_ROLLBACK,
        },
    ];

    let interfaces = discover_interfaces();
    if interfaces.is_empty() {
        steps.push(Step {
            description: "No interfaces reported by nyx-identity — nothing to randomize",
            cmd: WorkflowCommand::IdentityStatus,
            condition: Condition::Always,
            danger: DangerLevel::Safe,
            confirm: false,
            rollback_hint: STATUS_ROLLBACK,
        });
    } else {
        for interface in interfaces {
            steps.push(Step {
                description: "Randomize MAC address on a detected interface",
                cmd: WorkflowCommand::IdentityRandomizeMac { interface },
                condition: Condition::Always,
                danger: DangerLevel::Low,
                confirm: false,
                rollback_hint: "Restore via IdentityCommand::RestoreMac for that interface through nyx-identity.",
            });
        }
    }

    steps.push(Step {
        description: "Randomize hostname",
        cmd: WorkflowCommand::IdentityRandomizeHostname,
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Restore via IdentityCommand::RestoreHostname through nyx-identity.",
    });

    steps.push(Step {
        description: "Ensure USBGuard is running and enforcing",
        cmd: WorkflowCommand::DevicesSetUsbGuard { enabled: true },
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Disable via DevicesCommand::SetUsbGuard{enabled:false} through nyx-devices.",
    });

    steps.push(Step {
        description: "Confirm device state (USBGuard policy) took effect",
        cmd: WorkflowCommand::DevicesStatus,
        condition: Condition::IfSuccess,
        danger: DangerLevel::Safe,
        confirm: false,
        rollback_hint: STATUS_ROLLBACK,
    });

    steps
}

fn build_medium() -> Workflow {
    let mut steps = vec![intro_step(
        "Medium posture: kill switch Soft, IPv6 off, MAC/hostname randomized, USBGuard enforced. \
         Webcam, microphone, and Bluetooth are left alone.",
    )];

    steps.push(Step {
        description: "Kill switch to Soft",
        cmd: WorkflowCommand::HealthKillSwitch { level: KillSwitchLevel::Soft },
        condition: Condition::Always,
        danger: DangerLevel::Medium,
        confirm: false,
        rollback_hint: "Set the kill switch directly via nyx-health or the dashboard.",
    });
    steps.push(Step {
        description: "Confirm kill switch state took effect",
        cmd: WorkflowCommand::HealthStatus,
        condition: Condition::IfSuccess,
        danger: DangerLevel::Safe,
        confirm: false,
        rollback_hint: STATUS_ROLLBACK,
    });

    steps.extend(medium_steps());

    steps.push(Step {
        description: "Apply Medium Zen Browser policy (telemetry off, browser DoH off, WebRTC disabled)",
        cmd: WorkflowCommand::ApplyBrowserPolicy { label: "Medium", policy_json: MEDIUM_POLICY_JSON },
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Re-run this posture, or hand-edit /opt/zen-browser-bin/distribution/policies.json.",
    });

    Workflow { id: Posture::Medium.id(), description: Posture::Medium.description(), steps }
}

fn build_paranoid() -> Workflow {
    let vpn_protected = vpn_is_protected();

    let mut steps = vec![intro_step(
        "Paranoid posture: everything Medium does, plus timezone randomized and \
         webcam/mic/USB-storage/Bluetooth forced off, then the kill switch is Armed.",
    )];

    steps.extend(medium_steps());

    steps.push(Step {
        description: "Randomize timezone",
        cmd: WorkflowCommand::IdentityRandomizeTimezone,
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Restore via IdentityCommand::RestoreTimezone through nyx-identity.",
    });
    steps.push(Step {
        description: "Force webcam off",
        cmd: WorkflowCommand::DevicesSetModule { module: DeviceModule::Webcam, enabled: false },
        condition: Condition::Always,
        danger: DangerLevel::Medium,
        confirm: false,
        rollback_hint: "Re-enable via DevicesCommand::SetModule{module: Webcam, enabled:true} through nyx-devices.",
    });
    steps.push(Step {
        description: "Force USB mass-storage off",
        cmd: WorkflowCommand::DevicesSetModule { module: DeviceModule::UsbStorage, enabled: false },
        condition: Condition::Always,
        danger: DangerLevel::Medium,
        confirm: false,
        rollback_hint: "Re-enable via DevicesCommand::SetModule{module: UsbStorage, enabled:true} through nyx-devices.",
    });
    steps.push(Step {
        description: "Mute the default microphone",
        cmd: WorkflowCommand::DevicesSetMicrophone { enabled: false },
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Unmute via DevicesCommand::SetMicrophone{enabled:true} through nyx-devices.",
    });
    steps.push(Step {
        description: "Turn Bluetooth radio off",
        cmd: WorkflowCommand::DevicesSetRadio { radio: DeviceRadio::Bluetooth, on: false },
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Re-enable via DevicesCommand::SetRadio{radio: Bluetooth, on:true} through nyx-devices.",
    });

    steps.push(Step {
        description: "Apply Paranoid Zen Browser policy (telemetry/DoH/WebRTC off, private-browsing-only, \
                       password saving disabled)",
        cmd: WorkflowCommand::ApplyBrowserPolicy { label: "Paranoid", policy_json: PARANOID_POLICY_JSON },
        condition: Condition::Always,
        danger: DangerLevel::Low,
        confirm: false,
        rollback_hint: "Re-run this posture, or hand-edit /opt/zen-browser-bin/distribution/policies.json.",
    });

    // Same interactive-confirmation UX `emergency-lockdown`/`kill-switch-drill`
    // already use for a disruptive action — not a new pattern.
    let confirm_text = if vpn_protected {
        "About to Arm the kill switch. A VPN is connected and verified (handshake/route), so \
         Armed traffic still has a route out through it. Continue?"
            .to_string()
    } else {
        "About to Arm the kill switch. No VPN is currently connected and verified — Arming now \
         will cut off ALL network traffic except loopback with no tunnel to fall back on, until \
         you set the kill switch to Off again. Continue anyway?"
            .to_string()
    };
    steps.push(Step {
        description: "Operator confirmation before Arming the kill switch",
        cmd: WorkflowCommand::Confirm(confirm_text),
        condition: Condition::Always,
        danger: DangerLevel::Critical,
        confirm: false,
        rollback_hint: "Declining this step does nothing — the kill switch has not been touched yet.",
    });
    steps.push(Step {
        description: "Kill switch to Armed",
        cmd: WorkflowCommand::HealthKillSwitch { level: KillSwitchLevel::Armed },
        condition: Condition::IfSuccess,
        danger: DangerLevel::Critical,
        confirm: false,
        rollback_hint: "Set the kill switch to Off via nyx-health or the dashboard to undo — no daemon restart needed.",
    });
    steps.push(Step {
        description: "Confirm kill switch state took effect",
        cmd: WorkflowCommand::HealthStatus,
        condition: Condition::IfSuccess,
        danger: DangerLevel::Safe,
        confirm: false,
        rollback_hint: STATUS_ROLLBACK,
    });

    Workflow { id: Posture::Paranoid.id(), description: Posture::Paranoid.description(), steps }
}
