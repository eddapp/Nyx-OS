//! USBGuard integration — real device-authorization enforcement, not a
//! cosmetic switch. Lifecycle via systemd D-Bus; posture via USBGuard's own
//! configured policy, read from disk rather than assumed from "the service
//! is running".

use crate::systemd_ctl;
use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::process::Command;
use zbus::Connection;

const UNIT: &str = "usbguard.service";
const RULES_PATH: &str = "/etc/usbguard/rules.conf";
const DAEMON_CONF: &str = "/etc/usbguard/usbguard-daemon.conf";

pub async fn is_active(conn: &Connection) -> Option<bool> {
    systemd_ctl::is_active(conn, UNIT).await.ok()
}

pub async fn set_enabled(conn: &Connection, enabled: bool) -> NyxResult<()> {
    if enabled {
        systemd_ctl::start_unit(conn, UNIT).await
    } else {
        systemd_ctl::stop_unit(conn, UNIT).await
    }
}

/// Reads the daemon's own configured default policy. `Some(true)` means
/// unrecognized devices are refused by default (`ImplicitPolicyTarget =
/// block`) — the property that actually makes USBGuard a security control
/// rather than a passive logger.
pub fn default_deny() -> Option<bool> {
    let contents = fs::read_to_string(DAEMON_CONF).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ImplicitPolicyTarget=") {
            return Some(value.trim() == "block");
        }
    }
    None
}

/// Raw rule lines from USBGuard's own policy file. "allow"-prefixed lines
/// are its whitelist; "block"/"reject" lines are explicit denials.
pub fn policy_lines() -> Vec<String> {
    fs::read_to_string(RULES_PATH)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Recent connect/disconnect activity from USBGuard's own journal output.
pub fn recent_history(limit: usize) -> Vec<String> {
    let output = Command::new("journalctl")
        .args(["-u", "usbguard", "--no-pager", "-o", "short-iso", "-n"])
        .arg(limit.to_string())
        .output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect()
        }
        _ => Vec::new(),
    }
}

/// Currently-connected devices from USBGuard's own live IPC view (`usbguard
/// list-devices`), not the static policy file — each line includes the
/// rule ID USBGuard assigned this connection, which `allow_device`/
/// `reject_device` take. Requires the daemon to actually be running and
/// the caller to be in its IPC-allowed group (root, here); an empty
/// result on failure is indistinguishable from "no devices connected", but
/// callers already treat `usbguard_active` as the source of truth for
/// whether USBGuard is reachable at all.
pub fn list_devices() -> Vec<String> {
    let output = Command::new("usbguard").args(["list-devices"]).output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect()
        }
        _ => Vec::new(),
    }
}

/// Interactively authorizes one currently-connected device by the rule ID
/// USBGuard assigned it (as listed by `list_devices`). `permanent: true`
/// also appends a matching rule to the policy file (`-p`) so the decision
/// survives replug/reboot; otherwise it's a one-time allow for this
/// connection only.
pub fn allow_device(id: &str, permanent: bool) -> NyxResult<()> {
    let mut args = vec!["allow-device", id];
    if permanent {
        args.push("-p");
    }
    let output = Command::new("usbguard")
        .args(&args)
        .output()
        .map_err(|e| NyxError::Config(format!("failed to spawn usbguard: {e}")))?;
    if !output.status.success() {
        return Err(NyxError::Config(format!(
            "usbguard allow-device {id} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Interactively rejects (disconnects) one currently-connected device by
/// its USBGuard-assigned rule ID.
pub fn reject_device(id: &str) -> NyxResult<()> {
    let output = Command::new("usbguard")
        .args(["reject-device", id])
        .output()
        .map_err(|e| NyxError::Config(format!("failed to spawn usbguard: {e}")))?;
    if !output.status.success() {
        return Err(NyxError::Config(format!(
            "usbguard reject-device {id} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
