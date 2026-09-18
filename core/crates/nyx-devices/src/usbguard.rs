//! USBGuard integration — real device-authorization enforcement, not a
//! cosmetic switch. Lifecycle via systemd D-Bus; posture via USBGuard's own
//! configured policy, read from disk rather than assumed from "the service
//! is running".

use crate::systemd_ctl;
use nyx_core::NyxResult;
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
