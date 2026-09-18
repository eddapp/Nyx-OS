//! WiFi via NetworkManager's own radio switch (`nmcli radio wifi`) rather
//! than raw `rfkill` — NM tracks radio-enabled state itself and a raw
//! rfkill toggle behind its back can leave its UI/state stale. Bluetooth
//! has no NetworkManager-level equivalent, so that one does go through
//! `rfkill` directly.

use nyx_core::{NyxError, NyxResult};
use std::process::Command;

pub fn wifi_enabled() -> Option<bool> {
    let output = Command::new("nmcli").args(["radio", "wifi"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "enabled" => Some(true),
        "disabled" => Some(false),
        _ => None,
    }
}

pub fn set_wifi(on: bool) -> NyxResult<()> {
    let value = if on { "on" } else { "off" };
    let status = Command::new("nmcli")
        .args(["radio", "wifi", value])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn nmcli: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("nmcli radio wifi {value} exited with {status}")));
    }
    Ok(())
}

/// `None` means no Bluetooth radio was found at all (nothing to report),
/// not "unknown state".
pub fn bluetooth_enabled() -> Option<bool> {
    let output = Command::new("rfkill").args(["list", "bluetooth"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        return None;
    }
    Some(!text.contains("Soft blocked: yes"))
}

pub fn set_bluetooth(on: bool) -> NyxResult<()> {
    let action = if on { "unblock" } else { "block" };
    let status = Command::new("rfkill")
        .args([action, "bluetooth"])
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn rfkill: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("rfkill {action} bluetooth exited with {status}")));
    }
    Ok(())
}
