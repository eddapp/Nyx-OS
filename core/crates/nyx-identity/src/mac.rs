//! MAC address control via NetworkManager, not raw `macchanger`. NM already
//! owns interface lifecycle on this system (it's the only network manager
//! NyxOS ships) — fighting it with a tool that doesn't know about NM's own
//! connection profiles just means NM silently reapplies the real address on
//! the next reconnect. `cloned-mac-address` is NM's own supported knob for
//! exactly this, including the literal value `permanent` for "use the
//! hardware's real, burned-in address" — which is also why restoring needs
//! no stored state at all.

use nyx_core::{NyxError, NyxResult};
use std::process::Command;

fn run(args: &[&str]) -> NyxResult<String> {
    let output = Command::new("nmcli")
        .args(args)
        .output()
        .map_err(|e| NyxError::Network(format!("failed to spawn nmcli: {e}")))?;
    if !output.status.success() {
        return Err(NyxError::Network(format!(
            "nmcli {} exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn tabular(args: &[&str]) -> Vec<String> {
    run(args).map(|s| s.lines().map(str::to_string).collect()).unwrap_or_default()
}

/// Every non-loopback interface NetworkManager knows about, with its
/// current MAC — a live read, not whatever this daemon last set.
pub fn interfaces() -> Vec<(String, Option<String>)> {
    tabular(&["-t", "-f", "DEVICE", "device", "status"])
        .into_iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty() && d != "lo")
        .map(|device| {
            let mac = current_mac(&device);
            (device, mac)
        })
        .collect()
}

pub fn current_mac(interface: &str) -> Option<String> {
    let out = run(&["-t", "-f", "GENERAL.HWADDR", "device", "show", interface]).ok()?;
    let mac = out
        .lines()
        .next()?
        .trim_start_matches("GENERAL.HWADDR:")
        .trim()
        .to_string();
    if mac.is_empty() {
        None
    } else {
        Some(mac)
    }
}

fn connection_for(interface: &str) -> NyxResult<String> {
    for line in tabular(&["-t", "-f", "NAME,DEVICE", "connection", "show", "--active"]) {
        let mut parts = line.splitn(2, ':');
        if let (Some(name), Some(dev)) = (parts.next(), parts.next())
            && dev == interface
        {
            return Ok(name.to_string());
        }
    }
    Err(NyxError::Network(format!(
        "no active NetworkManager connection on {interface}"
    )))
}

fn cloned_mac_property(interface: &str) -> NyxResult<&'static str> {
    for line in tabular(&["-t", "-f", "DEVICE,TYPE", "device", "status"]) {
        let mut parts = line.splitn(2, ':');
        if let (Some(dev), Some(kind)) = (parts.next(), parts.next())
            && dev == interface
        {
            return match kind {
                "wifi" => Ok("802-11-wireless.cloned-mac-address"),
                "ethernet" => Ok("802-3-ethernet.cloned-mac-address"),
                other => Err(NyxError::Network(format!(
                    "unsupported device type '{other}' for MAC control"
                ))),
            };
        }
    }
    Err(NyxError::Network(format!("unknown device type for {interface}")))
}

fn set_cloned_mac(interface: &str, value: &str) -> NyxResult<()> {
    let conn = connection_for(interface)?;
    let property = cloned_mac_property(interface)?;
    run(&["connection", "modify", &conn, property, value])?;
    let _ = run(&["connection", "down", &conn]); // best-effort; may already be down
    run(&["connection", "up", &conn])?;
    Ok(())
}

pub fn randomize(interface: &str) -> NyxResult<()> {
    set_cloned_mac(interface, "random")
}

pub fn restore(interface: &str) -> NyxResult<()> {
    set_cloned_mac(interface, "permanent")
}
