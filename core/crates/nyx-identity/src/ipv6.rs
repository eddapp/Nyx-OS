//! System-wide IPv6 control via `sysctl`, persisted under `/etc/sysctl.d/`
//! so the setting survives reboot rather than only lasting until the next
//! one. Disabled is NyxOS's own recommended default — IPv6 can route
//! around a VPN/Tor tunnel that only redirects IPv4, which is a real leak
//! path, not a hypothetical one.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::process::Command;

const SYSCTL_DROPIN: &str = "/etc/sysctl.d/99-nyx-ipv6.conf";
const KEYS: &[&str] = &["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"];

pub fn enabled() -> Option<bool> {
    let output = Command::new("sysctl").args(["-n", KEYS[0]]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "0" => Some(true),
        "1" => Some(false),
        _ => None,
    }
}

pub fn set(enable: bool) -> NyxResult<()> {
    let value = if enable { "0" } else { "1" };
    for key in KEYS {
        let status = Command::new("sysctl")
            .arg("-w")
            .arg(format!("{key}={value}"))
            .status()
            .map_err(|e| NyxError::Config(format!("failed to spawn sysctl: {e}")))?;
        if !status.success() {
            return Err(NyxError::Config(format!("sysctl -w {key}={value} exited with {status}")));
        }
    }

    let contents = format!(
        "# Managed by nyx-identity — do not edit by hand.\n{} = {value}\n{} = {value}\n",
        KEYS[0], KEYS[1]
    );
    fs::write(SYSCTL_DROPIN, contents)?;
    Ok(())
}
