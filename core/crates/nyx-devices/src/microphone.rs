//! Microphone mute via `wpctl` (WirePlumber) — the actual audio server
//! NyxOS runs (PipeWire + WirePlumber, see `iso/packages.x86_64`). There is
//! no kernel module to unload without silencing every audio input path on
//! the system at once, so this is done at the audio-server level, on the
//! default source specifically.

use nyx_core::{NyxError, NyxResult};
use std::process::Command;

const TARGET: &str = "@DEFAULT_AUDIO_SOURCE@";

pub fn enabled() -> Option<bool> {
    let output = Command::new("wpctl").args(["get-volume", TARGET]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(!text.contains("[MUTED]"))
}

pub fn set(enabled: bool) -> NyxResult<()> {
    let value = if enabled { "0" } else { "1" };
    let status = Command::new("wpctl")
        .args(["set-mute", TARGET, value])
        .status()
        .map_err(|e| NyxError::Config(format!("failed to spawn wpctl: {e}")))?;
    if !status.success() {
        return Err(NyxError::Config(format!("wpctl set-mute exited with {status}")));
    }
    Ok(())
}
