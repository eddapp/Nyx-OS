//! Shared systemd drop-in machinery for VPN-over-Tor chaining
//! (`VpnCommand::ConnectViaSocksProxy`) — used by the three backends that
//! actually honor it: `openvpn.rs`, `xray.rs`, `shadowsocks.rs`. See each
//! module's own doc comment for why WireGuard/AmneziaWG/Hysteria2/SOCKS5
//! don't.
//!
//! A drop-in overrides only `ExecStart` on that one profile's unit
//! instance, leaving everything else the vendor/nyx-owned unit already
//! sets (capabilities, `WorkingDirectory`, restart policy, ...) untouched
//! — and leaves the user's own profile file on disk exactly as they wrote
//! it; any config that needs to change (Xray/Shadowsocks) is written to a
//! separate runtime-only copy instead. The override is removed again on
//! disconnect so a later plain `Connect` doesn't silently keep dialing
//! through whatever proxy was last used.

use nyx_core::{NyxError, NyxResult};
use std::fs;

/// Where nyx-vpn stages runtime-only files it generates itself (derived
/// Xray/Shadowsocks configs with a Tor outbound spliced in) — never the
/// profile's own directory, so the user's original file is never touched.
pub const RUNTIME_DIR: &str = "/run/nyx";

const DROPIN_FILENAME: &str = "nyx-vpn-socks-proxy.conf";

fn dropin_dir(unit: &str) -> String {
    format!("/etc/systemd/system/{unit}.d")
}

/// `ExecStart=` is not appended to by a drop-in — `systemd.service(5)`
/// documents that assigning the empty string first resets the list of
/// commands to start, with prior assignments (the vendor/nyx-owned unit's
/// own `ExecStart=`) having no effect, so a real override needs that empty
/// assignment before the replacement one.
pub fn write_exec_start_override(unit: &str, exec_start: &str) -> NyxResult<()> {
    let dir = dropin_dir(unit);
    fs::create_dir_all(&dir).map_err(|e| NyxError::Config(format!("creating {dir}: {e}")))?;
    let contents = format!("[Service]\nExecStart=\nExecStart={exec_start}\n");
    fs::write(format!("{dir}/{DROPIN_FILENAME}"), contents)
        .map_err(|e| NyxError::Config(format!("writing socks-proxy override for {unit}: {e}")))
}

/// Best-effort — an absent override is not an error, it just means this
/// unit wasn't chained through a proxy last time.
pub fn remove_exec_start_override(unit: &str) {
    let _ = fs::remove_file(format!("{}/{DROPIN_FILENAME}", dropin_dir(unit)));
}
