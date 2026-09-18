//! RAM-wipe-on-shutdown: installs a systemd unit that runs `sdmem -f`
//! (from the `secure-delete` package — confirmed available via the
//! `[blackarch]` repo this ISO already enables: `pacman -Si secure-delete`
//! reports `Repository: blackarch`) immediately before poweroff.
//!
//! Unit ordering verified against `systemd.special(7)`: `final.target` is
//! documented as the target that "may be used to pull in late services
//! after all normal services are already terminated and all mounts
//! unmounted", and the documented way to hook a one-shot into it is
//! `WantedBy=final.target` (so it gets pulled in) plus `Before=final.target`
//! (so it must finish before that point is considered reached) — which is
//! about as close to "the moment right before the actual power-off" as a
//! systemd unit can get.
//!
//! Honest limitation, also embedded in the unit's own `Description=`:
//! `sdmem` can only overwrite memory the kernel currently reports as
//! *free* at the moment it runs. Anything still resident to a running
//! process — this late in shutdown, mostly the kernel itself, PID 1, and
//! whatever's left of this unit's own process — is by definition in use
//! and cannot be safely overwritten out from under itself; there is no
//! way to scrub memory a process is actively using while it's using it.
//! This is a real, useful reduction in what a cold-boot RAM dump could
//! recover after poweroff, not a guarantee that every secret is gone. It
//! also adds real wall-clock time to shutdown, roughly proportional to
//! installed RAM size, since `sdmem` has to actually write to it.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub const UNIT_PATH: &str = "/etc/systemd/system/nyx-ram-wipe.service";
const UNIT_NAME: &str = "nyx-ram-wipe.service";

pub const UNIT_CONTENT: &str = "\
[Unit]
Description=NyxOS best-effort overwrite of free RAM before poweroff via sdmem -f -- only \
memory the kernel reports as free at the moment this runs is scrubbed, memory still allocated \
to running processes cannot be touched, and this adds real time to shutdown proportional to \
installed RAM size
Documentation=man:sdmem(1)
DefaultDependencies=no
After=umount.target
Before=final.target

[Service]
Type=oneshot
ExecStart=/usr/bin/sdmem -f
TimeoutStartSec=600
RemainAfterExit=no

[Install]
WantedBy=final.target
";

fn which(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    path.to_string_lossy()
        .split(':')
        .any(|dir| Path::new(dir).join(bin).is_file())
}

fn run(cmd: &str, args: &[&str]) -> NyxResult<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| NyxError::Config(format!("failed to spawn {cmd}: {e}")))?;
    if !status.success() {
        return Err(NyxError::Config(format!("{cmd} {} exited with {status}", args.join(" "))));
    }
    Ok(())
}

pub fn install() -> NyxResult<()> {
    if !which("sdmem") {
        return Err(NyxError::Config(
            "sdmem not found on PATH -- install the 'secure-delete' package (blackarch repo) \
             first: pacman -S secure-delete"
                .into(),
        ));
    }
    fs::write(UNIT_PATH, UNIT_CONTENT)?;
    fs::set_permissions(UNIT_PATH, fs::Permissions::from_mode(0o644))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", UNIT_NAME])?;
    Ok(())
}

pub fn remove() -> NyxResult<bool> {
    let path = Path::new(UNIT_PATH);
    if !path.exists() {
        return Ok(false);
    }
    let _ = run("systemctl", &["disable", UNIT_NAME]);
    fs::remove_file(path)?;
    run("systemctl", &["daemon-reload"])?;
    Ok(true)
}

pub fn is_installed() -> bool {
    Path::new(UNIT_PATH).exists()
}
