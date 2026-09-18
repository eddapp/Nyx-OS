//! Generic recurring-task scheduler, built on real systemd timers — the
//! native Linux primitive for "run this again every N seconds", not a
//! busy-loop or a cron dependency (per `systemd.timer(5)`, a timer unit
//! plus a paired `Type=oneshot` service is a first-class systemd
//! mechanism, and the timer keeps firing across reboots on its own once
//! enabled — nothing needs to stay resident for it to work).
//!
//! Wired to already-existing, already-bounded one-shot Nyx operations — no
//! new destructive capability is introduced in *this* file:
//!
//! - `wipe-shell-history` / `wipe-tmp` / `wipe-thumbnails` /
//!   `wipe-recent-files` / `wipe-logs` -> `nyx-wipe execute --yes <target>`
//!   for one of `nyx-wipe`'s five original, well-bounded `WipeTarget`
//!   categories.
//! - `wipe-free-space` / `shred-documents` / `shred-downloads` /
//!   `shred-desktop` -> `nyx-wipe execute --yes <target>` for the four
//!   newer, more dangerous `WipeTarget` categories a separate change added
//!   directly to `nyx-wipe` (real `sfill`/recursive `srm -r`, both
//!   genuinely slow and irreversible). This scheduler only ever invokes
//!   `nyx-wipe`'s own already-bounded named categories, exactly like the
//!   five above — it still never reaches an arbitrary path, and still
//!   never touches `nyx-wipe`'s `--path`/`--all` machinery.
//! - `randomize-mac` -> `nyx-identity`'s `IdentityCommand::RandomizeMac`,
//!   sent over `IDENTITY_SOCKET` (see `client.rs`).
//! - `lock-screen` -> `i3lock` directly, run as the logged-in desktop
//!   user via a `systemd --user` unit (see [`ScheduleTask::is_user_scope`]
//!   for why).
//! - `renew-tor-circuit` -> `nyx-health`'s `HealthCommand::TorRestart`,
//!   sent over `HEALTH_SOCKET`.

mod client;

use clap::ValueEnum;
use nyx_core::{
    HealthCommand, HealthState, IdentityCommand, IdentityReport, NyxError, NyxOutput, NyxResult,
    Status, HEALTH_SOCKET, IDENTITY_SOCKET,
};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const SYSTEM_UNIT_DIR: &str = "/usr/lib/systemd/system";
const USER_UNIT_DIR: &str = "/usr/lib/systemd/user";
/// Real path this binary is installed to by `install/pkgbuild/nyx-hardening/
/// PKGBUILD` (`$pkgdir/usr/bin/nyx-hardening`) — the exact `ExecStart=` used
/// for the two daemon-backed tasks, which re-invoke this same binary in
/// `schedule exec` mode so their generated service units don't need any
/// socket-speaking logic of their own.
const SELF_BIN: &str = "/usr/bin/nyx-hardening";
/// Real path `install/pkgbuild/nyx-wipe/PKGBUILD` installs `nyx-wipe` to.
const NYX_WIPE_BIN: &str = "/usr/bin/nyx-wipe";
/// Real path of the `i3lock` binary this ISO already depends on
/// (`iso/packages.x86_64`, `install/pkgbuild/nyx-desktop-sessions/PKGBUILD`)
/// — confirmed present on this system via `pacman -Ql i3lock`.
const I3LOCK_BIN: &str = "/usr/bin/i3lock";

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ScheduleTask {
    WipeShellHistory,
    WipeTmp,
    WipeThumbnails,
    WipeRecentFiles,
    WipeLogs,
    WipeFreeSpace,
    ShredDocuments,
    ShredDownloads,
    ShredDesktop,
    RandomizeMac,
    LockScreen,
    RenewTorCircuit,
}

impl ScheduleTask {
    pub const ALL: [ScheduleTask; 12] = [
        ScheduleTask::WipeShellHistory,
        ScheduleTask::WipeTmp,
        ScheduleTask::WipeThumbnails,
        ScheduleTask::WipeRecentFiles,
        ScheduleTask::WipeLogs,
        ScheduleTask::WipeFreeSpace,
        ScheduleTask::ShredDocuments,
        ScheduleTask::ShredDownloads,
        ScheduleTask::ShredDesktop,
        ScheduleTask::RandomizeMac,
        ScheduleTask::LockScreen,
        ScheduleTask::RenewTorCircuit,
    ];

    /// Stable task id — also the systemd unit name suffix
    /// (`nyx-schedule-<id>.{service,timer}`). Hardcoded rather than
    /// derived from `clap::ValueEnum` at runtime so the on-disk unit names
    /// this creates can never silently drift if the CLI's rename rule
    /// ever changes.
    pub fn id(&self) -> &'static str {
        match self {
            Self::WipeShellHistory => "wipe-shell-history",
            Self::WipeTmp => "wipe-tmp",
            Self::WipeThumbnails => "wipe-thumbnails",
            Self::WipeRecentFiles => "wipe-recent-files",
            Self::WipeLogs => "wipe-logs",
            Self::WipeFreeSpace => "wipe-free-space",
            Self::ShredDocuments => "shred-documents",
            Self::ShredDownloads => "shred-downloads",
            Self::ShredDesktop => "shred-desktop",
            Self::RandomizeMac => "randomize-mac",
            Self::LockScreen => "lock-screen",
            Self::RenewTorCircuit => "renew-tor-circuit",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::WipeShellHistory => "wipe shell history (nyx-wipe execute --yes shell-history)",
            Self::WipeTmp => "wipe /tmp (nyx-wipe execute --yes tmp)",
            Self::WipeThumbnails => "wipe thumbnail cache (nyx-wipe execute --yes thumbnails)",
            Self::WipeRecentFiles => "wipe recent-files lists (nyx-wipe execute --yes recent-files)",
            Self::WipeLogs => "wipe/vacuum logs (nyx-wipe execute --yes logs)",
            Self::WipeFreeSpace => {
                "wipe free disk space with sfill (nyx-wipe execute --yes free-space) -- slow, \
                 can take a long time to complete"
            }
            Self::ShredDocuments => {
                "securely shred the contents of every local user's Documents folder (nyx-wipe \
                 execute --yes shred-documents) -- irreversible"
            }
            Self::ShredDownloads => {
                "securely shred the contents of every local user's Downloads folder (nyx-wipe \
                 execute --yes shred-downloads) -- irreversible"
            }
            Self::ShredDesktop => {
                "securely shred the contents of every local user's Desktop folder (nyx-wipe \
                 execute --yes shred-desktop) -- irreversible"
            }
            Self::RandomizeMac => "randomize a network interface's MAC address",
            Self::LockScreen => "lock the screen",
            Self::RenewTorCircuit => "restart tor.service to force fresh circuits",
        }
    }

    fn wipe_target(&self) -> Option<&'static str> {
        match self {
            Self::WipeShellHistory => Some("shell-history"),
            Self::WipeTmp => Some("tmp"),
            Self::WipeThumbnails => Some("thumbnails"),
            Self::WipeRecentFiles => Some("recent-files"),
            Self::WipeLogs => Some("logs"),
            Self::WipeFreeSpace => Some("free-space"),
            Self::ShredDocuments => Some("shred-documents"),
            Self::ShredDownloads => Some("shred-downloads"),
            Self::ShredDesktop => Some("shred-desktop"),
            _ => None,
        }
    }

    /// `lock-screen` is the one task here that must run as the logged-in
    /// desktop user against that user's own X11 session, not as root —
    /// same reasoning `nyx-clipboard-clear` documents for itself
    /// (`core/crates/nyx-hardening/src/bin/nyx-clipboard-clear.rs`): a
    /// screen locker needs the user's own `DISPLAY`/`XAUTHORITY`, and
    /// `i3lock` run as root against another user's X session doesn't
    /// work. So this task's unit pair is installed as a `systemd --user`
    /// unit (`/usr/lib/systemd/user/`) rather than a system unit, and
    /// enabled with `systemctl --global enable` — the real, documented
    /// `systemctl(1)` mechanism for "every user's own systemd --user
    /// instance runs this from now on", which needs no active D-Bus
    /// session for a specific uid the way targeting one logged-in user's
    /// session from a root process would.
    pub fn is_user_scope(&self) -> bool {
        matches!(self, Self::LockScreen)
    }

    /// The real `ExecStart=` line for this task. `interface` is required
    /// (and only meaningful) for `randomize-mac`.
    pub fn exec_start(&self, interface: Option<&str>) -> Result<String, String> {
        match self {
            Self::LockScreen => Ok(I3LOCK_BIN.to_string()),
            Self::RandomizeMac => {
                let iface = interface
                    .ok_or_else(|| "randomize-mac requires --interface <name>".to_string())?;
                Ok(format!("{SELF_BIN} schedule exec randomize-mac --interface {iface}"))
            }
            Self::RenewTorCircuit => Ok(format!("{SELF_BIN} schedule exec renew-tor-circuit")),
            _ => {
                let target = self.wipe_target().expect("every non-daemon-backed task is a wipe target");
                Ok(format!("{NYX_WIPE_BIN} execute --yes {target}"))
            }
        }
    }
}

fn unit_dir(task: ScheduleTask) -> &'static str {
    if task.is_user_scope() { USER_UNIT_DIR } else { SYSTEM_UNIT_DIR }
}

fn unit_base(task: ScheduleTask) -> String {
    format!("nyx-schedule-{}", task.id())
}

fn service_path(task: ScheduleTask) -> String {
    format!("{}/{}.service", unit_dir(task), unit_base(task))
}

fn timer_path(task: ScheduleTask) -> String {
    format!("{}/{}.timer", unit_dir(task), unit_base(task))
}

/// Where `systemctl enable`/`--global enable` actually places the
/// `[Install] WantedBy=timers.target` symlink for this unit — real path
/// per `systemd.unit(5)`'s unit-search-path table (`/etc/systemd/system`
/// is "unit configuration created by the administrator" for the system
/// manager, `/etc/systemd/user` is the same for the per-user manager, and
/// enabling writes a `<target>.wants/<unit>` symlink under whichever of
/// those applies).
fn enablement_symlink(task: ScheduleTask) -> String {
    let base = unit_base(task);
    if task.is_user_scope() {
        format!("/etc/systemd/user/timers.target.wants/{base}.timer")
    } else {
        format!("/etc/systemd/system/timers.target.wants/{base}.timer")
    }
}

fn service_unit_content(task: ScheduleTask, exec_start: &str) -> String {
    format!(
        "[Unit]\nDescription=NyxOS scheduled task -- {}\n\n[Service]\nType=oneshot\nExecStart={}\n",
        task.description(),
        exec_start,
    )
}

/// `OnActiveSec=`+`OnUnitActiveSec=`, both set to the same interval, is
/// the standard "run every N seconds, starting shortly after the timer is
/// enabled" recipe (`systemd.timer(5)`): `OnActiveSec=` fires the first
/// run relative to when the timer itself starts, `OnUnitActiveSec=` fires
/// every run after that relative to the previous run. `OnCalendar=` was
/// deliberately not used — that's for wall-clock/calendar schedules
/// ("every day at 03:00"), not the plain "every N seconds" interval this
/// CLI takes. `Persistent=` was deliberately left out too: per
/// `systemd.timer(5)`, "this setting only has an effect on timers
/// configured with OnCalendar=", so setting it here would be a no-op
/// dressed up as a real guarantee.
fn timer_unit_content(task: ScheduleTask, interval_secs: u64) -> String {
    format!(
        "[Unit]\nDescription=NyxOS scheduled task timer -- {}\n\n[Timer]\nOnActiveSec={interval}s\nOnUnitActiveSec={interval}s\n\n[Install]\nWantedBy=timers.target\n",
        task.description(),
        interval = interval_secs,
    )
}

fn which(bin: &str) -> bool {
    Path::new(bin).is_file()
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

fn write_unit(path: &str, content: &str) -> NyxResult<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

pub fn install(task: ScheduleTask, interval_secs: u64, interface: Option<&str>) -> NyxResult<()> {
    if interval_secs == 0 {
        return Err(NyxError::Config("--interval-secs must be greater than 0".into()));
    }

    let exec_start = task.exec_start(interface).map_err(NyxError::Config)?;

    if task.wipe_target().is_some() && !which(NYX_WIPE_BIN) {
        return Err(NyxError::Config(format!("{NYX_WIPE_BIN} not found -- install nyx-wipe first")));
    }
    if task == ScheduleTask::LockScreen && !which(I3LOCK_BIN) {
        return Err(NyxError::Config(format!("{I3LOCK_BIN} not found -- install i3lock first")));
    }

    write_unit(&service_path(task), &service_unit_content(task, &exec_start))?;
    write_unit(&timer_path(task), &timer_unit_content(task, interval_secs))?;

    let base = unit_base(task);
    if task.is_user_scope() {
        // No `--now`: `--global` operates on every user's *future* login,
        // not a specific already-running session's D-Bus bus, and
        // `systemctl(1)` documents that a `--global` enable does not
        // reload/start anything live. Targeting one already-logged-in
        // user's session from a root process would need guessing which
        // uid/session that is, which this deliberately doesn't do.
        run("systemctl", &["--global", "enable", &format!("{base}.timer")])?;
    } else {
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", &format!("{base}.timer")])?;
    }
    Ok(())
}

pub fn remove(task: ScheduleTask) -> NyxResult<bool> {
    let svc = service_path(task);
    let tmr = timer_path(task);
    if !Path::new(&svc).exists() && !Path::new(&tmr).exists() {
        return Ok(false);
    }

    let base = unit_base(task);
    if task.is_user_scope() {
        let _ = run("systemctl", &["--global", "disable", &format!("{base}.timer")]);
    } else {
        let _ = run("systemctl", &["disable", "--now", &format!("{base}.timer")]);
    }

    let _ = fs::remove_file(&svc);
    let _ = fs::remove_file(&tmr);

    if !task.is_user_scope() {
        run("systemctl", &["daemon-reload"])?;
    }
    Ok(true)
}

#[derive(Serialize, Clone)]
pub struct TaskStatus {
    pub task: String,
    pub scope: &'static str,
    pub installed: bool,
    pub enabled: bool,
    pub interval_secs: Option<u64>,
}

/// Real read of the installed timer unit's `OnUnitActiveSec=` line — not
/// a cached/assumed value, so `schedule status` always reflects whatever
/// is actually on disk right now.
fn read_interval(path: &str) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("OnUnitActiveSec=") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(secs) = digits.parse::<u64>() {
                return Some(secs);
            }
        }
    }
    None
}

pub fn status() -> Vec<TaskStatus> {
    ScheduleTask::ALL
        .iter()
        .map(|&task| {
            let tmr = timer_path(task);
            let svc = service_path(task);
            let installed = Path::new(&svc).exists() && Path::new(&tmr).exists();
            let enabled = Path::new(&enablement_symlink(task)).exists();
            let interval_secs = if installed { read_interval(&tmr) } else { None };
            TaskStatus {
                task: task.id().to_string(),
                scope: if task.is_user_scope() { "user" } else { "system" },
                installed,
                enabled,
                interval_secs,
            }
        })
        .collect()
}

/// The actual work run by the two daemon-backed tasks' `ExecStart=` —
/// invoked as `nyx-hardening schedule exec <task>` by the generated
/// service unit. `wipe-*`/`lock-screen` never reach here: their
/// `ExecStart=` calls `nyx-wipe`/`i3lock` directly.
pub fn exec(task: ScheduleTask, interface: Option<&str>) -> Result<String, String> {
    match task {
        ScheduleTask::RandomizeMac => {
            let iface = interface.ok_or("randomize-mac requires --interface <name>")?;
            let cmd = IdentityCommand::RandomizeMac { interface: iface.to_string() };
            let out = client::call::<IdentityCommand, NyxOutput<IdentityReport>>(IDENTITY_SOCKET, &cmd)?;
            if matches!(out.status, Status::Ok | Status::Warning) {
                Ok(out.message)
            } else {
                Err(out.message)
            }
        }
        ScheduleTask::RenewTorCircuit => {
            let out = client::call::<HealthCommand, NyxOutput<HealthState>>(
                HEALTH_SOCKET,
                &HealthCommand::TorRestart,
            )?;
            if matches!(out.status, Status::Ok | Status::Warning) {
                Ok(out.message)
            } else {
                Err(out.message)
            }
        }
        other => Err(format!("{} is not a daemon-backed task -- its ExecStart= runs directly", other.id())),
    }
}
