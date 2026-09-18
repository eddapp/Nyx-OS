//! Shared launcher logic for NyxOS's four browser products: profile-path
//! resolution, tmpfs detection, and process exec/wait helpers. Every
//! binary in `src/bin/` is a thin, unprivileged, one-shot launcher meant
//! to run directly as the logged-in desktop user — no daemon, no socket,
//! matching this project's `nyx-diagnostics`/`nyx-wipe` CLI-tool pattern
//! rather than its resident-daemon pattern.

use nix::sys::statfs::{statfs, TMPFS_MAGIC};
use nix::unistd::{Uid, User};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolves the current user's home directory from `$HOME`, falling back
/// to an `/etc/passwd` (`getpwuid`) lookup if `$HOME` is unset or
/// relative. These launchers always run as the logged-in desktop user,
/// never root, so "current user" is always the right account to resolve.
pub fn home_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home);
        if path.is_absolute() {
            return path;
        }
    }
    User::from_uid(Uid::current())
        .ok()
        .flatten()
        .map(|u| u.dir)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// `$XDG_DATA_HOME`, falling back to `~/.local/share` per the XDG base
/// directory spec.
pub fn xdg_data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home_dir().join(".local/share"))
}

/// Creates (if missing) and returns the persistent Nyx profile directory
/// for one of the two persistent browsers — `name` is `"browser"` or
/// `"oniux"` — at `$XDG_DATA_HOME/nyx/browsers/<name>`, isolated from any
/// other Zen profile on the system.
///
/// A freshly created, empty directory is enough to hand to `-profile`:
/// Gecko self-initializes a full profile inside it on first launch (a
/// complete places.sqlite/cert9.db/key4.db/etc. tree appeared after one
/// `--profile <empty dir>` run during verification) — no separate
/// `-CreateProfile` step exists or is needed.
pub fn persistent_profile_dir(name: &str) -> io::Result<PathBuf> {
    let dir = xdg_data_home().join("nyx/browsers").join(name);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// True if `path` (which must already exist) is backed by tmpfs.
pub fn is_tmpfs(path: &Path) -> bool {
    statfs(path)
        .map(|s| s.filesystem_type() == TMPFS_MAGIC)
        .unwrap_or(false)
}

/// Picks a base directory for the disposable browser's ephemeral profile:
/// `$XDG_RUNTIME_DIR` if it's set and actually tmpfs, else `/tmp`. An
/// actual NyxOS live-boot target may mount `/tmp` differently than a given
/// dev sandbox does, so the tmpfs check is real, not assumed — see
/// `disposable_profile_dir`'s second return value.
fn disposable_base_dir() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(runtime_dir);
        if path.is_absolute() && is_tmpfs(&path) {
            return path;
        }
    }
    PathBuf::from("/tmp")
}

/// Creates and returns a fresh, unique ephemeral profile directory for the
/// disposable browser, plus whether its base directory is actually tmpfs
/// (so the caller can log an honest note when it isn't — `srm -r` still
/// secure-erases either way, just without tmpfs's extra "never touched a
/// real disk" property).
pub fn disposable_profile_dir() -> io::Result<(PathBuf, bool)> {
    let base = disposable_base_dir();
    let tmpfs = is_tmpfs(&base);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = base.join(format!("nyx-disposable-browser-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok((dir, tmpfs))
}

/// Replaces this process with `program` (resolved via `$PATH`) plus
/// `args` — the launched browser becomes the direct child of whatever
/// invoked this launcher (desktop menu, terminal, Thunar action) instead
/// of leaving a wrapper process sitting around. Only returns on failure.
pub fn exec_replace(program: &str, args: &[String]) -> io::Error {
    Command::new(program).args(args).exec()
}

/// Spawns `program` with `args` and waits for it to exit. Used only by
/// the disposable browser: unlike the other three launchers it has real
/// cleanup to do (secure-erasing the ephemeral profile) after the browser
/// process ends, so it can't exec-replace like they do.
pub fn spawn_and_wait(program: &str, args: &[String]) -> io::Result<ExitStatus> {
    let mut child: Child = Command::new(program).args(args).spawn()?;
    child.wait()
}

/// Securely erases `dir` with `srm -r` (from the already-shipped
/// `secure-delete` package) rather than a plain recursive remove — the
/// whole point of "disposable" is leaving no forensic trace. Deliberately
/// no `-f`: in `srm`, `-f` means "fast and insecure" (skips the
/// multi-pass overwrite), not "skip confirmation" — `srm` has no
/// interactive prompt to skip in the first place.
pub fn secure_delete_dir(dir: &Path) -> io::Result<ExitStatus> {
    Command::new("srm").arg("-r").arg(dir).status()
}

/// Prints a structured JSON error on stderr and exits 1 — same convention
/// `nyx-isolation`/`nyx-clipboard-clear` use.
pub fn fail(binary: &str, message: &str) -> ! {
    nyx_core::output::print_error(binary, "launch", message);
    std::process::exit(1);
}
