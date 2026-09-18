//! Per-target planning and execution. Every target is destructive and
//! irreversible — nothing here is a "recycle bin". `plan()` and `execute()`
//! share the exact same candidate-collection code so a dry run can never
//! under- or over-promise what `execute()` will actually touch.

use crate::users;
use nyx_core::WipeTarget;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

pub struct Plan {
    pub files: Vec<PathBuf>,
    pub bytes: u64,
    pub warnings: Vec<String>,
}

/// Skip names that are live sockets/private runtime dirs other software
/// depends on, even though they live under /tmp — mirrors the exclusions
/// systemd-tmpfiles itself applies for the same reason.
const TMP_SKIP_PREFIXES: &[&str] = &[
    ".X11-unix",
    ".ICE-unix",
    ".font-unix",
    ".XIM-unix",
    ".Test-unix",
    "systemd-private-",
    ".xfsm",
];

/// Only files idle for at least this long are candidates in /tmp — avoids
/// deleting another process's in-use scratch file out from under it.
const TMP_MIN_AGE: Duration = Duration::from_secs(60 * 60);

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn shell_history_candidates() -> Vec<PathBuf> {
    const RELATIVE: &[&str] = &[
        ".bash_history",
        ".zsh_history",
        ".local/share/fish/fish_history",
        ".lesshst",
        ".python_history",
        ".mysql_history",
        ".psql_history",
    ];
    let mut out = Vec::new();
    for account in users::accounts() {
        tracing::debug!("shell_history: scanning {} ({})", account.name, account.home.display());
        for rel in RELATIVE {
            let path = account.home.join(rel);
            if path.is_file() {
                out.push(path);
            }
        }
    }
    out
}

fn tmp_candidates() -> Vec<PathBuf> {
    let now = SystemTime::now();
    let mut out = Vec::new();

    for dir in ["/tmp", "/var/tmp"] {
        let Ok(entries) = fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if TMP_SKIP_PREFIXES.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue; // never recurse into directories — too easy to hit live app state
            }
            let Ok(modified) = meta.modified() else { continue };
            let Ok(age) = now.duration_since(modified) else { continue };
            if age >= TMP_MIN_AGE {
                out.push(entry.path());
            }
        }
    }
    out
}

fn thumbnail_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for account in users::accounts() {
        tracing::debug!("thumbnails: scanning {} ({})", account.name, account.home.display());
        let dir = account.home.join(".cache/thumbnails");
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            if entry.metadata().map(|m| m.is_file()).unwrap_or(false) {
                out.push(entry.path());
            }
            // subdirectories (normal/, large/, fail/) are walked one level
            // deep, same reasoning as above — this cache has no other kind
            // of content, so a shallow recurse here is safe.
            if entry.metadata().map(|m| m.is_dir()).unwrap_or(false)
                && let Ok(inner) = fs::read_dir(entry.path())
            {
                for f in inner.flatten() {
                    if f.metadata().map(|m| m.is_file()).unwrap_or(false) {
                        out.push(f.path());
                    }
                }
            }
        }
    }
    out
}

fn recent_files_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for account in users::accounts() {
        let path = account.home.join(".local/share/recently-used.xbel");
        if path.is_file() {
            out.push(path);
        }
    }
    out
}

/// True if any block device on this system is rotational-storage-free, i.e.
/// an SSD/NVMe where overwriting file *contents* is not a reliable erasure
/// guarantee (wear-levelling and the flash translation layer can retain the
/// old bytes elsewhere on the device).
fn any_non_rotational_media() -> bool {
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return true; // can't tell — assume the worst case and warn anyway
    };
    for entry in entries.flatten() {
        let flag_path = entry.path().join("queue/rotational");
        if let Ok(content) = fs::read_to_string(&flag_path)
            && content.trim() == "0"
        {
            return true;
        }
    }
    false
}

fn ssd_caveat(warnings: &mut Vec<String>) {
    if any_non_rotational_media() {
        warnings.push(
            "at least one non-rotational (SSD/NVMe) block device was detected — deleting or \
             overwriting these files removes them from the filesystem, but the underlying flash \
             translation layer may retain the old bytes elsewhere on the device until it is \
             independently trimmed/erased; this is not a guaranteed secure erase"
                .to_string(),
        );
    }
}

// ---------------------------------------------------------------------------
// Arbitrary-path wipe — backs a Thunar "Secure Wipe" action and similar
// file-manager integrations, where the caller (not nyx-wipe) picks exactly
// which file(s) to destroy. This is a different shape from the fixed
// categories above: no discovery step, just a safety check on whatever was
// handed in.
// ---------------------------------------------------------------------------

/// Absolute paths that `path` mode refuses to touch — checked before any
/// confirmation, because a confirmation prompt on top of a bad path is not a
/// safety control. Exact matches only, not prefixes: deleting one file under
/// `/etc` is the caller's call to make, deleting `/etc` itself is not.
///
/// Deliberately NOT on this list: `/tmp`, `/var/tmp`, `/media`, `/mnt` — a
/// caller may legitimately want to wipe an entire scratch or removable-media
/// mount point outright.
const PROTECTED_ABSOLUTE_PATHS: &[&str] = &[
    "/", "/home", "/root", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt",
    "/var", "/proc", "/sys", "/dev", "/run", "/srv",
];

pub struct PathOutcome {
    /// Resolved (canonicalized) path when known, otherwise the raw input.
    pub path: PathBuf,
    pub bytes: u64,
    /// Set means this entry was refused and will not be touched, no matter
    /// what `execute_paths` is asked to do.
    pub refused: Option<String>,
}

fn check_path(input: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(input).map_err(|e| format!("cannot resolve: {e}"))?;

    if PROTECTED_ABSOLUTE_PATHS
        .iter()
        .any(|p| canonical == Path::new(p))
    {
        return Err(format!(
            "{} is a protected system path — refusing unconditionally",
            canonical.display()
        ));
    }
    if canonical.is_dir() {
        return Err(
            "directories are not supported by path-mode wipe yet — pass individual files"
                .to_string(),
        );
    }
    if !canonical.is_file() {
        return Err("not a regular file".to_string());
    }
    Ok(canonical)
}

/// Resolve and safety-check every caller-supplied path. Never partially
/// resolves an entry — each one is either a clean, existing regular file
/// outside the protected list, or carries a `refused` reason.
pub fn plan_paths(paths: &[PathBuf]) -> Vec<PathOutcome> {
    paths
        .iter()
        .map(|p| match check_path(p) {
            Ok(resolved) => PathOutcome {
                bytes: file_size(&resolved),
                path: resolved,
                refused: None,
            },
            Err(reason) => PathOutcome {
                path: p.clone(),
                bytes: 0,
                refused: Some(reason),
            },
        })
        .collect()
}

fn wipe_tool_available() -> bool {
    Command::new("wipe")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Destroy every non-refused entry from a prior `plan_paths` call. Uses the
/// `wipe` overwrite-then-unlink tool when installed; otherwise falls back to
/// a plain removal and says so plainly rather than implying an overwrite
/// pass happened. Returns (path, succeeded, warnings) per entry.
pub fn execute_paths(outcomes: &[PathOutcome]) -> Vec<(PathBuf, bool, Vec<String>)> {
    let have_wipe = wipe_tool_available();
    let mut ssd_note = Vec::new();
    ssd_caveat(&mut ssd_note);

    outcomes
        .iter()
        .map(|o| {
            if let Some(reason) = &o.refused {
                return (o.path.clone(), false, vec![reason.clone()]);
            }

            let mut warnings = ssd_note.clone();
            if have_wipe {
                match Command::new("wipe").args(["-f", "-q"]).arg(&o.path).status() {
                    Ok(s) if s.success() => {}
                    Ok(s) => warnings.push(format!(
                        "'wipe' exited with {s} — falling back to a plain removal"
                    )),
                    Err(e) => warnings.push(format!(
                        "failed to run 'wipe': {e} — falling back to a plain removal"
                    )),
                }
            } else {
                warnings.push(
                    "'wipe' is not installed — the file was removed with no overwrite pass; \
                     recovery may be possible, especially on SSD/NVMe media"
                        .to_string(),
                );
            }

            let removed = fs::remove_file(&o.path).is_ok() || !o.path.exists();
            (o.path.clone(), removed, warnings)
        })
        .collect()
}

pub fn plan(target: WipeTarget) -> Plan {
    let mut warnings = Vec::new();
    let files = match target {
        WipeTarget::ShellHistory => {
            ssd_caveat(&mut warnings);
            shell_history_candidates()
        }
        WipeTarget::Tmp => {
            ssd_caveat(&mut warnings);
            tmp_candidates()
        }
        WipeTarget::Thumbnails => thumbnail_candidates(),
        WipeTarget::RecentFiles => recent_files_candidates(),
        WipeTarget::Logs => {
            // journalctl owns its own storage; we can't list "files" without
            // reimplementing its rotation logic, so plan just reports current
            // journal disk usage as the upper bound of what --vacuum-time=1s
            // would reclaim.
            let usage = Command::new("journalctl")
                .arg("--disk-usage")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            if let Some(line) = usage {
                warnings.push(format!("current journal usage: {line}"));
            }
            Vec::new()
        }
    };

    let bytes = files.iter().map(|p| file_size(p)).sum();
    Plan { files, bytes, warnings }
}

/// Actually delete what `plan()` found. Returns (files removed, bytes freed,
/// extra warnings for entries that couldn't be removed).
pub fn execute(target: WipeTarget, plan: &Plan) -> (usize, u64, Vec<String>) {
    let mut removed = 0usize;
    let mut freed = 0u64;
    let mut warnings = Vec::new();

    if target == WipeTarget::Logs {
        match Command::new("journalctl").args(["--rotate"]).status() {
            Ok(s) if s.success() => {}
            Ok(s) => warnings.push(format!("journalctl --rotate exited with {s}")),
            Err(e) => warnings.push(format!("failed to run journalctl --rotate: {e}")),
        }
        match Command::new("journalctl")
            .args(["--vacuum-time=1s"])
            .output()
        {
            Ok(o) if o.status.success() => {
                let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !msg.is_empty() {
                    warnings.push(msg);
                }
            }
            Ok(o) => warnings.push(format!(
                "journalctl --vacuum-time=1s exited with {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            )),
            Err(e) => warnings.push(format!("failed to run journalctl --vacuum-time: {e}")),
        }
        return (removed, freed, warnings);
    }

    for path in &plan.files {
        let size = file_size(path);
        match fs::remove_file(path) {
            Ok(()) => {
                removed += 1;
                freed += size;
            }
            Err(e) => warnings.push(format!("{}: {e}", path.display())),
        }
    }

    (removed, freed, warnings)
}
