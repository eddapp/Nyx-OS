//! Path-resolution safety checks. The goal is to defeat "trusted binary,
//! hijacked parent directory" and PATH-hijack tricks: every identity nyx-
//! isolation is asked to launch gets its *entire* resolved path walked from
//! `/` down, not just the final file, before anything is exec'd.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Fixed, safe search path for `profile:<name>` resolution — never the
/// invoking process's own inherited `$PATH`, which a caller could have
/// manipulated to point a familiar name at something else entirely.
const SAFE_PATH: &[&str] = &["/usr/local/sbin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Walk every path component from `/` down to `path`, refusing if any
/// component is a symlink, is writable by group/other without being both
/// root-owned and sticky (the `/tmp`-style exception), or is owned by
/// neither root nor the invoking user. Also refuses a setuid/setgid target.
pub fn validate_ownership_chain(path: &Path) -> Result<PathBuf, String> {
    let canonical =
        fs::canonicalize(path).map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
    let invoking_uid = nix::unistd::getuid().as_raw();

    let mut current = PathBuf::from("/");
    for component in canonical.components().skip(1) {
        current.push(component);
        let meta = fs::symlink_metadata(&current).map_err(|e| format!("{}: {e}", current.display()))?;

        if meta.file_type().is_symlink() {
            return Err(format!(
                "{}: refusing to trust a symlink in the resolution path",
                current.display()
            ));
        }

        let mode = meta.permissions().mode();
        let group_or_other_writable = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        let owner_is_root = meta.uid() == 0;

        if group_or_other_writable && !(sticky && owner_is_root) {
            return Err(format!(
                "{}: writable by group/other without a root-owned sticky bit — untrusted ancestor",
                current.display()
            ));
        }
        if meta.uid() != 0 && meta.uid() != invoking_uid {
            return Err(format!(
                "{}: owned by neither root nor the invoking user",
                current.display()
            ));
        }
    }

    let final_meta =
        fs::metadata(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    if final_meta.permissions().mode() & 0o6000 != 0 {
        return Err(format!(
            "{}: refusing to sandbox a setuid/setgid executable",
            canonical.display()
        ));
    }

    Ok(canonical)
}

/// Resolve `name` against [`SAFE_PATH`] only, then validate the result.
pub fn resolve_in_safe_path(name: &str) -> Result<PathBuf, String> {
    if name.is_empty() || name.contains('/') {
        return Err("program names for profile:<name> may not be empty or contain '/'".to_string());
    }
    for dir in SAFE_PATH {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return validate_ownership_chain(&candidate);
        }
    }
    Err(format!("'{name}' was not found on the safe resolution path"))
}

/// `profile:<name>` is only allowed when a root-owned Firejail profile for
/// it already exists — an extra allowlist beyond merely "found on disk", so
/// this mode can't be used to sandbox arbitrary unreviewed programs with
/// Firejail's generic default policy.
pub fn require_firejail_profile(name: &str) -> Result<(), String> {
    let path = PathBuf::from(format!("/etc/firejail/{name}.profile"));
    let meta = fs::metadata(&path).map_err(|_| {
        format!(
            "no profile at {} — profile:<name> requires one to already exist",
            path.display()
        )
    })?;
    if meta.uid() != 0 {
        return Err(format!("{}: not root-owned — refusing to trust it", path.display()));
    }
    Ok(())
}
