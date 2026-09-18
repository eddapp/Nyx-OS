//! `nyx-diagnostics bundle` — collects a sanitized diagnostics archive
//! for support/troubleshooting: the same live daemon statuses `summary`
//! gathers, an interfaces/routes dump, `uname -a`, and recent
//! systemd/journal output for the Nyx services, all redacted item-by-item
//! as it's collected (see `redact.rs`) and packed into a gzipped tarball.
//! Never includes secrets, credentials, browsing history, or personal
//! file contents by design — it only ever shells out to read *this
//! machine's own service/network state*, nothing user-content-shaped.

use crate::redact::{redact, redact_and_count, current_username, RedactionCounts};
use crate::{checks, gather_daemon_statuses};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Nyx units whose systemd state and journal output are worth bundling.
/// Kept in one place so `systemctl status` and `journalctl -u` stay in
/// sync with each other.
const NYX_UNITS: &[&str] =
    &["nyx-health", "nyx-vpn", "nyx-dns", "nyx-identity", "nyx-devices", "nyx-integrity", "nyx-telemetry"];

pub struct BundleOutcome {
    pub archive_path: PathBuf,
    pub counts: RedactionCounts,
    pub files: Vec<String>,
}

/// Runs `bin` and returns its stdout as text, appending a short failure
/// note (still real information — "this unit isn't loaded" is itself
/// diagnostic) rather than dropping non-zero exits, since `systemctl
/// status` on an inactive/failed unit routinely exits non-zero while
/// still printing exactly the output we want in the bundle.
fn run_capture(bin: &str, args: &[&str]) -> String {
    match Command::new(bin).args(args).output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            if !o.status.success() {
                text.push_str(&format!("\n[{bin} exited with {}]\n", o.status));
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.trim().is_empty() {
                    text.push_str(stderr.trim());
                    text.push('\n');
                }
            }
            text
        }
        Err(e) => format!("failed to run {bin}: {e}"),
    }
}

/// Redacts `raw` and writes it into the staging directory under
/// `filename`, recording the filename for the bundle's index and folding
/// this item's redaction counts into the running total. This is the one
/// place every collected item passes through on its way into the bundle,
/// so nothing gets written unredacted.
fn stage_item(
    dir: &Path,
    filename: &str,
    raw: &str,
    username: &str,
    counts: &mut RedactionCounts,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let sanitized = redact_and_count(raw, username, counts);
    fs::write(dir.join(filename), sanitized)
        .map_err(|e| format!("failed to write {filename}: {e}"))?;
    files.push(filename.to_string());
    Ok(())
}

fn default_output_path(timestamp: u64) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(format!("nyx-diagnostics-bundle-{timestamp}.tar.gz"))
}

fn tar_gzip(staging_root: &Path, stage_name: &str, archive_path: &Path) -> Result<(), String> {
    let parent = staging_root
        .parent()
        .ok_or_else(|| "staging directory has no parent".to_string())?;
    let status = Command::new("tar")
        .args([
            "-czf",
            archive_path.to_str().ok_or_else(|| "archive path is not valid UTF-8".to_string())?,
            "-C",
            parent.to_str().ok_or_else(|| "staging parent is not valid UTF-8".to_string())?,
            stage_name,
        ])
        .status()
        .map_err(|e| format!("failed to spawn tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar exited with {status}"));
    }
    Ok(())
}

/// Collects, redacts, and packs the bundle. `output` overrides the
/// default `~/nyx-diagnostics-bundle-<timestamp>.tar.gz` path.
pub fn collect(output: Option<String>) -> Result<BundleOutcome, String> {
    let username = current_username();
    let mut counts = RedactionCounts::default();
    let mut files = Vec::new();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_secs();

    let stage_name = format!("nyx-diagnostics-bundle-{timestamp}");
    let staging_root = std::env::temp_dir().join(&stage_name);
    fs::create_dir_all(&staging_root).map_err(|e| format!("failed to create staging dir: {e}"))?;

    let result = collect_into(&staging_root, &username, &mut counts, &mut files);

    // Whatever happens above, the staging directory is scratch space —
    // never leave it behind, whether collection succeeded or not.
    let cleanup = |staging_root: &Path| {
        let _ = fs::remove_dir_all(staging_root);
    };

    if let Err(e) = result {
        cleanup(&staging_root);
        return Err(e);
    }

    let archive_path = output.map(PathBuf::from).unwrap_or_else(|| default_output_path(timestamp));
    if let Some(parent) = archive_path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = fs::create_dir_all(parent)
    {
        cleanup(&staging_root);
        return Err(format!("failed to create output directory: {e}"));
    }

    let tar_result = tar_gzip(&staging_root, &stage_name, &archive_path);
    cleanup(&staging_root);
    tar_result?;

    Ok(BundleOutcome { archive_path, counts, files })
}

fn collect_into(
    staging_root: &Path,
    username: &str,
    counts: &mut RedactionCounts,
    files: &mut Vec<String>,
) -> Result<(), String> {
    // Same live daemon statuses `summary` gathers — factored into
    // `gather_daemon_statuses` in main.rs so neither command duplicates
    // the daemon-calling logic.
    for (label, json) in gather_daemon_statuses() {
        stage_item(staging_root, &format!("daemon-{label}.json"), &json, username, counts, files)?;
    }

    let net = checks::network_dump();
    let net_text = format!("== interfaces ==\n{}\n\n== routes ==\n{}\n", net.interfaces, net.routes);
    stage_item(staging_root, "network.txt", &net_text, username, counts, files)?;

    let uname = run_capture("uname", &["-a"]);
    stage_item(staging_root, "uname.txt", &uname, username, counts, files)?;

    let kernel_version = run_capture("uname", &["-r"]);
    stage_item(staging_root, "kernel-version.txt", &kernel_version, username, counts, files)?;

    let mut systemctl_args: Vec<&str> = vec!["status", "--no-pager"];
    systemctl_args.extend(NYX_UNITS.iter().copied());
    let unit_states = run_capture("systemctl", &systemctl_args);
    stage_item(staging_root, "systemd-status.txt", &unit_states, username, counts, files)?;

    let mut journal_args: Vec<&str> = Vec::new();
    for unit in NYX_UNITS {
        journal_args.push("-u");
        journal_args.push(unit);
    }
    journal_args.extend(["--no-pager", "-n", "200"]);
    let journal = run_capture("journalctl", &journal_args);
    stage_item(staging_root, "journal.txt", &journal, username, counts, files)?;

    // Index/manifest last, once the file list is complete. Uses the
    // plain `redact` entry point — its own content is generated by us
    // (timestamp + filenames), but it's redacted anyway rather than
    // special-cased as "trusted", since a filename could in principle
    // embed something identifying.
    let index_raw = format!(
        "NyxOS diagnostics bundle\ngenerated (unix time): {}\nfiles:\n{}\n",
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        files.join("\n")
    );
    let index = redact(&index_raw);
    fs::write(staging_root.join("00-index.txt"), index)
        .map_err(|e| format!("failed to write index: {e}"))?;
    files.push("00-index.txt".to_string());

    Ok(())
}
