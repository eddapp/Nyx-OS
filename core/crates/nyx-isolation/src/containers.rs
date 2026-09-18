//! Podman-based container isolation — a second sandbox runtime alongside
//! Firejail (see `main.rs`), deliberately narrow in scope. This is NOT a
//! general "run any image" tool: exactly one purpose-built image
//! ("workbench") ever exists as far as this module is concerned, pinned by
//! digest and re-verified against `/etc/nyx/workbench-image.json` before
//! every single launch — a swapped or tampered local image is refused, not
//! silently trusted. See `containers/workbench.Containerfile` and
//! `containers/build-workbench.sh` for how that image and its pinned
//! digest actually get produced.
//!
//! Every container this module creates is rootless Podman — nyx-isolation
//! itself refuses to run as root (see `main.rs`), and rootless Podman
//! never needs it — with a fixed, non-optional security posture: no
//! network by default, every capability dropped, no privilege escalation,
//! a real user-namespace mapping, and hard PID/memory limits. Lifecycle is
//! label-based (`io.nyxos.managed`, `io.nyxos.profile`) so a "stop
//! everything" action can never accidentally destroy someone's disposable
//! work mid-task: a disposable container is `--rm` from the moment it is
//! created (stopping it destroys it, which is the entire point of
//! "disposable"), and [`stop_all`] only ever touches the persistent
//! workbench.

use crate::validate;
use nyx_core::WORKBENCH_IMAGE_METADATA_PATH;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

/// Absolute path, never resolved through the caller's own inherited
/// `$PATH` — the same posture `main.rs` already takes with
/// `/usr/bin/firejail`.
const PODMAN: &str = "/usr/bin/podman";

/// The one and only image this module ever runs. Never caller-supplied.
pub const WORKBENCH_IMAGE: &str = "localhost/nyx-workbench:latest";

/// Name of the single persistent workbench container. Fixed, not
/// caller-supplied — there is exactly one persistent workbench, by design.
const PERSISTENT_NAME: &str = "nyx-workbench";

const LABEL_MANAGED: &str = "io.nyxos.managed=true";
const LABEL_MANAGED_FILTER: &str = "label=io.nyxos.managed=true";
const LABEL_PROFILE_KEY: &str = "io.nyxos.profile";
const PROFILE_DISPOSABLE: &str = "disposable";
const PROFILE_PERSISTENT: &str = "persistent";

/// Whether a freshly launched disposable shell gets a network namespace at
/// all. The default posture (see [`launch_disposable`]) is `None`; `Pasta`
/// is an explicit, clearly-labelled opt-in a caller has to ask for — Podman
/// 6 dropped slirp4netns entirely, so pasta is the only rootless user-mode
/// network backend left to offer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    None,
    Pasta,
}

impl Network {
    fn flag(self) -> &'static str {
        match self {
            Network::None => "--network=none",
            Network::Pasta => "--network=pasta",
        }
    }
}

/// One container `status()` found, tagged with `io.nyxos.managed=true`.
#[derive(Debug, Serialize)]
pub struct ContainerStatus {
    pub name: String,
    pub state: String,
    pub profile: String,
}

#[derive(Serialize, Deserialize)]
struct ImageMetadata {
    image: String,
    digest: String,
    /// Unix epoch seconds — kept as a bare integer rather than pulling in a
    /// date/time crate just to format one build timestamp.
    built_at: u64,
}

fn podman(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(PODMAN)
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn {PODMAN}: {e}"))
}

/// Run a podman subcommand to completion, returning trimmed stdout on
/// success and a real error (including podman's own stderr) on failure —
/// no silent "assume it worked".
fn podman_ok(args: &[&str]) -> Result<String, String> {
    let out = podman(args)?;
    if !out.status.success() {
        return Err(format!(
            "podman {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn podman_status(args: &[&str]) -> bool {
    podman(args).map(|o| o.status.success()).unwrap_or(false)
}

/// Load and ownership-validate the sidecar metadata file. Reuses
/// `validate.rs`'s existing ownership-chain walk rather than a second copy
/// of that logic, plus an explicit root-ownership check on the file
/// itself — this is trust state only `build-workbench.sh` (or the
/// equivalent `container build-image` path), run as root, is meant to
/// write.
fn load_metadata() -> Result<ImageMetadata, String> {
    let path = Path::new(WORKBENCH_IMAGE_METADATA_PATH);
    let canonical = validate::validate_ownership_chain(path)
        .map_err(|e| format!("workbench image metadata failed validation: {e}"))?;

    let meta =
        std::fs::metadata(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    if meta.uid() != 0 {
        return Err(format!(
            "{}: not root-owned — refusing to trust it",
            canonical.display()
        ));
    }

    let raw = std::fs::read_to_string(&canonical)
        .map_err(|e| format!("{}: {e}", canonical.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("{}: corrupt metadata: {e}", canonical.display()))
}

/// The digest Podman currently reports for the locally loaded workbench
/// image, straight from `podman image inspect` — never trusted from any
/// cache nyx-isolation itself might keep.
fn current_digest(image: &str) -> Result<String, String> {
    let digest = podman_ok(&["image", "inspect", "--format", "{{.Digest}}", image])
        .map_err(|e| format!("workbench image {image} is not present locally: {e}"))?;
    if digest.is_empty() || digest == "<none>" {
        return Err(format!(
            "{image}: podman reports no digest for the locally loaded image — refusing to \
             trust it"
        ));
    }
    Ok(digest)
}

/// Verify the currently loaded local workbench image's digest still
/// matches what was pinned at build time. Called before every single
/// launch below — a swapped or tampered local image is refused outright,
/// never silently used.
pub fn verify_image_digest() -> Result<String, String> {
    let metadata = load_metadata()?;
    if metadata.image != WORKBENCH_IMAGE {
        return Err(format!(
            "workbench metadata names image '{}', nyx-isolation only ever runs '{WORKBENCH_IMAGE}'",
            metadata.image
        ));
    }
    let live = current_digest(&metadata.image)?;
    if live != metadata.digest {
        return Err(format!(
            "workbench image digest mismatch: pinned {}, found {live} — the local image was \
             rebuilt or swapped since the last verified build; re-run build-workbench.sh if \
             this was intentional",
            metadata.digest
        ));
    }
    Ok(metadata.image)
}

/// Build (or rebuild) the workbench image and pin its digest into the
/// sidecar metadata file. The Rust equivalent of `build-workbench.sh`,
/// kept in step with it deliberately (same image tag, same metadata
/// shape). Like that script, this needs to run as root purely to write
/// the root-owned digest metadata file — the build itself is ordinary
/// rootless Podman. `main.rs` only reaches this function through the one
/// subcommand explicitly exempted from nyx-isolation's otherwise-universal
/// "never root" rule, for exactly this reason.
pub fn build_image(context_dir: &Path) -> Result<String, String> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(
            "building the workbench image requires root (it writes the root-owned digest \
             metadata file at /etc/nyx/workbench-image.json) — run via sudo"
                .to_string(),
        );
    }

    let containerfile = context_dir.join("workbench.Containerfile");
    if !containerfile.is_file() {
        return Err(format!("{}: not found", containerfile.display()));
    }
    let containerfile_str = containerfile
        .to_str()
        .ok_or_else(|| format!("{}: not valid UTF-8", containerfile.display()))?;
    let context_str = context_dir
        .to_str()
        .ok_or_else(|| format!("{}: not valid UTF-8", context_dir.display()))?;

    podman_ok(&[
        "build",
        "--pull=newer",
        "--tag",
        WORKBENCH_IMAGE,
        "--file",
        containerfile_str,
        context_str,
    ])?;

    let digest = current_digest(WORKBENCH_IMAGE)?;
    let built_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let metadata = ImageMetadata {
        image: WORKBENCH_IMAGE.to_string(),
        digest: digest.clone(),
        built_at,
    };
    let json = serde_json::to_string_pretty(&metadata)
        .map_err(|e| format!("failed to serialize workbench image metadata: {e}"))?;

    let path = Path::new(WORKBENCH_IMAGE_METADATA_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("{}: {e}", path.display()))?;

    Ok(digest)
}

fn container_exists(name: &str) -> bool {
    podman_status(&["container", "exists", name])
}

fn container_running(name: &str) -> Result<bool, String> {
    let out = podman_ok(&["inspect", "--format", "{{.State.Running}}", name])?;
    Ok(out == "true")
}

fn create_persistent_container() -> Result<(), String> {
    podman_ok(&[
        "create",
        "--name",
        PERSISTENT_NAME,
        "--network=none",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--userns=nomap",
        "--pids-limit=256",
        "--memory=1536m",
        "--log-driver=none",
        "--pull=never",
        &format!("--label={LABEL_MANAGED}"),
        &format!("--label={LABEL_PROFILE_KEY}={PROFILE_PERSISTENT}"),
        WORKBENCH_IMAGE,
        "idle",
    ])?;
    Ok(())
}

/// Build a `podman run` command for a brand-new, `--rm`-from-creation
/// disposable sandbox shell. The caller (`main.rs`) execs this so the
/// interactive container becomes the direct child of whatever invoked
/// nyx-isolation, matching the Firejail/native launch path's own exec
/// convention.
pub fn launch_disposable(network: Network) -> Result<Command, String> {
    verify_image_digest()?;

    let mut cmd = Command::new(PODMAN);
    cmd.arg("run")
        .arg("--rm")
        .arg("-it")
        .arg(network.flag())
        .arg("--cap-drop=all")
        .arg("--security-opt=no-new-privileges")
        .arg("--userns=nomap")
        .arg("--pids-limit=256")
        .arg("--memory=1536m")
        .arg("--log-driver=none")
        .arg("--pull=never")
        .arg(format!("--label={LABEL_MANAGED}"))
        .arg(format!("--label={LABEL_PROFILE_KEY}={PROFILE_DISPOSABLE}"))
        .arg(WORKBENCH_IMAGE)
        .arg("shell");
    Ok(cmd)
}

/// Build a command that attaches an interactive shell to the single
/// persistent workbench, creating and/or starting it first if needed. Like
/// [`launch_disposable`], the caller execs the returned command.
pub fn launch_persistent() -> Result<Command, String> {
    verify_image_digest()?;

    if !container_exists(PERSISTENT_NAME) {
        create_persistent_container()?;
    }
    if !container_running(PERSISTENT_NAME)? {
        podman_ok(&["start", PERSISTENT_NAME])?;
    }

    let mut cmd = Command::new(PODMAN);
    cmd.args([
        "exec",
        "-it",
        PERSISTENT_NAME,
        "/usr/local/bin/nyx-workbench-entrypoint",
        "shell",
    ]);
    Ok(cmd)
}

/// Every container nyx-isolation manages (`io.nyxos.managed=true`), its
/// profile, and its current state — a live query against Podman, not
/// nyx-isolation's own memory of what it started.
pub fn status() -> Result<Vec<ContainerStatus>, String> {
    let out = podman_ok(&[
        "ps",
        "-a",
        "--filter",
        LABEL_MANAGED_FILTER,
        "--format",
        "{{.Names}}\t{{.State}}\t{{index .Labels \"io.nyxos.profile\"}}",
    ])?;
    Ok(out
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut parts = line.splitn(3, '\t');
            ContainerStatus {
                name: parts.next().unwrap_or_default().to_string(),
                state: parts.next().unwrap_or_default().to_string(),
                profile: parts.next().unwrap_or_default().to_string(),
            }
        })
        .collect())
}

/// Names of managed containers with the given profile label, optionally
/// restricted to currently-running ones.
fn managed_names(profile: &str, running_only: bool) -> Result<Vec<String>, String> {
    let profile_filter = format!("label={LABEL_PROFILE_KEY}={profile}");
    let mut args = vec!["ps"];
    if !running_only {
        args.push("-a");
    }
    args.push("--filter");
    args.push(LABEL_MANAGED_FILTER);
    args.push("--filter");
    args.push(&profile_filter);
    args.push("--format");
    args.push("{{.Names}}");

    let out = podman_ok(&args)?;
    Ok(out.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Start every stopped persistent-profile managed container. Disposable
/// containers never appear here: they are `--rm` from creation, so a
/// stopped one simply doesn't exist to be found.
pub fn start_all() -> Result<Vec<String>, String> {
    let names = managed_names(PROFILE_PERSISTENT, false)?;
    let mut started = Vec::new();
    for name in names {
        podman_ok(&["start", &name])?;
        started.push(name);
    }
    Ok(started)
}

/// Stop every running persistent-profile managed container. Deliberately
/// scoped to `profile=persistent` only: a disposable container is `--rm`
/// from the moment it is created, so "stopping" one is indistinguishable
/// from destroying whatever ephemeral work is running inside it.
/// `stop_all` must never reach one.
pub fn stop_all() -> Result<Vec<String>, String> {
    let names = managed_names(PROFILE_PERSISTENT, true)?;
    let mut stopped = Vec::new();
    for name in names {
        podman_ok(&["stop", &name])?;
        stopped.push(name);
    }
    Ok(stopped)
}

/// Remove the persistent workbench container entirely, destroying
/// everything inside it. Irreversible — the caller (`main.rs`) requires an
/// explicit `--yes` before ever passing `confirmed: true`, the same
/// pattern `nyx-wipe` uses for its own destructive operations. Returns
/// `Ok(false)` rather than an error when there was nothing to remove.
pub fn reset_workbench(confirmed: bool) -> Result<bool, String> {
    if !confirmed {
        return Err(
            "refusing to reset the persistent workbench without explicit confirmation — this \
             destroys it and everything inside it"
                .to_string(),
        );
    }
    if !container_exists(PERSISTENT_NAME) {
        return Ok(false);
    }
    podman_ok(&["rm", "-f", PERSISTENT_NAME])?;
    Ok(true)
}
