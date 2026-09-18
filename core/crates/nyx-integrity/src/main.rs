mod handler;
mod manifest;
mod pacman;
mod state;

use nyx_core::INTEGRITY_SOCKET;
use state::AppState;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const RUNTIME_DIR: &str = "/run/nyx";
// Same trust boundary as nyx-health/nyx-dns: anyone who can already `sudo`
// on this system can read integrity state without an extra prompt.
const SOCKET_GROUP: &str = "wheel";
/// How often the daemon re-runs a quick verification on its own, so `Status`
/// is never more than this stale even if nobody explicitly asked for `Verify`.
const BACKGROUND_INTERVAL: Duration = Duration::from_secs(30 * 60);

fn bind_socket() -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(RUNTIME_DIR)?;

    let path = Path::new(INTEGRITY_SOCKET);
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;

    if let Ok(Some(group)) = nix::unistd::Group::from_name(SOCKET_GROUP) {
        let _ = nix::unistd::chown(path, None, Some(group.gid));
    } else {
        tracing::warn!("group '{SOCKET_GROUP}' does not exist — socket left owned by root only");
    }

    Ok(listener)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nyx_core::logging::init();

    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!(
            "nyx-integrity must run as root (it reads other packages' files and writes \
             /etc/nyx/integrity.manifest)"
        );
    }

    let state = Arc::new(AppState::default());
    let listener = bind_socket()?;

    tracing::info!("nyx-integrity listening on {INTEGRITY_SOCKET}");

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BACKGROUND_INTERVAL);
            loop {
                ticker.tick().await;
                handler::run_verify(&state, true).await;
            }
        });
    }

    // Prime the cache once at startup rather than waiting a full interval,
    // so a fresh `Status` call right after boot isn't just the zero-value
    // default report.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handler::run_verify(&state, true).await;
        });
    }

    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str(&line) {
                    Ok(cmd) => handler::dispatch(&state, cmd).await,
                    Err(e) => nyx_core::NyxOutput::err("nyx-integrity", "parse", e.to_string()),
                };

                let mut payload = serde_json::to_vec(&response).unwrap_or_default();
                payload.push(b'\n');
                if write_half.write_all(&payload).await.is_err() {
                    break;
                }
            }
        });
    }
}
