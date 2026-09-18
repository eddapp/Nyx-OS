//! nyx-watch — real, deterministic change detection over process/socket/
//! route/firewall/DNS state. Not anomaly *scoring*: every category is a
//! plain diff of two real snapshots of real system state (`/proc`, `ip
//! route`, `nft list table`, nyx-dns's own socket), so an event here means
//! "this specific fact changed between two polls", never a guess about
//! whether that's suspicious.
//!
//! Requires root for the same reason `nyx-dns`/`nyx-integrity` do: mapping
//! a socket's inode back to an owning PID across *other users'* processes
//! (category 1/3's PID resolution) needs `CAP_SYS_PTRACE`-gated access to
//! their `/proc/<pid>/fd`, and reading every process's `/proc/<pid>/status`
//! reliably (category 2) and `nft list table` (category 6) both assume the
//! same privilege level every other root Nyx daemon already runs at.

mod dns_watch;
mod firewall;
mod handler;
mod poller;
mod proc_net;
mod procs;
mod protocol;
mod routes;
mod sockets;
mod state;

use protocol::WATCH_SOCKET;
use state::AppState;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const RUNTIME_DIR: &str = "/run/nyx";
// Same trust boundary as nyx-health/nyx-dns/nyx-integrity: anyone who can
// already `sudo` on this system can read what's changed without an extra
// prompt on every poll.
const SOCKET_GROUP: &str = "wheel";
/// How often the background loop takes a fresh snapshot and diffs it.
/// Chosen as a balance between catching short-lived listeners/connections
/// and not spending the whole interval walking every process's `/proc/fd`
/// for PID resolution on busy systems.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

fn bind_socket() -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(RUNTIME_DIR)?;

    let path = Path::new(WATCH_SOCKET);
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
            "nyx-watch must run as root (it maps other processes' sockets to PIDs and reads \
             nft's ruleset)"
        );
    }

    let state = Arc::new(AppState::default());
    let listener = bind_socket()?;

    tracing::info!("nyx-watch listening on {WATCH_SOCKET}");

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // Prime the baseline immediately rather than waiting a full
            // interval, so `Status` right after boot doesn't just say "no
            // poll has completed yet" for up to `POLL_INTERVAL`.
            poller::poll_once(&state).await;

            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.tick().await; // first tick fires immediately; skip it, we just polled.
            loop {
                ticker.tick().await;
                poller::poll_once(&state).await;
            }
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
                    Err(e) => nyx_core::NyxOutput::err("nyx-watch", "parse", e.to_string()),
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
