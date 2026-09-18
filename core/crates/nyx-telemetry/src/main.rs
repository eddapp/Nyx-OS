//! nyx-telemetry — the one Nyx daemon that needs no privilege at all.
//! Every value it reports comes from `/proc` or `statvfs`, both readable
//! by any user, so it runs unprivileged (`DynamicUser=yes` in its systemd
//! unit) with a world-readable socket. There is no security boundary to
//! enforce over CPU/RAM/network numbers.

mod cpu;
mod disk;
mod handler;
mod memory;
mod network;
mod state;
mod system;

use nyx_core::TELEMETRY_SOCKET;
use state::AppState;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const RUNTIME_DIR: &str = "/run/nyx-telemetry";

fn bind_socket() -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(RUNTIME_DIR)?;

    let path = Path::new(TELEMETRY_SOCKET);
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;

    Ok(listener)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nyx_core::logging::init();

    let state = Arc::new(AppState::default());
    let listener = bind_socket()?;

    tracing::info!("nyx-telemetry listening on {TELEMETRY_SOCKET}");

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
                    Err(e) => nyx_core::NyxOutput::err("nyx-telemetry", "parse", e.to_string()),
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
