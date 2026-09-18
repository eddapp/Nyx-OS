mod handler;
mod hostname;
mod ipv6;
mod mac;
mod persisted;
mod state;
mod timezone;

use nyx_core::IDENTITY_SOCKET;
use state::AppState;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const RUNTIME_DIR: &str = "/run/nyx";
// Same trust boundary as the other Nyx daemons: anyone who can already
// `sudo` on this system can drive identity changes without an extra prompt.
const SOCKET_GROUP: &str = "wheel";

fn bind_socket() -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(RUNTIME_DIR)?;

    let path = Path::new(IDENTITY_SOCKET);
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
            "nyx-identity must run as root (it drives nmcli/hostnamectl/timedatectl/sysctl)"
        );
    }

    let state = Arc::new(AppState::default());
    let listener = bind_socket()?;

    tracing::info!("nyx-identity listening on {IDENTITY_SOCKET}");

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
                    Err(e) => nyx_core::NyxOutput::err("nyx-identity", "parse", e.to_string()),
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
