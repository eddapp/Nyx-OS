mod amneziawg;
mod dante;
mod free_provider;
mod handler;
mod hysteria;
mod import;
mod openvpn;
mod route;
mod shadowsocks;
mod socks_override;
mod state;
mod systemd_ctl;
mod templates;
mod util;
mod wireguard;
mod xray;

use nyx_core::VPN_SOCKET;
use state::AppState;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use zbus::Connection;

const RUNTIME_DIR: &str = "/run/nyx";
// Same trust boundary as nyx-health/nyx-dns/nyx-integrity: anyone who can
// already `sudo` on this system can drive the VPN without an extra prompt.
const SOCKET_GROUP: &str = "wheel";

fn bind_socket() -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(RUNTIME_DIR)?;

    let path = Path::new(VPN_SOCKET);
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
            "nyx-vpn must run as root (it drives wg-quick and openvpn-client@.service)"
        );
    }

    let conn = Connection::system().await?;
    let state = Arc::new(AppState::default());
    let listener = bind_socket()?;

    tracing::info!("nyx-vpn listening on {VPN_SOCKET}");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn = conn.clone();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str(&line) {
                    Ok(cmd) => handler::dispatch(&conn, &state, cmd).await,
                    Err(e) => nyx_core::NyxOutput::err("nyx-vpn", "parse", e.to_string()),
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
