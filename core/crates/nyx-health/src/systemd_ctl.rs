//! Service lifecycle via the systemd D-Bus API — no `systemctl` subprocess,
//! the daemon talks to `org.freedesktop.systemd1` directly.

use nyx_core::{NyxError, NyxResult};
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

#[zbus::proxy(
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    interface = "org.freedesktop.systemd1.Manager"
)]
trait SystemdManager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.systemd1",
    interface = "org.freedesktop.systemd1.Unit"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

async fn manager(conn: &Connection) -> NyxResult<SystemdManagerProxy<'_>> {
    SystemdManagerProxy::new(conn)
        .await
        .map_err(|e| NyxError::Network(format!("systemd manager proxy: {e}")))
}

pub async fn start_unit(conn: &Connection, unit: &str) -> NyxResult<()> {
    manager(conn)
        .await?
        .start_unit(unit, "replace")
        .await
        .map_err(|e| NyxError::Network(format!("failed to start {unit}: {e}")))?;
    Ok(())
}

pub async fn stop_unit(conn: &Connection, unit: &str) -> NyxResult<()> {
    manager(conn)
        .await?
        .stop_unit(unit, "replace")
        .await
        .map_err(|e| NyxError::Network(format!("failed to stop {unit}: {e}")))?;
    Ok(())
}

/// A real `systemctl restart` equivalent (`RestartUnit`, not a
/// stop-then-start pair) — used for Tor-over-VPN chaining to force fresh
/// circuits over a VPN's route. See `HealthCommand::TorRestart`'s doc
/// comment for why a bare restart was chosen over Tor's control-port
/// protocol.
pub async fn restart_unit(conn: &Connection, unit: &str) -> NyxResult<()> {
    manager(conn)
        .await?
        .restart_unit(unit, "replace")
        .await
        .map_err(|e| NyxError::Network(format!("failed to restart {unit}: {e}")))?;
    Ok(())
}

pub async fn is_active(conn: &Connection, unit: &str) -> NyxResult<bool> {
    let path = manager(conn)
        .await?
        .get_unit(unit)
        .await
        .map_err(|_| NyxError::Network(format!("{unit} not loaded")))?;

    let unit_proxy = SystemdUnitProxy::builder(conn)
        .path(path)
        .map_err(|e| NyxError::Network(format!("unit proxy path: {e}")))?
        .build()
        .await
        .map_err(|e| NyxError::Network(format!("unit proxy: {e}")))?;

    let state = unit_proxy
        .active_state()
        .await
        .map_err(|e| NyxError::Network(format!("active_state: {e}")))?;
    Ok(state == "active")
}
