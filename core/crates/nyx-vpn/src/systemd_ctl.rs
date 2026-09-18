//! Service lifecycle via the systemd D-Bus API — used to drive the
//! `openvpn-client@<name>.service` template unit. No `systemctl` subprocess.

use nyx_core::{NyxError, NyxResult};
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

#[zbus::proxy(
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    interface = "org.freedesktop.systemd1.Manager"
)]
trait SystemdManager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn reload(&self) -> zbus::Result<()>;
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

/// The D-Bus equivalent of `systemctl daemon-reload` — needed after
/// writing or removing a unit drop-in (see `socks_override.rs`) for
/// systemd to notice it before the next `start_unit`/`stop_unit`.
pub async fn reload(conn: &Connection) -> NyxResult<()> {
    manager(conn)
        .await?
        .reload()
        .await
        .map_err(|e| NyxError::Network(format!("failed to reload systemd manager: {e}")))?;
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
