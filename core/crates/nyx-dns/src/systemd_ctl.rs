//! Read-only systemd query — nyx-dns never starts/stops units itself (that's
//! nyx-health's job); it only observes whether the enforced resolver is up.

use nyx_core::{NyxError, NyxResult};
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

#[zbus::proxy(
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    interface = "org.freedesktop.systemd1.Manager"
)]
trait SystemdManager {
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

pub async fn is_active(conn: &Connection, unit: &str) -> NyxResult<bool> {
    let manager = SystemdManagerProxy::new(conn)
        .await
        .map_err(|e| NyxError::Network(format!("systemd manager proxy: {e}")))?;

    let path = manager
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
