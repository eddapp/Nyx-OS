//! Systemd D-Bus access for nyx-dns. Mostly read-only — nyx-health owns
//! service lifecycle in general — but `DnsCommand::SwitchProvider` needs to
//! restart `dnscrypt-proxy.service` specifically after rewriting its config,
//! so this is the one unit nyx-dns is allowed to restart itself, using the
//! same `RestartUnit` D-Bus call nyx-health's own `systemd_ctl.rs` uses.

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
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
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

/// Restart `unit` via the real `RestartUnit` D-Bus call (not a stop-then-
/// start pair) — used only by `DnsCommand::SwitchProvider` to reload
/// `dnscrypt-proxy.service` after editing its `server_names` line.
pub async fn restart_unit(conn: &Connection, unit: &str) -> NyxResult<()> {
    let manager = SystemdManagerProxy::new(conn)
        .await
        .map_err(|e| NyxError::Network(format!("systemd manager proxy: {e}")))?;
    manager
        .restart_unit(unit, "replace")
        .await
        .map_err(|e| NyxError::Network(format!("failed to restart {unit}: {e}")))?;
    Ok(())
}
