use crate::{luks, microphone, modules, radios, usb, usbguard};
use nyx_core::{DeviceModule, DeviceRadio, DevicesCommand, DevicesReport, NyxOutput, SecurityState};
use zbus::Connection;

const BINARY: &str = "nyx-devices";

async fn report(conn: &Connection) -> DevicesReport {
    let usbguard_active = usbguard::is_active(conn).await;
    let usbguard_default_deny = usbguard::default_deny();

    let (state, detail) = match (usbguard_active, usbguard_default_deny) {
        (Some(true), Some(true)) => (
            SecurityState::Protected,
            "USBGuard is active with a default-deny policy — unrecognized USB devices are refused"
                .to_string(),
        ),
        (Some(true), Some(false)) => (
            SecurityState::Degraded,
            "USBGuard is active but its default policy is not 'block' — unrecognized devices may \
             be allowed"
                .to_string(),
        ),
        (Some(true), None) => (
            SecurityState::Degraded,
            "USBGuard is active but its default policy could not be read".to_string(),
        ),
        (Some(false), _) => (
            SecurityState::Blocked,
            "USBGuard is not running — no USB device authorization is being enforced".to_string(),
        ),
        (None, _) => (SecurityState::Error, "could not determine USBGuard's state".to_string()),
    };

    DevicesReport {
        wifi_enabled: radios::wifi_enabled(),
        bluetooth_enabled: radios::bluetooth_enabled(),
        webcam_enabled: Some(modules::is_loaded(&modules::WEBCAM)),
        microphone_enabled: microphone::enabled(),
        usb_storage_enabled: Some(modules::is_loaded(&modules::USB_STORAGE)),
        usbguard_active,
        usbguard_default_deny,
        encrypted_root: luks::root_is_encrypted(),
        luks_devices: luks::luks_devices(),
        usb_devices: usb::devices(),
        usbguard_policy: usbguard::policy_lines(),
        usbguard_history: usbguard::recent_history(20),
        state,
        detail,
    }
}

pub async fn dispatch(conn: &Connection, cmd: DevicesCommand) -> NyxOutput<DevicesReport> {
    match cmd {
        DevicesCommand::Status => {
            let r = report(conn).await;
            let detail = r.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(r))
        }

        DevicesCommand::SetRadio { radio, on } => {
            let result = match radio {
                DeviceRadio::Wifi => radios::set_wifi(on),
                DeviceRadio::Bluetooth => radios::set_bluetooth(on),
            };
            match result {
                Ok(()) => {
                    let r = report(conn).await;
                    let word = if on { "on" } else { "off" };
                    NyxOutput::ok(BINARY, "set_radio", format!("{radio:?} set to {word}"), Some(r))
                }
                Err(e) => NyxOutput::<DevicesReport>::err(BINARY, "set_radio", e.to_string()),
            }
        }

        DevicesCommand::SetModule { module, enabled } => {
            let spec = match module {
                DeviceModule::Webcam => &modules::WEBCAM,
                DeviceModule::UsbStorage => &modules::USB_STORAGE,
            };
            match modules::set(spec, enabled) {
                Ok(()) => {
                    let r = report(conn).await;
                    let word = if enabled { "enabled" } else { "disabled" };
                    NyxOutput::ok(BINARY, "set_module", format!("{module:?} {word}"), Some(r))
                }
                Err(e) => NyxOutput::<DevicesReport>::err(BINARY, "set_module", e.to_string()),
            }
        }

        DevicesCommand::SetMicrophone { enabled } => match microphone::set(enabled) {
            Ok(()) => {
                let r = report(conn).await;
                let word = if enabled { "unmuted" } else { "muted" };
                NyxOutput::ok(BINARY, "set_microphone", format!("microphone {word}"), Some(r))
            }
            Err(e) => NyxOutput::<DevicesReport>::err(BINARY, "set_microphone", e.to_string()),
        },

        DevicesCommand::SetUsbGuard { enabled } => match usbguard::set_enabled(conn, enabled).await {
            Ok(()) => {
                let r = report(conn).await;
                let word = if enabled { "started" } else { "stopped" };
                NyxOutput::ok(BINARY, "set_usbguard", format!("USBGuard {word}"), Some(r))
            }
            Err(e) => NyxOutput::<DevicesReport>::err(BINARY, "set_usbguard", e.to_string()),
        },
    }
}
