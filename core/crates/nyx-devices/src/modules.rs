//! Webcam/USB-storage control via kernel module load state. There is no
//! generic OS-level "webcam" or "USB storage" switch, so this unloads the
//! driver that covers the overwhelming majority of real devices in each
//! category (UVC-class webcams; USB mass-storage), and — the part that
//! actually matters for "disable" to mean something — writes a modprobe
//! blacklist so it stays off across replug/reboot instead of silently
//! coming back the next time udev sees the device.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::process::Command;

pub struct ModuleSpec {
    pub kernel_name: &'static str,
    pub blacklist_path: &'static str,
}

pub const WEBCAM: ModuleSpec = ModuleSpec {
    kernel_name: "uvcvideo",
    blacklist_path: "/etc/modprobe.d/nyx-webcam-blacklist.conf",
};

pub const USB_STORAGE: ModuleSpec = ModuleSpec {
    kernel_name: "usb_storage",
    blacklist_path: "/etc/modprobe.d/nyx-usb-storage-blacklist.conf",
};

pub fn is_loaded(spec: &ModuleSpec) -> bool {
    let Ok(contents) = fs::read_to_string("/proc/modules") else {
        return false;
    };
    contents
        .lines()
        .any(|line| line.split_whitespace().next() == Some(spec.kernel_name))
}

pub fn set(spec: &ModuleSpec, enabled: bool) -> NyxResult<()> {
    if enabled {
        let _ = fs::remove_file(spec.blacklist_path);
        let status = Command::new("modprobe")
            .arg(spec.kernel_name)
            .status()
            .map_err(|e| NyxError::Config(format!("failed to spawn modprobe: {e}")))?;
        if !status.success() {
            return Err(NyxError::Config(format!(
                "modprobe {} exited with {status}",
                spec.kernel_name
            )));
        }
    } else {
        let contents = format!(
            "# Managed by nyx-devices — do not edit by hand.\nblacklist {}\n",
            spec.kernel_name
        );
        fs::write(spec.blacklist_path, contents)?;
        // Best-effort immediate unload — the blacklist file is what
        // actually guarantees it stays off, whether or not the running
        // kernel lets go of it right this moment (it may be busy backing
        // an in-use device).
        let _ = Command::new("modprobe").args(["-r", spec.kernel_name]).status();
    }
    Ok(())
}
