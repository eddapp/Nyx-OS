//! Connected USB device inventory via `lsusb` (usbutils).

use std::process::Command;

pub fn devices() -> Vec<String> {
    match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect()
        }
        _ => Vec::new(),
    }
}
