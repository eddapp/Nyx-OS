//! The one piece of state nyx-identity actually needs to remember: the
//! hostname/timezone captured right before the first randomization, since
//! (unlike a MAC address) there's no hardware-level "permanent" value to
//! fall back on for either of these.

use nyx_core::{NyxResult, IDENTITY_STATE_PATH};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistedState {
    pub original_hostname: Option<String>,
    pub original_timezone: Option<String>,
}

pub fn load() -> PersistedState {
    fs::read_to_string(IDENTITY_STATE_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(state: &PersistedState) -> NyxResult<()> {
    if let Some(parent) = Path::new(IDENTITY_STATE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    fs::write(IDENTITY_STATE_PATH, json)?;
    Ok(())
}
