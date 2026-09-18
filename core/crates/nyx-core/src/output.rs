//! Structured JSON output — every Nyx OS binary prints this format on stdout
//! so it can be parsed by the dashboard, logs, or scripts without scraping text.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
    Warning,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NyxOutput<T> {
    pub status: Status,
    pub binary: String,
    pub command: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> NyxOutput<T> {
    pub fn ok(
        binary: impl Into<String>,
        command: impl Into<String>,
        message: impl Into<String>,
        data: Option<T>,
    ) -> Self {
        Self {
            status: Status::Ok,
            binary: binary.into(),
            command: command.into(),
            message: message.into(),
            data,
        }
    }

    pub fn err(binary: impl Into<String>, command: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: Status::Error,
            binary: binary.into(),
            command: command.into(),
            message: message.into(),
            data: None,
        }
    }

    /// The command succeeded but didn't do quite what was asked (e.g. a
    /// fallback kicked in) — distinct from `ok` so callers can't mistake a
    /// caveated result for a clean one just because `data` is present.
    pub fn warn(
        binary: impl Into<String>,
        command: impl Into<String>,
        message: impl Into<String>,
        data: Option<T>,
    ) -> Self {
        Self {
            status: Status::Warning,
            binary: binary.into(),
            command: command.into(),
            message: message.into(),
            data,
        }
    }

    pub fn print(&self) {
        println!(
            "{}",
            serde_json::to_string(self)
                .unwrap_or_else(|_| r#"{"status":"error","message":"output serialization failed"}"#.into())
        );
    }
}

pub fn print_error(binary: &str, command: &str, message: &str) {
    let out = NyxOutput::<()> {
        status: Status::Error,
        binary: binary.into(),
        command: command.into(),
        message: message.into(),
        data: None,
    };
    eprintln!(
        "{}",
        serde_json::to_string(&out)
            .unwrap_or_else(|_| format!(r#"{{"status":"error","message":"{message}"}}"#))
    );
}
