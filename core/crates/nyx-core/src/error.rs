use thiserror::Error;

/// Central error type. No `.unwrap()` in production code — everything routes
/// through here so every binary reports failures the same way.
#[derive(Error, Debug)]
pub enum NyxError {
    #[error("network error: {0}")]
    Network(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("tor error: {0}")]
    Tor(String),

    #[error("dns error: {0}")]
    Dns(String),

    #[error("firewall error: {0}")]
    Firewall(String),

    #[error("wipe error: {0}")]
    Wipe(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type NyxResult<T> = Result<T, NyxError>;
