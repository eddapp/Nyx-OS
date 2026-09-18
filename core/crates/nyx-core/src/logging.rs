//! Logging setup. Call `init()` at the top of every binary's `main()`.
//! Set `RUST_LOG=debug` for verbose output; default is warn-only.

use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_target(false)
        .compact()
        .init();
}
