#!/usr/bin/env bash
# =============================================================================
# Nyx OS Bootstrap Script
# Assumes Rust (rustc/cargo) and all deps are already installed on Arch Linux
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log()     { echo -e "${CYAN}[NYX]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[!!]${RESET}  $*"; }
error()   { echo -e "${RED}[ERR]${RESET} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}\n"; }

NYXARCH_DIR="$HOME/nyx"
CRATES=(nyx-core nyx-health nyx-tor nyx-dns nyx-route nyx-wipe nyx-integrity)

# =============================================================================
# STEP 1 — Preflight
# =============================================================================
header "Preflight"

[[ "$EUID" -eq 0 ]] && error "Don't run as root."

command -v rustc &>/dev/null || error "rustc not found. Install: sudo pacman -S rust"
command -v cargo &>/dev/null || error "cargo not found. Install: sudo pacman -S rust"

success "rustc: $(rustc --version)"
success "cargo: $(cargo --version)"

if [[ -d "$NYXARCH_DIR" ]]; then
    warn "Directory $NYXARCH_DIR already exists."
    read -rp "  Overwrite and start fresh? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { log "Aborted. Nothing changed."; exit 0; }
    rm -rf "$NYXARCH_DIR"
    success "Cleared existing directory."
fi

# =============================================================================
# STEP 2 — Workspace skeleton
# =============================================================================
header "Workspace structure"

mkdir -p "$NYXARCH_DIR"
cd "$NYXARCH_DIR"

log "Writing workspace Cargo.toml..."
cat > Cargo.toml << 'TOML'
[workspace]
members = [
    "crates/nyx-core",
    "crates/nyx-health",
    "crates/nyx-tor",
    "crates/nyx-dns",
    "crates/nyx-route",
    "crates/nyx-wipe",
    "crates/nyx-integrity",
]
resolver = "2"

[workspace.dependencies]
serde              = { version = "1", features = ["derive"] }
serde_json         = "1"
thiserror          = "1"
tokio              = { version = "1", features = ["full"] }
tracing            = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow             = "1"
clap               = { version = "4", features = ["derive"] }
TOML
success "Workspace Cargo.toml written."

# =============================================================================
# STEP 3 — Scaffold crates
# =============================================================================
header "Scaffolding crates"

mkdir -p crates
for crate in "${CRATES[@]}"; do
    cargo new --lib "crates/$crate" --quiet
    success "  crates/$crate"
done

# =============================================================================
# STEP 4 — nyx-core
# =============================================================================
header "nyx-core — shared foundation"

NYX_CORE="$NYXARCH_DIR/crates/nyx-core"

cat > "$NYX_CORE/Cargo.toml" << 'TOML'
[package]
name        = "nyx-core"
version     = "0.1.0"
edition     = "2021"
description = "Nyx OS shared types, error handling, and structured output"

[dependencies]
serde              = { workspace = true }
serde_json         = { workspace = true }
thiserror          = { workspace = true }
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }
TOML

cat > "$NYX_CORE/src/lib.rs" << 'RUST'
//! nyx-core — shared foundation for all Nyx OS binaries

pub mod error;
pub mod output;
pub mod logging;

pub use error::{NyxError, NyxResult};
pub use output::{NyxOutput, Status};
RUST

cat > "$NYX_CORE/src/error.rs" << 'RUST'
use thiserror::Error;

/// Central error type. No .unwrap() in production — everything goes through here.
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

    #[error("wipe error: {0}")]
    Wipe(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type NyxResult<T> = Result<T, NyxError>;
RUST

cat > "$NYX_CORE/src/output.rs" << 'RUST'
//! Structured JSON output — every Nyx OS binary prints this format.
//! The dashboard and Conky monitor both parse this.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
    Warning,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NyxOutput<T: Serialize> {
    pub status:  Status,
    pub binary:  String,
    pub command: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> NyxOutput<T> {
    pub fn ok(
        binary:  impl Into<String>,
        command: impl Into<String>,
        message: impl Into<String>,
        data:    Option<T>,
    ) -> Self {
        Self {
            status:  Status::Ok,
            binary:  binary.into(),
            command: command.into(),
            message: message.into(),
            data,
        }
    }

    pub fn warn(
        binary:  impl Into<String>,
        command: impl Into<String>,
        message: impl Into<String>,
    ) -> NyxOutput<()> {
        NyxOutput {
            status:  Status::Warning,
            binary:  binary.into(),
            command: command.into(),
            message: message.into(),
            data:    None,
        }
    }

    pub fn print(&self) {
        println!("{}", serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| r#"{"status":"error","message":"output serialization failed"}"#.into()));
    }
}

pub fn print_error(binary: &str, command: &str, message: &str) {
    let out = NyxOutput::<()> {
        status:  Status::Error,
        binary:  binary.into(),
        command: command.into(),
        message: message.into(),
        data:    None,
    };
    eprintln!("{}", serde_json::to_string_pretty(&out)
        .unwrap_or_else(|_| format!(r#"{{"status":"error","message":"{}"}}"#, message)));
}
RUST

cat > "$NYX_CORE/src/logging.rs" << 'RUST'
//! Logging setup. Call init() at the top of every binary's main().
//! Set RUST_LOG=debug for verbose output, default is warn-only.

use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .compact()
        .init();
}
RUST

success "nyx-core written."

# =============================================================================
# STEP 5 — Wire remaining crates to nyx-core
# =============================================================================
header "Wiring crates"

for crate in nyx-health nyx-tor nyx-dns nyx-route nyx-wipe nyx-integrity; do
    TOML_PATH="$NYXARCH_DIR/crates/$crate/Cargo.toml"

    cat >> "$TOML_PATH" << TOML

[dependencies]
nyx-core   = { path = "../nyx-core" }
serde      = { workspace = true }
serde_json = { workspace = true }
thiserror  = { workspace = true }
tokio      = { workspace = true }
clap       = { workspace = true }
TOML

    cat > "$NYXARCH_DIR/crates/$crate/src/lib.rs" << RUST
//! $crate — stub, not yet implemented
pub use nyx_core::{NyxError, NyxResult};
RUST

    success "  $crate"
done

# =============================================================================
# STEP 6 — Project directories
# =============================================================================
header "Project directories"

mkdir -p "$NYXARCH_DIR"/{dashboard,config,install,docs}
mkdir -p "$NYXARCH_DIR/config"/{nftables,torrc,profiles,dns}
mkdir -p "$NYXARCH_DIR/install"/{archinstall,pkgbuild}
mkdir -p "$NYXARCH_DIR/docs"/{binaries,architecture}

cat > "$NYXARCH_DIR/README.md" << 'MD'
# Nyx OS

Privacy-focused Arch Linux OS. Rust binaries. No shell script soup.

## Workspace

| Crate | Purpose |
|---|---|
| nyx-core | Shared types, error handling, JSON output, logging |
| nyx-health | Kill switches, panic modes, identity randomization |
| nyx-tor | Tor lifecycle, multi-instance, exit node control |
| nyx-dns | DNS management, DNSCrypt, leak detection |
| nyx-route | Protocol switching: WireGuard, OpenVPN, Shadowsocks, V2Ray |
| nyx-wipe | Secure deletion, RAM wipe, anti-forensics |
| nyx-integrity | File integrity, permission monitoring |

## Build

```bash
cargo build
cargo build --release
```

## Dashboard

Tauri 2 + Svelte 5 — lives in dashboard/
MD

success "Directories and README created."

# =============================================================================
# STEP 7 — Build verification
# =============================================================================
header "Build verification"

cd "$NYXARCH_DIR"
log "Running cargo build..."

if cargo build 2>&1; then
    success "Workspace builds clean."
else
    error "Build failed — check output above."
fi

# =============================================================================
# Done
# =============================================================================
header "Nyx OS bootstrap complete"

echo -e "${BOLD}Workspace:${RESET} $NYXARCH_DIR"
echo ""
echo -e "${BOLD}Crates:${RESET}"
for crate in "${CRATES[@]}"; do
    echo -e "  ${GREEN}✓${RESET} $crate"
done
echo ""
echo -e "${BOLD}Next:${RESET} cd $NYXARCH_DIR"
echo -e "Start with ${CYAN}crates/nyx-health/src/lib.rs${RESET}"
echo -e "That's the kill switch and panic system — everything else depends on it."
