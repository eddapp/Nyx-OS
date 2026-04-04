#!/usr/bin/env bash
set -euo pipefail

echo "[NYX] Initializing workspace..."

mkdir -p nyx && cd nyx
cargo new --lib crates/nyx-core
cargo new --lib crates/nyx-route
cargo new --lib crates/nyx-dns
cargo new --lib crates/nyx-tor
cargo new --lib crates/nyx-health
cargo new --lib crates/nyx-integrity
cargo new --lib crates/nyx-wipe

echo "[OK] Workspace scaffolded."
