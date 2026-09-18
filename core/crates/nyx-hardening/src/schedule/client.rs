//! Minimal blocking client for the Nyx daemon control sockets — same
//! newline-delimited-JSON protocol every daemon speaks
//! (`nyx-core::protocol`), generalized over which socket and which
//! command/response types. Mirrors `nyx-diagnostics/src/client.rs`'s
//! `call()` exactly (connect, write one JSON line, read one JSON line
//! back) rather than inventing a second implementation of the same
//! protocol.
//!
//! Used only by `nyx-hardening schedule exec <task>` — the two scheduled
//! tasks that are backed by an already-running root daemon rather than a
//! standalone CLI (`randomize-mac` -> nyx-identity, `renew-tor-circuit` ->
//! nyx-health) go through this, so the systemd service unit's
//! `ExecStart=` can just re-invoke `nyx-hardening` itself.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub fn call<C: Serialize, R: DeserializeOwned>(socket: &str, cmd: &C) -> Result<R, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {socket}: {e}"))?;

    let mut line = serde_json::to_string(cmd).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("send to {socket}: {e}"))?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|e| format!("recv from {socket}: {e}"))?;

    serde_json::from_str(&response).map_err(|e| format!("bad response from {socket}: {e}"))
}
