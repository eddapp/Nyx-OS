//! Blocking client for the nyx-health control socket. One line of JSON in,
//! one line of JSON out — called from a background thread so it never blocks
//! the GTK main loop.

use nyx_core::{HealthCommand, HealthState, NyxOutput};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub fn send(cmd: HealthCommand) -> Result<NyxOutput<HealthState>, String> {
    let mut stream =
        UnixStream::connect(nyx_core::HEALTH_SOCKET).map_err(|e| format!("connect: {e}"))?;

    let mut line = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(|e| format!("send: {e}"))?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|e| format!("recv: {e}"))?;

    serde_json::from_str(&response).map_err(|e| format!("bad response: {e}"))
}
