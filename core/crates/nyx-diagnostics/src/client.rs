//! Minimal blocking client for the Nyx daemon sockets — same
//! newline-delimited-JSON protocol every daemon speaks, generalized over
//! which socket and which command/response types. Failing to reach a
//! daemon is reported as an error for that one check, not fatal to the
//! rest of the report — a daemon that isn't running is itself diagnostic
//! information.

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
