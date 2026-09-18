//! Minimal blocking client shared by every step that talks to a Nyx daemon
//! socket — same newline-delimited-JSON protocol the dashboard already
//! uses, generalized over which socket and which command/response types.

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
