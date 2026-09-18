//! Blocking clients for the Nyx daemon sockets. One line of JSON in, one
//! line of JSON out — always called from a background thread so it never
//! blocks the GTK main loop.

use nyx_core::{
    DevicesCommand, DevicesReport, DnsCommand, DnsReport, HealthCommand, HealthState,
    IdentityCommand, IdentityReport, IntegrityCommand, IntegrityReport, NyxOutput,
    TelemetryCommand, TelemetryReport, VpnCommand, VpnReport, DEVICES_SOCKET, DNS_SOCKET,
    HEALTH_SOCKET, IDENTITY_SOCKET, INTEGRITY_SOCKET, TELEMETRY_SOCKET, VPN_SOCKET,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn call<C: Serialize, R: DeserializeOwned>(socket: &str, cmd: &C) -> Result<R, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {socket}: {e}"))?;

    let mut line = serde_json::to_string(cmd).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("send: {e}"))?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|e| format!("recv: {e}"))?;

    serde_json::from_str(&response).map_err(|e| format!("bad response: {e}"))
}

pub fn send(cmd: HealthCommand) -> Result<NyxOutput<HealthState>, String> {
    call(HEALTH_SOCKET, &cmd)
}

pub fn send_vpn(cmd: VpnCommand) -> Result<NyxOutput<VpnReport>, String> {
    call(VPN_SOCKET, &cmd)
}

pub fn send_identity(cmd: IdentityCommand) -> Result<NyxOutput<IdentityReport>, String> {
    call(IDENTITY_SOCKET, &cmd)
}

pub fn send_devices(cmd: DevicesCommand) -> Result<NyxOutput<DevicesReport>, String> {
    call(DEVICES_SOCKET, &cmd)
}

pub fn send_telemetry(cmd: TelemetryCommand) -> Result<NyxOutput<TelemetryReport>, String> {
    call(TELEMETRY_SOCKET, &cmd)
}

pub fn send_dns(cmd: DnsCommand) -> Result<NyxOutput<DnsReport>, String> {
    call(DNS_SOCKET, &cmd)
}

pub fn send_integrity(cmd: IntegrityCommand) -> Result<NyxOutput<IntegrityReport>, String> {
    call(INTEGRITY_SOCKET, &cmd)
}
