//! Real DNS-path checks. Every function here inspects actual system state —
//! nothing is inferred from "a process with this name exists".

use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

const RESOLV_CONF: &str = "/etc/resolv.conf";
const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Domain used only to prove the resolver at 127.0.0.1:53 completes queries
/// end-to-end. Any well-formed response (including NXDOMAIN) counts —
/// we're checking the local resolver works, not that the internet exists.
const PROBE_DOMAIN: &str = "cloudflare.com";

/// Nameserver lines from `/etc/resolv.conf`, in file order.
pub fn resolv_conf_nameservers() -> Vec<String> {
    let contents = match fs::read_to_string(RESOLV_CONF) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver").map(|rest| rest.trim().to_string()))
        .collect()
}

/// True only if every configured nameserver is loopback. An empty list is
/// NOT local — that means resolution would fall through to whatever the
/// resolver library defaults to, which we can't vouch for.
pub fn resolver_is_local(nameservers: &[String]) -> bool {
    !nameservers.is_empty()
        && nameservers
            .iter()
            .all(|ns| ns == "127.0.0.1" || ns == "::1")
}

/// Parse a hex, little-endian-per-32-bit-word IPv4 address as it appears in
/// `/proc/net/{tcp,udp}`'s `local_address` field (e.g. "0100007F" -> 127.0.0.1).
fn parse_proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::new(
        (n & 0xFF) as u8,
        ((n >> 8) & 0xFF) as u8,
        ((n >> 16) & 0xFF) as u8,
        ((n >> 24) & 0xFF) as u8,
    ))
}

/// Scan a `/proc/net/{tcp,tcp6,udp,udp6}`-shaped table for entries bound to
/// `port` on something other than loopback. Returns true on the first such
/// entry found; malformed/unreadable tables are treated as "nothing found"
/// rather than an error, since /proc layout can vary and we'd rather under-
/// report than crash the daemon over a parsing edge case.
fn table_has_foreign_listener(path: &str, port: u16, is_v6: bool) -> bool {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(local) = fields.first() else { continue };
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(bound_port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if bound_port != port {
            continue;
        }

        if is_v6 {
            // We don't expect any IPv6 DNS listener at all (dnscrypt-proxy is
            // configured with ipv6_servers = false and binds v4-only), so any
            // hit here is foreign regardless of address.
            return true;
        }

        match parse_proc_ipv4(addr_hex) {
            Some(addr) if !addr.is_loopback() => return true,
            Some(_) => {} // loopback — expected, that's dnscrypt-proxy
            None => {}
        }
    }
    false
}

/// True if anything besides a loopback-bound process is listening on port 53
/// — the leak-relevant signal: a path around the enforced resolver exists.
pub fn foreign_listener_on_53() -> bool {
    table_has_foreign_listener("/proc/net/tcp", DNS_PORT, false)
        || table_has_foreign_listener("/proc/net/udp", DNS_PORT, false)
        || table_has_foreign_listener("/proc/net/tcp6", DNS_PORT, true)
        || table_has_foreign_listener("/proc/net/udp6", DNS_PORT, true)
}

/// Hand-rolled minimal DNS query (RFC 1035 header + one question) — kept
/// dependency-free and small enough to read end-to-end in one sitting rather
/// than pulling in a full resolver crate for a single probe packet.
fn build_query(id: u16, qname: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in qname.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root label
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    msg
}

/// Send [`PROBE_DOMAIN`] to 127.0.0.1:53 and confirm we get back a
/// well-formed response with a matching transaction ID. Any RCODE counts —
/// this proves the loopback resolver is alive and answering, which is the
/// property nyx-dns is responsible for; whether the *answer* is correct is
/// outside its scope.
pub fn probe_local_resolver() -> bool {
    let id: u16 = std::process::id() as u16;
    let query = build_query(id, PROBE_DOMAIN);

    let socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if socket.set_read_timeout(Some(QUERY_TIMEOUT)).is_err() {
        return false;
    }
    if socket.send_to(&query, ("127.0.0.1", DNS_PORT)).is_err() {
        return false;
    }

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) if len >= 12 => {
            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
            let flags = u16::from_be_bytes([buf[2], buf[3]]);
            let is_response = flags & 0x8000 != 0;
            resp_id == id && is_response
        }
        _ => false,
    }
}
