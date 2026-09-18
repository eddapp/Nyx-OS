//! Parsing for `/proc/net/{tcp,tcp6,udp,udp6}`. The hex address:port and
//! IPv4 decoding here is the same real format `nyx-dns/src/checks.rs`
//! already parses (`parse_proc_ipv4`) — adapted rather than reimplemented
//! from scratch, and extended with the IPv6 and per-entry state/inode
//! fields nyx-dns doesn't need but nyx-watch does.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP socket states as they appear (hex) in `/proc/net/tcp{,6}`'s `st`
/// field — from the kernel's `enum` in `include/net/tcp_states.h`. Only the
/// two nyx-watch actually cares about are named; every other value is
/// still parsed but simply doesn't match either filter.
pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_LISTEN: u8 = 0x0A;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketEntry {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    /// Raw `st` field. For UDP this is not a TCP-style state machine value
    /// (UDP has no LISTEN/ESTABLISHED concept) — callers should not filter
    /// on it for UDP tables, only TCP ones.
    pub state: u8,
    /// The socket's inode number, usable to look up the owning process via
    /// `/proc/*/fd/*` — see `sockets::inode_to_pid`.
    pub inode: u64,
}

/// Parse a hex, little-endian-per-32-bit-word IPv4 address as it appears in
/// `/proc/net/{tcp,udp}`'s address fields (e.g. "0100007F" -> 127.0.0.1).
/// Copied from `nyx-dns/src/checks.rs::parse_proc_ipv4` — same field, same
/// format, no reason to re-derive it differently here.
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

/// Parse a hex IPv6 address as it appears in `/proc/net/{tcp6,udp6}`: four
/// 8-hex-char groups, each one a 32-bit word printed with the same
/// little-endian-per-word trick as the IPv4 case above (the kernel formats
/// each word with `%08X` after reading it back in host/little-endian byte
/// order). Not present in nyx-dns (it only checks IPv4 loopback there), but
/// the same underlying `/proc` convention, documented in `ip6_hex_parse`
/// implementations elsewhere (e.g. `proc_net_addr` in the kernel, and every
/// third-party `/proc/net/tcp6` parser that has to reproduce it).
fn parse_proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}`-shaped table. Unreadable files
/// or malformed lines are skipped rather than treated as fatal — same
/// "under-report rather than crash" stance `nyx-dns/src/checks.rs` takes,
/// since `/proc` layout can in principle vary and a daemon watching for
/// change shouldn't itself become the thing that goes down.
pub fn parse_table(path: &str, is_v6: bool) -> Vec<SocketEntry> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx_queue:rx_queue tr:tm->when
        // retrnsmt uid timeout inode ... — inode is field index 9.
        if fields.len() < 10 {
            continue;
        }
        let Some((local_hex, local_port_hex)) = fields[1].split_once(':') else { continue };
        let Some((rem_hex, rem_port_hex)) = fields[2].split_once(':') else { continue };
        let Ok(state) = u8::from_str_radix(fields[3], 16) else { continue };
        let Ok(local_port) = u16::from_str_radix(local_port_hex, 16) else { continue };
        let Ok(remote_port) = u16::from_str_radix(rem_port_hex, 16) else { continue };
        let Ok(inode) = fields[9].parse::<u64>() else { continue };

        let addrs = if is_v6 {
            match (parse_proc_ipv6(local_hex), parse_proc_ipv6(rem_hex)) {
                (Some(l), Some(r)) => Some((IpAddr::V6(l), IpAddr::V6(r))),
                _ => None,
            }
        } else {
            match (parse_proc_ipv4(local_hex), parse_proc_ipv4(rem_hex)) {
                (Some(l), Some(r)) => Some((IpAddr::V4(l), IpAddr::V4(r))),
                _ => None,
            }
        };
        let Some((local_addr, remote_addr)) = addrs else { continue };

        out.push(SocketEntry { local_addr, local_port, remote_addr, remote_port, state, inode });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_loopback() {
        assert_eq!(parse_proc_ipv4("0100007F"), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parses_ipv6_loopback() {
        // ::1 in the kernel's per-word little-endian encoding.
        assert_eq!(parse_proc_ipv6("00000000000000000000000001000000"), Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn parses_real_tcp_table_without_panicking() {
        // Content is inherently host-dependent, so this only confirms the
        // parser survives whatever this machine's live table contains and
        // every entry gets a syntactically valid address, not that any
        // particular socket exists.
        let entries = parse_table("/proc/net/tcp", false);
        for entry in &entries {
            assert!(entry.local_addr.is_ipv4());
        }
    }
}
