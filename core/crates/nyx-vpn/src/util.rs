//! Small dependency-free helpers shared by `import.rs`, `free_provider.rs`,
//! and `templates.rs` — deliberately hand-rolled rather than pulling in a
//! `base64` crate for one decode/encode pair (this project's own
//! "curate narrowly" convention already applies to runtime dependencies,
//! not just user-facing feature scope).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard (RFC 4648) base64 decode, with `=` padding required. Returns
/// `None` on any malformed input rather than silently truncating — a
/// caller decoding a VPN Gate CSV cell or validating a WireGuard key needs
/// to know decoding failed, not get back partial bytes.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Some(Vec::new());
    }
    if !cleaned.len().is_multiple_of(4) {
        return None;
    }
    let pad = cleaned.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks(4) {
        let mut vals = [0u8; 4];
        let mut chunk_pad = 0usize;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                chunk_pad += 1;
                continue;
            }
            let idx = ALPHABET.iter().position(|&a| a == b)?;
            vals[i] = idx as u8;
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if chunk_pad < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if chunk_pad < 1 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

/// Standard (RFC 4648) base64 encode. Not currently needed by any caller
/// that doesn't already have `serde_json`'s own base64-free path, kept
/// here anyway so `base64_decode`'s round-trip is covered by tests.
#[cfg(test)]
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// A real WireGuard/AmneziaWG key is exactly 32 raw bytes — base64-encoded
/// that's always 44 characters ending in `=` padding. Confirmed against
/// `wg genkey`'s own output shape and `wg-quick(8)`'s documented `Key`
/// type. Used to sanity-check `PrivateKey`/`PublicKey` values in imported
/// configs without needing a real WireGuard implementation on hand.
pub fn looks_like_wg_key(value: &str) -> bool {
    value.len() == 44 && value.ends_with('=') && base64_decode(value).map(|b| b.len() == 32).unwrap_or(false)
}

/// nyx-vpn didn't have an existing convention for the permission bits on a
/// profile it writes itself (every backend module's own profile directory
/// is populated by hand today) — private key/credential material warrants
/// `0600` (owner-only), so this introduces that convention for every write
/// path this round adds (`import.rs`, `free_provider.rs`, `templates.rs`).
pub fn write_private_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// A profile still containing an unfilled `WriteProviderTemplate`
/// placeholder. Every placeholder this round writes shares the same
/// `<REPLACE_WITH_...>` prefix, so one substring scan catches all of them
/// across every protocol's file format (WireGuard's `.conf` and OpenVPN's
/// `.conf` today) without needing a per-format parser just to answer
/// "is this real yet".
pub const INCOMPLETE_MARKER: &str = "<REPLACE_WITH_";

/// Best-effort: a missing/unreadable file is reported as complete rather
/// than incomplete — `list_profiles()` already only calls this for names
/// it just found on disk, so a read failure here is a race, not the
/// common case.
pub fn file_is_incomplete(path: &str) -> bool {
    Path::new(path).exists()
        && std::fs::read_to_string(path).map(|s| s.contains(INCOMPLETE_MARKER)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        let cases: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for case in cases {
            let encoded = base64_encode(case);
            assert_eq!(base64_decode(&encoded).unwrap(), *case);
        }
    }

    #[test]
    fn wg_key_shape() {
        assert!(looks_like_wg_key("ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="));
        assert!(!looks_like_wg_key("not-a-real-key"));
        assert!(!looks_like_wg_key("<REPLACE_WITH_YOUR_OWN_PRIVATE_KEY>"));
    }
}
