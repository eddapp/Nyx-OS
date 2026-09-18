//! `VpnCommand::ImportProfile` — turns a caller-supplied config (bytes over
//! the socket, not a path the daemon is asked to trust) into a real profile
//! under whichever backend's `PROFILE_DIR`, after a real protocol-shaped
//! sanity check. See each `validate_*` function for what "well-formed"
//! means per protocol — deliberately mirrors the same conventions each
//! backend module already parses its own profiles with (`openvpn.rs`'s
//! `dev`/`proto` line scan, `hysteria.rs`'s indentation-aware YAML scan,
//! `dante.rs`'s `SOCKS_SERVER_ADDR=` line), not a new ad-hoc format per
//! protocol.

use crate::util;
use nyx_core::{NyxError, NyxResult, VpnProtocol};
use std::net::SocketAddr;

/// Profile names become filesystem paths under a root-owned directory —
/// this rejects anything but a plain, single-component filename before any
/// path is ever built, independent of the protocol-specific content check
/// below.
pub(crate) fn valid_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 {
        return Err("profile name must be 1-128 characters".to_string());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        || name.starts_with('.')
        || name.contains("..")
    {
        return Err(format!(
            "profile name '{name}' is not a safe filename — only letters, digits, '-', '_', \
             '.' are allowed, and it can't start with '.' or contain '..'"
        ));
    }
    Ok(())
}

/// A real WireGuard/AmneziaWG config has an `[Interface]` section with a
/// real-shaped `PrivateKey` and at least one `[Peer]` section with a
/// real-shaped `PublicKey` and an `Endpoint` — checked against `wg-quick`'s
/// own documented `.conf` shape (`wg-quick(8)`), not just "the file has
/// some text in it".
fn validate_wireguard_like(contents: &str) -> Result<(), String> {
    let interface_start = contents.find("[Interface]").ok_or("missing an [Interface] section")?;
    let peer_start = contents.find("[Peer]").ok_or("missing a [Peer] section")?;
    if peer_start < interface_start {
        return Err("[Peer] appears before [Interface] — not a valid wg-quick config".to_string());
    }

    let interface_block = &contents[interface_start..peer_start];
    let private_key = interface_block
        .lines()
        .find_map(|l| l.trim().strip_prefix("PrivateKey").map(str::trim).and_then(|r| r.strip_prefix('=')))
        .map(str::trim)
        .ok_or("[Interface] has no PrivateKey= line")?;
    if !util::looks_like_wg_key(private_key) {
        return Err(
            "[Interface]'s PrivateKey isn't a real-shaped WireGuard key (44 base64 characters \
             decoding to 32 bytes)"
                .to_string(),
        );
    }

    let peer_block = &contents[peer_start..];
    let public_key = peer_block
        .lines()
        .find_map(|l| l.trim().strip_prefix("PublicKey").map(str::trim).and_then(|r| r.strip_prefix('=')))
        .map(str::trim)
        .ok_or("[Peer] has no PublicKey= line")?;
    if !util::looks_like_wg_key(public_key) {
        return Err(
            "[Peer]'s PublicKey isn't a real-shaped WireGuard key (44 base64 characters \
             decoding to 32 bytes)"
                .to_string(),
        );
    }
    if !peer_block.lines().any(|l| l.trim().starts_with("Endpoint")) {
        return Err("[Peer] has no Endpoint= line".to_string());
    }
    Ok(())
}

/// A real OpenVPN client config has a `remote <host> <port>` directive
/// (confirmed against `openvpn(8)`'s own `--remote` entry) and a `dev`
/// directive naming the tunnel device — the same two directives
/// `openvpn.rs`'s own `configured_device`/`up_via_socks_proxy` already
/// parse out of a real profile.
fn validate_openvpn(contents: &str) -> Result<(), String> {
    let remote_ok = contents.lines().any(|l| {
        let mut parts = l.split_whitespace();
        parts.next() == Some("remote") && parts.next().is_some()
    });
    if !remote_ok {
        return Err("no 'remote <host> <port>' directive found".to_string());
    }
    let dev_ok = contents.lines().any(|l| {
        let mut parts = l.split_whitespace();
        parts.next() == Some("dev") && parts.next().is_some()
    });
    if !dev_ok {
        return Err("no 'dev <name>' directive found".to_string());
    }
    Ok(())
}

/// A real Xray config's top level is a JSON object with a non-empty
/// `outbounds` array — the same field `xray.rs`'s own
/// `up_via_socks_proxy` already requires to exist before it will chain
/// anything through Tor.
fn validate_xray(contents: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("not valid JSON: {e}"))?;
    let outbounds = value.get("outbounds").and_then(|v| v.as_array()).ok_or("no outbounds[] array")?;
    if outbounds.is_empty() {
        return Err("outbounds[] is empty".to_string());
    }
    Ok(())
}

/// A real shadowsocks-rust client config is a JSON object naming a server,
/// port, password, and cipher method — the minimal single-server shape
/// documented in shadowsocks-rust's own README, and the same fields
/// `shadowsocks.rs` would need present for the process to do anything.
fn validate_shadowsocks(contents: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("not valid JSON: {e}"))?;
    for field in ["server", "server_port", "password", "method"] {
        if value.get(field).is_none() {
            return Err(format!("missing required field '{field}'"));
        }
    }
    Ok(())
}

/// Deliberately minimal — same scope as `hysteria.rs`'s own
/// `scan_listen_under`: not a real YAML parser, just enough to check the
/// two top-level keys a real Hysteria2 client config needs
/// (`server:`/`auth:`, per apernet/hysteria's own client config docs).
fn validate_hysteria(contents: &str) -> Result<(), String> {
    let has_top_level = |key: &str| {
        contents.lines().any(|l| {
            let indent = l.len() - l.trim_start().len();
            indent == 0 && l.trim().starts_with(key)
        })
    };
    if !has_top_level("server:") {
        return Err("no top-level 'server:' key found".to_string());
    }
    if !has_top_level("auth:") {
        return Err("no top-level 'auth:' key found".to_string());
    }
    Ok(())
}

/// Same format `dante.rs`'s own `read_socks_addr` parses from disk: a
/// plain `SOCKS_SERVER_ADDR=<ip>:<port>` line, IP literal only (no DNS
/// resolution in this backend).
fn validate_socks5(contents: &str) -> Result<(), String> {
    let value = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("SOCKS_SERVER_ADDR="))
        .ok_or("no SOCKS_SERVER_ADDR=<ip>:<port> line found")?;
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| format!("SOCKS_SERVER_ADDR '{value}' is not a literal ip:port"))
}

pub(crate) fn profile_dir_and_ext(protocol: VpnProtocol) -> (&'static str, &'static str) {
    match protocol {
        VpnProtocol::WireGuard => (crate::wireguard::PROFILE_DIR, "conf"),
        VpnProtocol::AmneziaWg => (crate::amneziawg::PROFILE_DIR, "conf"),
        VpnProtocol::OpenVpn => (crate::openvpn::PROFILE_DIR, "conf"),
        VpnProtocol::Xray => (crate::xray::PROFILE_DIR, "json"),
        VpnProtocol::Shadowsocks => (crate::shadowsocks::PROFILE_DIR, "json"),
        VpnProtocol::Hysteria2 => (crate::hysteria::PROFILE_DIR, "yaml"),
        VpnProtocol::Socks5 => (crate::dante::PROFILE_DIR, "conf"),
    }
}

/// Validate `contents` against `protocol`'s real, documented config shape,
/// then write it into that backend's `PROFILE_DIR` as `<name>.<ext>`. Never
/// writes anything that failed validation — a malformed file sitting in a
/// `PROFILE_DIR` would otherwise be silently picked up by that backend's
/// own `list_profiles()`/`up()` later and fail in a much more confusing
/// place than right here.
pub fn import_profile(protocol: VpnProtocol, name: &str, contents: &str) -> NyxResult<String> {
    valid_profile_name(name).map_err(NyxError::Config)?;

    let validation = match protocol {
        VpnProtocol::WireGuard | VpnProtocol::AmneziaWg => validate_wireguard_like(contents),
        VpnProtocol::OpenVpn => validate_openvpn(contents),
        VpnProtocol::Xray => validate_xray(contents),
        VpnProtocol::Shadowsocks => validate_shadowsocks(contents),
        VpnProtocol::Hysteria2 => validate_hysteria(contents),
        VpnProtocol::Socks5 => validate_socks5(contents),
    };
    validation.map_err(|e| NyxError::Config(format!("profile '{name}' rejected for {protocol:?}: {e}")))?;

    let (dir, ext) = profile_dir_and_ext(protocol);
    std::fs::create_dir_all(dir).map_err(|e| NyxError::Config(format!("creating {dir}: {e}")))?;
    let path = format!("{dir}/{name}.{ext}");
    util::write_private_file(&path, contents)
        .map_err(|e| NyxError::Config(format!("writing {path}: {e}")))?;

    Ok(format!("imported {protocol:?} profile '{name}' to {path}"))
}
