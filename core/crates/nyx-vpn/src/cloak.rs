//! Cloak (`cbeuw/Cloak`) client backend — `ck-client`, the client half of a
//! pluggable-transport obfuscation layer that disguises another proxy's
//! traffic as ordinary HTTPS to an innocuous domain (domain fronting), to
//! evade DPI-based censorship. NyxOS is a client-only tool (no relay
//! infrastructure of its own), so this only ever drives `ck-client`
//! against a Cloak server the user already has real credentials for —
//! never `ck-server`.
//!
//! Confirmed against upstream Cloak (v2.10.0, matching what the AUR's
//! `cloak-obfuscation-bin` package currently builds — its PKGBUILD installs
//! exactly `/usr/bin/ck-client` and `/usr/bin/ck-server`) — its own
//! `cmd/ck-client/ck-client.go`: `ck-client` is a plain local TCP/UDP
//! listener (`-i`/`-l`, default `127.0.0.1:1984`) for an underlying proxy
//! client to connect to, which then dials out to a Cloak server
//! (`-s`/`-p`, i.e. `RemoteHost`/`RemotePort` in its JSON config) and
//! multiplexes the disguised traffic there. It is *not* a SOCKS proxy —
//! nothing negotiates a SOCKS handshake through it, the underlying client
//! just dials it as if it were the real remote server — so this is a
//! parallel mechanism to `socks_override.rs`'s VPN-over-Tor chaining, not
//! the same one. Only OpenVPN is wired up here (see `openvpn.rs`'s
//! `up_via_cloak`, which does the actual redirect); this module owns only
//! `ck-client`'s own lifecycle and config.
//!
//! Lifecycle is a templated systemd unit (`nyx-vpn-cloak@<profile>.service`,
//! see `packaging/`) — the AUR package ships no unit of its own, so this
//! project supplies one, same convention as `nyx-vpn-xray@.service`/
//! `nyx-vpn-hysteria@.service`. `ck-client`'s own real JSON config
//! (`ckclient.json` shape, confirmed against Cloak's
//! `internal/client/state.go` `RawConfig` struct and its own
//! `example_config/ckclient.json`) is generated fresh into `/run/nyx` per
//! connection attempt — there's no persistent Cloak "profile" on disk the
//! way Xray/Hysteria2 have, since `VpnCommand::ConnectViaCloak` carries the
//! Cloak parameters inline (the same shape `SocksProxyAddr` already does
//! for VPN-over-Tor chaining) rather than naming a stored profile.
//!
//! Before ever touching OpenVPN, this starts `ck-client` and does a real
//! TCP connect check against its own local listener — process-active is
//! not proof it's accepting connections yet, the same "verify, don't
//! assume" bar `handler.rs` already holds Tor's SocksPort to before
//! dialing through it.

use nyx_core::{CloakConfig, NyxError, NyxResult};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

/// `ck-client`'s own documented default local listener (`-i 127.0.0.1 -l
/// 1984`) — fixed rather than configurable, since NyxOS never runs more
/// than one VPN tunnel at once, so there's no port-collision risk to guard
/// against.
const CLOAK_LOCAL_HOST: &str = "127.0.0.1";
const CLOAK_LOCAL_PORT: u16 = 1984;

/// Fixed to `"openvpn"` — must match the key the Cloak server operator
/// configured in their own `ckserver.json`'s `ProxyBook` for the OpenVPN
/// server sitting behind it. Not user-configurable here: this command is
/// explicitly OpenVPN-only (see `VpnCommand::ConnectViaCloak`'s doc
/// comment), so exposing an arbitrary `ProxyMethod` would misrepresent
/// what this integration actually verified.
const PROXY_METHOD: &str = "openvpn";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-cloak@{profile}.service")
}

fn ckclient_config_path(profile: &str) -> String {
    format!("{}/nyx-vpn-cloak-{profile}-ckclient.json", crate::socks_override::RUNTIME_DIR)
}

/// Real TCP connect check against `ck-client`'s own local listener, polled
/// until it accepts a connection or `timeout` elapses — same shape as
/// `dante.rs`'s `wait_for_interface`, just checking a TCP listener instead
/// of a kernel interface.
async fn wait_for_local_port(host: &str, port: u16, timeout: Duration) -> bool {
    let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() else {
        return false;
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Best-effort rollback of just the `ck-client` side (unit + override +
/// generated config) — used both by `down_ckclient` (the general teardown
/// path, called from `openvpn::down` unconditionally) and internally by
/// `up` when a later step fails after `ck-client` was already started.
async fn teardown_ckclient(conn: &Connection, profile: &str) {
    let unit = unit_name(profile);
    let _ = crate::systemd_ctl::stop_unit(conn, &unit).await;
    crate::socks_override::remove_exec_start_override(&unit);
    let _ = std::fs::remove_file(ckclient_config_path(profile));
    let _ = crate::systemd_ctl::reload(conn).await;
}

/// Public alias for the teardown path `openvpn::down` calls unconditionally
/// on every disconnect/reconnect — a no-op if this profile was never
/// brought up via Cloak.
pub async fn down_ckclient(conn: &Connection, profile: &str) {
    teardown_ckclient(conn, profile).await;
}

/// Bring up OpenVPN-over-Cloak for `profile`: writes `ck-client`'s own
/// config, starts it under its templated unit, verifies its local listener
/// is really accepting connections, then hands off to
/// `openvpn::up_via_cloak` to redirect `profile`'s OpenVPN connection at
/// it. Any failure at any step rolls back everything started so far.
pub async fn up(conn: &Connection, profile: &str, cfg: &CloakConfig) -> NyxResult<()> {
    if cfg.remote_host.trim().is_empty() {
        return Err(NyxError::Config("Cloak config: remote_host is empty".to_string()));
    }
    if cfg.public_key.trim().is_empty() {
        return Err(NyxError::Config("Cloak config: public_key is empty".to_string()));
    }
    if cfg.uid.trim().is_empty() {
        return Err(NyxError::Config("Cloak config: uid is empty".to_string()));
    }
    if cfg.server_name.trim().is_empty() {
        return Err(NyxError::Config("Cloak config: server_name is empty".to_string()));
    }
    if cfg.encryption_method.eq_ignore_ascii_case("plain") {
        return Err(NyxError::Config(
            "Cloak config: encryption_method 'plain' is refused when wrapping OpenVPN — \
             Cloak's own docs warn OpenVPN's handshake has a recognizable fingerprint that \
             plaintext framing wouldn't hide, defeating the point of wrapping it; use \
             'aes-256-gcm', 'aes-128-gcm', or 'chacha20-poly1305' instead"
                .to_string(),
        ));
    }

    // OpenVPN's default transport is UDP (see openvpn.rs's own
    // `configured_proto` doc comment) — Cloak's client config has a real
    // `UDP` field for exactly this, so the profile's own declared/implied
    // transport is passed straight through instead of asking the caller
    // to repeat it.
    let udp = !matches!(
        crate::openvpn::configured_proto(profile).as_deref(),
        Some("tcp-client") | Some("tcp4-client") | Some("tcp6-client")
    );

    let config_json = serde_json::json!({
        "Transport": "direct",
        "ProxyMethod": PROXY_METHOD,
        "EncryptionMethod": cfg.encryption_method,
        "UID": cfg.uid,
        "PublicKey": cfg.public_key,
        "ServerName": cfg.server_name,
        "NumConn": cfg.num_conn.unwrap_or(4),
        "BrowserSig": cfg.browser_sig.clone().unwrap_or_else(|| "chrome".to_string()),
        "RemoteHost": cfg.remote_host,
        "RemotePort": cfg.remote_port.to_string(),
        "LocalHost": CLOAK_LOCAL_HOST,
        "LocalPort": CLOAK_LOCAL_PORT.to_string(),
        "UDP": udp,
    });

    let config_path = ckclient_config_path(profile);
    std::fs::create_dir_all(crate::socks_override::RUNTIME_DIR)
        .map_err(|e| NyxError::Config(format!("creating {}: {e}", crate::socks_override::RUNTIME_DIR)))?;
    let rendered = serde_json::to_vec_pretty(&config_json).map_err(NyxError::from)?;
    std::fs::write(&config_path, rendered)
        .map_err(|e| NyxError::Config(format!("writing ck-client config for '{profile}': {e}")))?;

    let unit = unit_name(profile);
    let exec_start = format!("/usr/bin/ck-client -c {config_path}");
    if let Err(e) = crate::socks_override::write_exec_start_override(&unit, &exec_start) {
        let _ = std::fs::remove_file(&config_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::reload(conn).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = std::fs::remove_file(&config_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::start_unit(conn, &unit).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = std::fs::remove_file(&config_path);
        let _ = crate::systemd_ctl::reload(conn).await;
        return Err(e);
    }

    if !wait_for_local_port(CLOAK_LOCAL_HOST, CLOAK_LOCAL_PORT, Duration::from_secs(5)).await {
        teardown_ckclient(conn, profile).await;
        return Err(NyxError::Network(format!(
            "ck-client for '{profile}' started but its local listener at \
             {CLOAK_LOCAL_HOST}:{CLOAK_LOCAL_PORT} never accepted a connection — refusing to \
             point OpenVPN at it"
        )));
    }

    if let Err(e) =
        crate::openvpn::up_via_cloak(conn, profile, CLOAK_LOCAL_HOST, CLOAK_LOCAL_PORT).await
    {
        teardown_ckclient(conn, profile).await;
        return Err(e);
    }

    Ok(())
}
