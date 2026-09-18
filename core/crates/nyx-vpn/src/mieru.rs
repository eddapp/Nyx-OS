//! mieru backend (github.com/enfein/mieru) — an anti-censorship SOCKS5/
//! HTTP/HTTPS proxy protocol distinct from every other backend this crate
//! drives: it uses XChaCha20-Poly1305 AEAD with random, non-encrypted
//! padding segments and an independent replay cache on both the client
//! and server side, specifically to resist DPI/GFW-style traffic
//! classification (confirmed against upstream's own `docs/protocol.md`).
//! Client binary is `mieru`; the server binary `mita` is a wholly separate
//! package this crate never touches, since nyx-vpn only ever dials out as
//! a client.
//!
//! Not packaged in Arch's official repos or the AUR at all (checked
//! directly via `pacman -Si`/the AUR RPC API — zero results), so this
//! project ships its own `install/pkgbuild/mieru/PKGBUILD`, a prebuilt-
//! binary package sourced from upstream's own GitHub Releases
//! (`mieru_<ver>_linux_amd64.tar.gz`, a single statically-linked ELF
//! binary named `mieru` — confirmed by downloading and inspecting the
//! actual release asset).
//!
//! Config format: confirmed against upstream's own
//! `docs/client-install.md`. The client's config file is one JSON object
//! with a top-level `profiles` array (each entry: `profileName`, `user`
//! `{name, password}`, `servers` `[{ipAddress, portBindings}]`, `mtu`,
//! `multiplexing.level`, `handshakeMode`, and an optional `dialer` for
//! upstream SOCKS5 chaining — see [`up_via_socks_proxy`]), plus top-level
//! `activeProfile`, `rpcPort`, `socks5Port`, `socks5ListenLAN`, and
//! `httpProxyPort`. Each profile file under [`PROFILE_DIR`] is one such
//! complete config, the same "one file, one full config" shape
//! `xray.rs`'s profiles use.
//!
//! `mieru start`/`stop` are the CLI's own self-daemonizing background-
//! process management (fork + its own PID tracking) — not something a
//! systemd unit should supervise on top of. Upstream's own help text
//! documents a second mode "for developers and experienced users": `mieru
//! run`, which stays in the foreground and loads its config from the
//! `MIERU_CONFIG_JSON_FILE` environment variable. That's the one real
//! supervision hooks into here (confirmed by actually running the release
//! binary with a test config: `mieru run` opened a listener on the
//! configured `socks5Port` and a separate RPC control listener on
//! `rpcPort`, then stayed in the foreground logging normally — exactly
//! what a `Type=simple` unit needs). Lifecycle is therefore a templated
//! systemd unit (`nyx-vpn-mieru@<name>.service`, see `packaging/`), same
//! shape as `openvpn.rs` driving `openvpn-client@.service`.
//!
//! Like Xray/Shadowsocks, mieru is not a kernel-level tunnel and exposes
//! no handshake-recency concept over a simple CLI query (its RPC control
//! port is for its own CLI's `describe`/`get metrics` subcommands, not a
//! documented public status protocol nyx-vpn should reimplement). So "is
//! it really working" here is process-alive plus a best-effort check that
//! *something* is accepting TCP connections on the profile's configured
//! `socks5Port` — `handler.rs` never reports this protocol as `Protected`.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

const PROFILE_DIR: &str = "/etc/nyx/mieru";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-mieru@{profile}.service")
}

fn runtime_config_path(profile: &str) -> String {
    format!("{}/nyx-vpn-mieru-{profile}-via-tor.json", crate::socks_override::RUNTIME_DIR)
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                path.file_stem().and_then(|s| s.to_str()).map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

pub async fn up(conn: &Connection, profile: &str) -> NyxResult<()> {
    crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await
}

pub async fn down(conn: &Connection, profile: &str) -> NyxResult<()> {
    let unit = unit_name(profile);
    let result = crate::systemd_ctl::stop_unit(conn, &unit).await;
    // Best-effort: undo any VPN-over-Tor override/runtime config so a
    // later plain `up()` doesn't silently keep dialing through Tor.
    crate::socks_override::remove_exec_start_override(&unit);
    let _ = fs::remove_file(runtime_config_path(profile));
    let _ = crate::systemd_ctl::reload(conn).await;
    result
}

/// VPN-over-Tor chaining. mieru's own client config has a documented
/// per-profile `dialer` object (confirmed against `docs/client-install.md`:
/// `{"protocol": "SOCKS5_PROXY_PROTOCOL", "host": ..., "port": ...,
/// "socks5Authentication": {...}}`, described as routing the client's own
/// connection to its mieru server through an upstream SOCKS5 proxy) — the
/// same real, upstream-documented shape this project already requires
/// before honoring `VpnCommand::ConnectViaSocksProxy` for a backend.
///
/// This reads the profile's own JSON, finds the profile object named by
/// top-level `activeProfile` inside `profiles[]`, sets its `dialer` to
/// point at the given proxy, and writes the result to a *runtime-only*
/// copy — the profile file on disk is never rewritten. The templated
/// unit's `ExecStart=` is then overridden via a drop-in (see
/// `socks_override.rs`) to point `MIERU_CONFIG_JSON_FILE` at that runtime
/// copy instead of the original.
pub async fn up_via_socks_proxy(
    conn: &Connection,
    profile: &str,
    socks_host: &str,
    socks_port: u16,
) -> NyxResult<()> {
    let original_path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(&original_path)
        .map_err(|e| NyxError::Config(format!("reading mieru profile '{profile}': {e}")))?;
    let mut config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| NyxError::Config(format!("parsing mieru profile '{profile}': {e}")))?;

    let active_name = config
        .get("activeProfile")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NyxError::Config(format!("mieru profile '{profile}' has no activeProfile")))?
        .to_string();

    let profiles = config
        .get_mut("profiles")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| NyxError::Config(format!("mieru profile '{profile}' has no profiles[] to chain through Tor")))?;

    let active_profile = profiles
        .iter_mut()
        .find(|p| p.get("profileName").and_then(|v| v.as_str()) == Some(active_name.as_str()))
        .ok_or_else(|| {
            NyxError::Config(format!(
                "mieru profile '{profile}' has no profiles[] entry named its own activeProfile '{active_name}'"
            ))
        })?;
    let active_obj = active_profile.as_object_mut().ok_or_else(|| {
        NyxError::Config(format!("mieru profile '{profile}': active profile entry is not an object"))
    })?;
    active_obj.insert(
        "dialer".to_string(),
        serde_json::json!({
            "protocol": "SOCKS5_PROXY_PROTOCOL",
            "host": socks_host,
            "port": socks_port,
        }),
    );

    let runtime_path = runtime_config_path(profile);
    fs::create_dir_all(crate::socks_override::RUNTIME_DIR)
        .map_err(|e| NyxError::Config(format!("creating {}: {e}", crate::socks_override::RUNTIME_DIR)))?;
    let rendered = serde_json::to_vec_pretty(&config).map_err(NyxError::from)?;
    fs::write(&runtime_path, rendered)
        .map_err(|e| NyxError::Config(format!("writing runtime mieru-via-Tor config: {e}")))?;

    let unit = unit_name(profile);
    // `env VAR=value cmd` is a single argv systemd can run directly under
    // `ExecStart=` — no shell needed, so this stays compatible with
    // `NoNewPrivileges=yes` the same way every other backend's override
    // does.
    let exec_start = format!("/usr/bin/env MIERU_CONFIG_JSON_FILE={runtime_path} /usr/bin/mieru run");
    if let Err(e) = crate::socks_override::write_exec_start_override(&unit, &exec_start) {
        let _ = fs::remove_file(&runtime_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::reload(conn).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = fs::remove_file(&runtime_path);
        return Err(e);
    }
    if let Err(e) = crate::systemd_ctl::start_unit(conn, &unit).await {
        crate::socks_override::remove_exec_start_override(&unit);
        let _ = fs::remove_file(&runtime_path);
        let _ = crate::systemd_ctl::reload(conn).await;
        return Err(e);
    }
    Ok(())
}

pub async fn is_active(conn: &Connection, profile: &str) -> NyxResult<bool> {
    crate::systemd_ctl::is_active(conn, &unit_name(profile)).await
}

/// Best-effort discovery of which configured profile (if any) currently
/// has an active systemd unit — used by Status to find a connection this
/// daemon didn't itself start (e.g. after a restart).
pub async fn find_active_profile(conn: &Connection) -> Option<String> {
    for profile in list_profiles() {
        if is_active(conn, &profile).await.unwrap_or(false) {
            return Some(profile);
        }
    }
    None
}

/// Parse the top-level `socks5Port`/`socks5ListenLAN` out of a profile's
/// JSON config — the local address a client (or nyx-vpn's own status
/// probe) would connect to. `None` if the file is missing, isn't valid
/// JSON, or has no `socks5Port`.
pub fn configured_local_addr(profile: &str) -> Option<SocketAddr> {
    let path = format!("{PROFILE_DIR}/{profile}.json");
    let contents = fs::read_to_string(path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&contents).ok()?;
    let port = config.get("socks5Port")?.as_u64()?;
    let port = u16::try_from(port).ok()?;
    let listen_lan = config.get("socks5ListenLAN").and_then(|v| v.as_bool()).unwrap_or(false);
    // mieru binds the SOCKS5 listener to all interfaces when
    // `socks5ListenLAN` is true, loopback-only otherwise — connect to
    // loopback either way, matching how `xray.rs`/`shadowsocks.rs` treat
    // an unspecified bind address.
    let ip: IpAddr = if listen_lan { IpAddr::from([0, 0, 0, 0]) } else { IpAddr::from([127, 0, 0, 1]) };
    let ip = if ip.is_unspecified() { IpAddr::from([127, 0, 0, 1]) } else { ip };
    Some(SocketAddr::new(ip, port))
}

/// Best-effort liveness signal: does *something* accept a TCP connection
/// on the profile's configured SOCKS5 port. This proves the process has a
/// listener up, nothing more — it is not a handshake or an end-to-end
/// reachability check of the configured mieru server.
pub fn local_proxy_reachable(profile: &str) -> bool {
    let Some(addr) = configured_local_addr(profile) else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}
