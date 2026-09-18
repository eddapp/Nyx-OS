//! SOCKS5 backend — deliberately *not* built on the `dante` package.
//!
//! `dante` (official `extra` repo) ships exactly two binaries: `sockd`, a
//! SOCKS4/5 *server*, and `socksify`, an `LD_PRELOAD` wrapper that makes
//! one already-running application's connections go through a SOCKS
//! proxy. Neither is a system-wide client — `sockd` is the wrong end
//! entirely (nyx-vpn is a client of somebody else's SOCKS5 endpoint, not a
//! host offering one), and `socksify` only ever covers a single process
//! you launch underneath it, not "the OS's default route", which is the
//! bar every other backend in this crate clears.
//!
//! What actually turns "a remote SOCKS5 endpoint" into something
//! route-able like a real VPN is `badvpn-tun2socks`, from the official
//! `extra` package `badvpn`: it opens a TUN device and forwards every TCP
//! connection arriving on it through a SOCKS5 server, confirmed against
//! upstream's own wiki (`ambrop72/badvpn` "Tun2socks" page) and
//! `badvpn-tun2socks(8)`. That page's own worked example is the basis for
//! the route dance below: `badvpn-tun2socks` does not create the TUN
//! device itself (that's a separate `ip tuntap add` step, done here by the
//! templated unit's `ExecStartPre`), and it does not touch routing at all
//! — the caller has to (a) add a specific route to the SOCKS5 server
//! itself over the *existing* default gateway before (b) pointing the
//! default route at the TUN device, or step (b) would make reaching the
//! SOCKS5 server recurse through the tunnel that depends on reaching it.
//!
//! Because this genuinely is a kernel TUN device that can carry the
//! default route, `default_route_via_vpn` and `interface` are real,
//! independently-verified signals here exactly like WireGuard/AmneziaWG —
//! this is not the weaker "local proxy" shape of `xray.rs`/
//! `shadowsocks.rs`/`hysteria.rs`. But SOCKS5 itself has no built-in
//! encryption or authentication of its own: unlike every other protocol in
//! this crate, "the route is clean and the TUN device is up" says nothing
//! about confidentiality. `handler.rs` reflects that by capping this
//! protocol at `Degraded` no matter how verified the route is — never
//! `Protected`.
//!
//! One real, documented limitation on top of that: `badvpn-tun2socks` has
//! no username/password flags (checked against its own man page/wiki), so
//! authenticated SOCKS5 servers aren't supported. And the SOCKS5 endpoint
//! must be given as a literal IP, not a hostname, in the profile — this
//! module doesn't carry its own DNS resolution, and resolving it wrong
//! would just move the same "how do I even reach the resolver" bootstrap
//! problem the bypass route already exists to solve.
//!
//! No `up_via_socks_proxy` here, deliberately: `badvpn-tun2socks` takes
//! exactly one `--socks-server-addr` and has no second/upstream-proxy flag
//! of its own (checked against its full option list). Chaining this
//! backend "through Tor" would mean replacing the profile's actual SOCKS5
//! VPN endpoint with Tor's SocksPort outright, not chaining anything —
//! there is no real mechanism here, so this is rejected rather than faked.
//! See `nyx_core::VpnCommand::ConnectViaSocksProxy`.

use nyx_core::{NyxError, NyxResult};
use std::fs;
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use zbus::Connection;

const PROFILE_DIR: &str = "/etc/nyx/socks5";
/// The virtual router `badvpn-tun2socks` presents *inside* the TUN device
/// (per its own docs, this must differ from the TUN device's own address)
/// — also the gateway nyx-vpn points the replacement default route at.
const VIRTUAL_ROUTER_ADDR: &str = "10.90.0.2";
/// Lower than the bypass route's metric, so a route to the SOCKS5 server
/// over the physical link is always preferred over the (soon to be
/// default) route through the tunnel.
const BYPASS_ROUTE_METRIC: &str = "5";
/// Lower than any normal default route's metric (typically several
/// hundred, e.g. DHCP's 600) so this one wins, but higher than the bypass
/// route above so the SOCKS5 server itself stays reachable.
const DEFAULT_ROUTE_METRIC: &str = "6";

fn unit_name(profile: &str) -> String {
    format!("nyx-vpn-socks5@{profile}.service")
}

fn config_path(profile: &str) -> String {
    format!("{PROFILE_DIR}/{profile}.conf")
}

pub fn list_profiles() -> Vec<String> {
    let Ok(entries) = fs::read_dir(PROFILE_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                path.file_stem().and_then(|s| s.to_str()).map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// Parse `SOCKS_SERVER_ADDR=<ip>:<port>` out of the profile — the same
/// file is also systemd's `EnvironmentFile` for the templated unit (see
/// `packaging/nyx-vpn-socks5@.service`), so the format is plain shell-style
/// `KEY=VALUE` lines, not an nyx-specific one.
fn read_socks_addr(profile: &str) -> Result<SocketAddr, String> {
    let contents = fs::read_to_string(config_path(profile))
        .map_err(|e| format!("reading profile '{profile}': {e}"))?;
    let value = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("SOCKS_SERVER_ADDR="))
        .ok_or_else(|| format!("profile '{profile}' has no SOCKS_SERVER_ADDR=<ip>:<port> line"))?;
    value.parse::<SocketAddr>().map_err(|_| {
        format!(
            "SOCKS_SERVER_ADDR '{value}' is not a literal IP:port — hostnames aren't supported, \
             resolve it yourself and put the IP in the profile"
        )
    })
}

fn run_ip(args: &[&str]) -> NyxResult<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .map_err(|e| NyxError::Network(format!("failed to spawn ip {args:?}: {e}")))?;
    if !status.success() {
        return Err(NyxError::Network(format!("ip {args:?} exited with {status}")));
    }
    Ok(())
}

fn add_bypass_route(server: &SocketAddr, gateway_ip: &str, gateway_iface: &str) -> NyxResult<()> {
    run_ip(&[
        "route",
        "replace",
        &format!("{}/32", server.ip()),
        "via",
        gateway_ip,
        "dev",
        gateway_iface,
        "metric",
        BYPASS_ROUTE_METRIC,
    ])
}

/// Best-effort: the TUN device (and every route pointed at it) is torn
/// down by the unit's own `ExecStopPost` and the kernel dropping routes
/// through a deleted interface, but the bypass route lives on the
/// *physical* interface and outlives the TUN device, so it needs its own
/// explicit removal.
fn del_bypass_route(server: &SocketAddr) {
    let _ = run_ip(&["route", "del", &format!("{}/32", server.ip()), "metric", BYPASS_ROUTE_METRIC]);
}

fn set_default_via_tun(tun_name: &str) -> NyxResult<()> {
    run_ip(&[
        "route",
        "replace",
        "default",
        "via",
        VIRTUAL_ROUTER_ADDR,
        "dev",
        tun_name,
        "metric",
        DEFAULT_ROUTE_METRIC,
    ])
}

fn interface_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

async fn wait_for_interface(name: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if interface_exists(name) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn up(conn: &Connection, profile: &str) -> NyxResult<()> {
    let server = read_socks_addr(profile).map_err(NyxError::Config)?;
    let (gateway_iface, gateway_ip) = crate::route::default_gateway().ok_or_else(|| {
        NyxError::Network(
            "no existing default route to bypass through — can't safely reach the SOCKS5 \
             server without one"
                .to_string(),
        )
    })?;

    add_bypass_route(&server, &gateway_ip, &gateway_iface)?;

    if let Err(e) = crate::systemd_ctl::start_unit(conn, &unit_name(profile)).await {
        del_bypass_route(&server);
        return Err(e);
    }

    if !wait_for_interface(profile, Duration::from_secs(3)).await {
        let _ = crate::systemd_ctl::stop_unit(conn, &unit_name(profile)).await;
        del_bypass_route(&server);
        return Err(NyxError::Network(format!(
            "badvpn-tun2socks did not bring up TUN device '{profile}' within 3s"
        )));
    }

    if let Err(e) = set_default_via_tun(profile) {
        let _ = crate::systemd_ctl::stop_unit(conn, &unit_name(profile)).await;
        del_bypass_route(&server);
        return Err(e);
    }

    Ok(())
}

pub async fn down(conn: &Connection, profile: &str) -> NyxResult<()> {
    let server = read_socks_addr(profile).ok();
    let result = crate::systemd_ctl::stop_unit(conn, &unit_name(profile)).await;
    let _ = run_ip(&["route", "del", "default", "dev", profile, "metric", DEFAULT_ROUTE_METRIC]);
    if let Some(server) = server {
        del_bypass_route(&server);
    }
    result
}

/// Every TUN device currently present whose name matches a *known*
/// profile — a live kernel query, not nyx-vpn's own memory of what it
/// started, mirroring `wireguard::active_interfaces()`. The one honest gap
/// versus WireGuard's version: `wg show interfaces` can only ever list
/// genuine WireGuard kernel interfaces, so there's no naming ambiguity.
/// Plain TUN has no such protocol-level marker, so a name match is the
/// best available signal — the same name-based limitation `openvpn.rs`
/// already documents for its own `configured_device`.
pub fn active_interfaces() -> Vec<String> {
    list_profiles().into_iter().filter(|name| interface_exists(name)).collect()
}
