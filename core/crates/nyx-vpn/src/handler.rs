use crate::state::AppState;
use crate::{amneziawg, cloak, dante, hysteria, openvpn, route, shadowsocks, wireguard, xray};
use nyx_core::{NyxOutput, SecurityState, VpnCommand, VpnProfile, VpnProtocol, VpnReport};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use zbus::Connection;

const BINARY: &str = "nyx-vpn";

/// Shared status derivation for the two kernel-tunnel backends
/// (WireGuard/AmneziaWG): both expose a real handshake-recency signal over
/// an identical CLI shape, so "is it really protecting traffic" means the
/// same thing for either — a recent handshake *and* the default route
/// actually going through the tunnel.
fn kernel_tunnel_status(
    label: &str,
    interface: Option<&str>,
    handshake_age_secs: Option<u64>,
    default_route_via_vpn: bool,
) -> (SecurityState, String) {
    if handshake_age_secs.is_some() && default_route_via_vpn {
        (
            SecurityState::Protected,
            format!(
                "{label} interface {} up, handshake {}s ago, carrying the default route",
                interface.unwrap_or("?"),
                handshake_age_secs.unwrap_or(0)
            ),
        )
    } else if handshake_age_secs.is_none() {
        (
            SecurityState::Degraded,
            format!(
                "{label} interface is up but no peer has handshaked yet — normal immediately \
                 after connecting, but not yet verified"
            ),
        )
    } else {
        (
            SecurityState::Degraded,
            format!(
                "{label} tunnel is up and has handshaked, but is not carrying the default route"
            ),
        )
    }
}

/// Shared status derivation for the three local-proxy backends (Xray,
/// Shadowsocks, Hysteria2): none of them are a kernel tunnel, none expose
/// a handshake-recency concept over a simple CLI query, so the strongest
/// honest signal is "the process is active and something is accepting
/// connections on its configured local port" — never promoted to
/// `Protected`.
fn proxy_status(label: &str, profile: Option<&str>, reachable: impl Fn(&str) -> bool) -> (SecurityState, String) {
    let Some(profile) = profile else {
        return (
            SecurityState::Unknown,
            format!("{label} reported active with no profile name — internal inconsistency"),
        );
    };
    if reachable(profile) {
        (
            SecurityState::Degraded,
            format!(
                "{label} process is active and its local proxy port is accepting connections \
                 — {label} exposes no handshake-recency concept the way WireGuard/AmneziaWG do, \
                 so this is the strongest signal available and is never reported as fully \
                 Protected"
            ),
        )
    } else {
        (
            SecurityState::Degraded,
            format!(
                "{label} process is active but its local proxy port isn't accepting \
                 connections yet — normal immediately after starting, but not yet verified"
            ),
        )
    }
}

/// Live probe of VPN state, independent of what nyx-vpn itself remembers
/// starting — a tunnel someone else brought up is still a tunnel. Both
/// `Status` and every mutating command's response go through this.
async fn probe(conn: &Connection, state: &AppState) -> VpnReport {
    let wg_ifaces = wireguard::active_interfaces();
    let ovpn_profile = openvpn::find_active_profile(conn).await;
    let awg_ifaces = amneziawg::active_interfaces();
    let xray_profile = xray::find_active_profile(conn).await;
    let ss_profile = shadowsocks::find_active_profile(conn).await;
    let hysteria_profile = hysteria::find_active_profile(conn).await;
    let socks5_ifaces = dante::active_interfaces();
    let default_iface = route::default_route_interface();
    let remembered = state.active.lock().await.clone();

    let (protocol, profile, interface) = if let Some((VpnProtocol::WireGuard, name)) = &remembered
        && wg_ifaces.contains(name)
    {
        (Some(VpnProtocol::WireGuard), Some(name.clone()), Some(name.clone()))
    } else if let Some((VpnProtocol::OpenVpn, name)) = &remembered
        && ovpn_profile.as_deref() == Some(name.as_str())
    {
        (Some(VpnProtocol::OpenVpn), Some(name.clone()), openvpn::configured_device(name))
    } else if let Some((VpnProtocol::AmneziaWg, name)) = &remembered
        && awg_ifaces.contains(name)
    {
        (Some(VpnProtocol::AmneziaWg), Some(name.clone()), Some(name.clone()))
    } else if let Some((VpnProtocol::Xray, name)) = &remembered
        && xray_profile.as_deref() == Some(name.as_str())
    {
        (Some(VpnProtocol::Xray), Some(name.clone()), None)
    } else if let Some((VpnProtocol::Shadowsocks, name)) = &remembered
        && ss_profile.as_deref() == Some(name.as_str())
    {
        (Some(VpnProtocol::Shadowsocks), Some(name.clone()), None)
    } else if let Some((VpnProtocol::Hysteria2, name)) = &remembered
        && hysteria_profile.as_deref() == Some(name.as_str())
    {
        (Some(VpnProtocol::Hysteria2), Some(name.clone()), None)
    } else if let Some((VpnProtocol::Socks5, name)) = &remembered
        && socks5_ifaces.contains(name)
    {
        (Some(VpnProtocol::Socks5), Some(name.clone()), Some(name.clone()))
    } else if let Some(name) = wg_ifaces.first() {
        (Some(VpnProtocol::WireGuard), Some(name.clone()), Some(name.clone()))
    } else if let Some(name) = &ovpn_profile {
        (Some(VpnProtocol::OpenVpn), Some(name.clone()), openvpn::configured_device(name))
    } else if let Some(name) = awg_ifaces.first() {
        (Some(VpnProtocol::AmneziaWg), Some(name.clone()), Some(name.clone()))
    } else if let Some(name) = &xray_profile {
        (Some(VpnProtocol::Xray), Some(name.clone()), None)
    } else if let Some(name) = &ss_profile {
        (Some(VpnProtocol::Shadowsocks), Some(name.clone()), None)
    } else if let Some(name) = &hysteria_profile {
        (Some(VpnProtocol::Hysteria2), Some(name.clone()), None)
    } else if let Some(name) = socks5_ifaces.first() {
        (Some(VpnProtocol::Socks5), Some(name.clone()), Some(name.clone()))
    } else {
        (None, None, None)
    };

    let default_route_via_vpn = match (&interface, &default_iface) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };

    let handshake_age_secs = match protocol {
        Some(VpnProtocol::WireGuard) => interface.as_deref().and_then(wireguard::handshake_age_secs),
        Some(VpnProtocol::AmneziaWg) => interface.as_deref().and_then(amneziawg::handshake_age_secs),
        _ => None,
    };

    let (state_value, detail) = match protocol {
        None => (SecurityState::Unknown, "no VPN tunnel is currently up".to_string()),

        Some(VpnProtocol::WireGuard) => {
            kernel_tunnel_status("WireGuard", interface.as_deref(), handshake_age_secs, default_route_via_vpn)
        }

        Some(VpnProtocol::AmneziaWg) => {
            kernel_tunnel_status("AmneziaWG", interface.as_deref(), handshake_age_secs, default_route_via_vpn)
        }

        Some(VpnProtocol::OpenVpn) => {
            let has_addr = interface.as_deref().map(route::interface_has_address).unwrap_or(false);
            if has_addr && default_route_via_vpn {
                (
                    SecurityState::Protected,
                    format!(
                        "OpenVPN service active, interface {} has an address, carrying the \
                         default route",
                        interface.as_deref().unwrap_or("?")
                    ),
                )
            } else if !has_addr {
                (
                    SecurityState::Degraded,
                    "OpenVPN service is active but its interface has no address yet, or its \
                     device name is unknown — connection not independently verified"
                        .to_string(),
                )
            } else {
                (
                    SecurityState::Degraded,
                    "OpenVPN tunnel is up but is not carrying the default route".to_string(),
                )
            }
        }

        Some(VpnProtocol::Xray) => proxy_status("Xray", profile.as_deref(), xray::local_proxy_reachable),
        Some(VpnProtocol::Shadowsocks) => {
            proxy_status("Shadowsocks", profile.as_deref(), shadowsocks::local_proxy_reachable)
        }
        Some(VpnProtocol::Hysteria2) => {
            proxy_status("Hysteria2", profile.as_deref(), hysteria::local_proxy_reachable)
        }

        Some(VpnProtocol::Socks5) => {
            // A real TUN device that can carry the default route — but
            // SOCKS5 itself has no built-in encryption or authentication,
            // so this is capped at Degraded no matter how clean the route
            // looks. See dante.rs's module doc for the full reasoning.
            let has_addr = interface.as_deref().map(route::interface_has_address).unwrap_or(false);
            if has_addr && default_route_via_vpn {
                (
                    SecurityState::Degraded,
                    format!(
                        "SOCKS5-to-TUN bridge {} up, carrying the default route — but SOCKS5 \
                         itself provides no encryption or authentication of its own, so this is \
                         never reported as fully Protected",
                        interface.as_deref().unwrap_or("?")
                    ),
                )
            } else if !has_addr {
                (
                    SecurityState::Degraded,
                    "SOCKS5-to-TUN bridge interface is up but has no address yet — not yet \
                     verified"
                        .to_string(),
                )
            } else {
                (
                    SecurityState::Degraded,
                    "SOCKS5-to-TUN bridge is up but is not carrying the default route".to_string(),
                )
            }
        }
    };

    VpnReport {
        connected: protocol.is_some(),
        protocol,
        profile,
        interface,
        handshake_age_secs,
        default_route_via_vpn,
        state: state_value,
        detail,
        profiles: Vec::new(),
    }
}

fn list_profiles() -> Vec<VpnProfile> {
    let mut profiles: Vec<VpnProfile> = wireguard::list_profiles()
        .into_iter()
        .map(|name| VpnProfile { protocol: VpnProtocol::WireGuard, name })
        .collect();
    profiles.extend(
        openvpn::list_profiles()
            .into_iter()
            .map(|name| VpnProfile { protocol: VpnProtocol::OpenVpn, name }),
    );
    profiles.extend(
        amneziawg::list_profiles()
            .into_iter()
            .map(|name| VpnProfile { protocol: VpnProtocol::AmneziaWg, name }),
    );
    profiles.extend(
        xray::list_profiles().into_iter().map(|name| VpnProfile { protocol: VpnProtocol::Xray, name }),
    );
    profiles.extend(
        shadowsocks::list_profiles()
            .into_iter()
            .map(|name| VpnProfile { protocol: VpnProtocol::Shadowsocks, name }),
    );
    profiles.extend(
        hysteria::list_profiles()
            .into_iter()
            .map(|name| VpnProfile { protocol: VpnProtocol::Hysteria2, name }),
    );
    profiles.extend(
        dante::list_profiles().into_iter().map(|name| VpnProfile { protocol: VpnProtocol::Socks5, name }),
    );
    profiles
}

async fn teardown(conn: &Connection, protocol: VpnProtocol, profile: &str) -> Result<(), String> {
    match protocol {
        VpnProtocol::WireGuard => wireguard::down(profile).map_err(|e| e.to_string()),
        VpnProtocol::OpenVpn => openvpn::down(conn, profile).await.map_err(|e| e.to_string()),
        VpnProtocol::AmneziaWg => amneziawg::down(profile).map_err(|e| e.to_string()),
        VpnProtocol::Xray => xray::down(conn, profile).await.map_err(|e| e.to_string()),
        VpnProtocol::Shadowsocks => shadowsocks::down(conn, profile).await.map_err(|e| e.to_string()),
        VpnProtocol::Hysteria2 => hysteria::down(conn, profile).await.map_err(|e| e.to_string()),
        VpnProtocol::Socks5 => dante::down(conn, profile).await.map_err(|e| e.to_string()),
    }
}

pub async fn dispatch(conn: &Connection, state: &AppState, cmd: VpnCommand) -> NyxOutput<VpnReport> {
    match cmd {
        VpnCommand::Status => {
            let report = probe(conn, state).await;
            let detail = report.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(report))
        }

        VpnCommand::List => {
            let mut report = probe(conn, state).await;
            report.profiles = list_profiles();
            let count = report.profiles.len();
            NyxOutput::ok(BINARY, "list", format!("{count} profile(s) found"), Some(report))
        }

        VpnCommand::Connect { protocol, profile } => {
            // Never run two tunnels at once — tear down whatever's active first.
            if let Some((prev_protocol, prev_name)) = state.active.lock().await.clone() {
                let _ = teardown(conn, prev_protocol, &prev_name).await;
            }

            let result = match protocol {
                VpnProtocol::WireGuard => {
                    if !wireguard::list_profiles().contains(&profile) {
                        Err(format!("no WireGuard profile named '{profile}' at /etc/wireguard/"))
                    } else {
                        wireguard::up(&profile).map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::OpenVpn => {
                    if !openvpn::list_profiles().contains(&profile) {
                        Err(format!(
                            "no OpenVPN profile named '{profile}' at /etc/openvpn/client/"
                        ))
                    } else {
                        openvpn::up(conn, &profile).await.map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::AmneziaWg => {
                    if !amneziawg::list_profiles().contains(&profile) {
                        Err(format!(
                            "no AmneziaWG profile named '{profile}' at /etc/amnezia/amneziawg/"
                        ))
                    } else {
                        amneziawg::up(&profile).map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Xray => {
                    if !xray::list_profiles().contains(&profile) {
                        Err(format!("no Xray profile named '{profile}' at /etc/nyx/xray/"))
                    } else {
                        xray::up(conn, &profile).await.map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Shadowsocks => {
                    if !shadowsocks::list_profiles().contains(&profile) {
                        Err(format!(
                            "no Shadowsocks profile named '{profile}' at /etc/shadowsocks-rust/"
                        ))
                    } else {
                        shadowsocks::up(conn, &profile).await.map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Hysteria2 => {
                    if !hysteria::list_profiles().contains(&profile) {
                        Err(format!("no Hysteria2 profile named '{profile}' at /etc/nyx/hysteria/"))
                    } else {
                        hysteria::up(conn, &profile).await.map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Socks5 => {
                    if !dante::list_profiles().contains(&profile) {
                        Err(format!("no SOCKS5 profile named '{profile}' at /etc/nyx/socks5/"))
                    } else {
                        dante::up(conn, &profile).await.map_err(|e| e.to_string())
                    }
                }
            };

            match result {
                Ok(()) => {
                    *state.active.lock().await = Some((protocol, profile));
                    let report = probe(conn, state).await;
                    let detail = report.detail.clone();
                    NyxOutput::ok(BINARY, "connect", detail, Some(report))
                }
                Err(e) => NyxOutput::<VpnReport>::err(BINARY, "connect", e),
            }
        }

        VpnCommand::ConnectViaSocksProxy { protocol, profile, socks_proxy } => {
            // "tor.service is active" is a process-liveness claim, not
            // proof the SocksPort itself is accepting connections yet —
            // a real TCP connect, not a status check, is the bar every
            // other verification in this project already holds itself to.
            let target = format!("{}:{}", socks_proxy.host, socks_proxy.port);
            let reachable = target
                .parse::<SocketAddr>()
                .ok()
                .map(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok())
                .unwrap_or(false);
            if !reachable {
                return NyxOutput::<VpnReport>::err(
                    BINARY,
                    "connect_via_socks_proxy",
                    format!(
                        "upstream SOCKS proxy {target} is not accepting connections — refusing \
                         to dial through it"
                    ),
                );
            }

            // Never run two tunnels at once — tear down whatever's active first.
            if let Some((prev_protocol, prev_name)) = state.active.lock().await.clone() {
                let _ = teardown(conn, prev_protocol, &prev_name).await;
            }

            let result = match protocol {
                VpnProtocol::WireGuard | VpnProtocol::AmneziaWg => Err(format!(
                    "{protocol:?} is a UDP-only in-kernel tunnel — Tor's SocksPort is TCP-only \
                     (no SOCKS5 UDP ASSOCIATE support), so there is no way to carry it through \
                     Tor at all; this is a protocol-layer limitation, not a missing feature"
                )),
                VpnProtocol::Hysteria2 => Err(
                    "Hysteria2's transport is QUIC (also UDP-only, so the same SocksPort \
                     limitation applies), and its client config has no proxy-chaining option \
                     of its own for reaching its own server through an upstream proxy"
                        .to_string(),
                ),
                VpnProtocol::Socks5 => Err(
                    "the SOCKS5 backend (badvpn-tun2socks) takes exactly one upstream \
                     --socks-server-addr with no chaining flag — there is no second hop to \
                     point at Tor without replacing the profile's own configured SOCKS5 \
                     endpoint outright"
                        .to_string(),
                ),
                VpnProtocol::OpenVpn => {
                    if !openvpn::list_profiles().contains(&profile) {
                        Err(format!("no OpenVPN profile named '{profile}' at /etc/openvpn/client/"))
                    } else {
                        openvpn::up_via_socks_proxy(conn, &profile, &socks_proxy.host, socks_proxy.port)
                            .await
                            .map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Xray => {
                    if !xray::list_profiles().contains(&profile) {
                        Err(format!("no Xray profile named '{profile}' at /etc/nyx/xray/"))
                    } else {
                        xray::up_via_socks_proxy(conn, &profile, &socks_proxy.host, socks_proxy.port)
                            .await
                            .map_err(|e| e.to_string())
                    }
                }
                VpnProtocol::Shadowsocks => {
                    if !shadowsocks::list_profiles().contains(&profile) {
                        Err(format!(
                            "no Shadowsocks profile named '{profile}' at /etc/shadowsocks-rust/"
                        ))
                    } else {
                        shadowsocks::up_via_socks_proxy(conn, &profile, &socks_proxy.host, socks_proxy.port)
                            .await
                            .map_err(|e| e.to_string())
                    }
                }
            };

            match result {
                Ok(()) => {
                    *state.active.lock().await = Some((protocol, profile));
                    let report = probe(conn, state).await;
                    let detail = report.detail.clone();
                    NyxOutput::ok(BINARY, "connect_via_socks_proxy", detail, Some(report))
                }
                Err(e) => NyxOutput::<VpnReport>::err(BINARY, "connect_via_socks_proxy", e),
            }
        }

        VpnCommand::ConnectViaCloak { profile, cloak_config } => {
            if !openvpn::list_profiles().contains(&profile) {
                return NyxOutput::<VpnReport>::err(
                    BINARY,
                    "connect_via_cloak",
                    format!("no OpenVPN profile named '{profile}' at /etc/openvpn/client/"),
                );
            }

            // Never run two tunnels at once — tear down whatever's active first.
            if let Some((prev_protocol, prev_name)) = state.active.lock().await.clone() {
                let _ = teardown(conn, prev_protocol, &prev_name).await;
            }

            let result = cloak::up(conn, &profile, &cloak_config).await.map_err(|e| e.to_string());

            match result {
                Ok(()) => {
                    *state.active.lock().await = Some((VpnProtocol::OpenVpn, profile));
                    let report = probe(conn, state).await;
                    let detail = report.detail.clone();
                    NyxOutput::ok(BINARY, "connect_via_cloak", detail, Some(report))
                }
                Err(e) => NyxOutput::<VpnReport>::err(BINARY, "connect_via_cloak", e),
            }
        }

        VpnCommand::Disconnect => {
            let Some((protocol, profile)) = state.active.lock().await.clone() else {
                let report = probe(conn, state).await;
                return NyxOutput::ok(
                    BINARY,
                    "disconnect",
                    "nothing was connected by nyx-vpn",
                    Some(report),
                );
            };

            match teardown(conn, protocol, &profile).await {
                Ok(()) => {
                    *state.active.lock().await = None;
                    let report = probe(conn, state).await;
                    let detail = report.detail.clone();
                    NyxOutput::ok(BINARY, "disconnect", detail, Some(report))
                }
                Err(e) => NyxOutput::<VpnReport>::err(BINARY, "disconnect", e),
            }
        }
    }
}
