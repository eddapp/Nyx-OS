use crate::state::AppState;
use crate::{openvpn, route, wireguard};
use nyx_core::{NyxOutput, SecurityState, VpnCommand, VpnProfile, VpnProtocol, VpnReport};
use zbus::Connection;

const BINARY: &str = "nyx-vpn";

/// Live probe of VPN state, independent of what nyx-vpn itself remembers
/// starting — a tunnel someone else brought up is still a tunnel. Both
/// `Status` and every mutating command's response go through this.
async fn probe(conn: &Connection, state: &AppState) -> VpnReport {
    let wg_ifaces = wireguard::active_interfaces();
    let ovpn_profile = openvpn::find_active_profile(conn).await;
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
    } else if let Some(name) = wg_ifaces.first() {
        (Some(VpnProtocol::WireGuard), Some(name.clone()), Some(name.clone()))
    } else if let Some(name) = &ovpn_profile {
        (Some(VpnProtocol::OpenVpn), Some(name.clone()), openvpn::configured_device(name))
    } else {
        (None, None, None)
    };

    let default_route_via_vpn = match (&interface, &default_iface) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };

    let handshake_age_secs = match protocol {
        Some(VpnProtocol::WireGuard) => interface.as_deref().and_then(wireguard::handshake_age_secs),
        _ => None,
    };

    let (state_value, detail) = match protocol {
        None => (SecurityState::Unknown, "no VPN tunnel is currently up".to_string()),
        Some(VpnProtocol::WireGuard) => {
            if handshake_age_secs.is_some() && default_route_via_vpn {
                (
                    SecurityState::Protected,
                    format!(
                        "WireGuard interface {} up, handshake {}s ago, carrying the default route",
                        interface.as_deref().unwrap_or("?"),
                        handshake_age_secs.unwrap_or(0)
                    ),
                )
            } else if handshake_age_secs.is_none() {
                (
                    SecurityState::Degraded,
                    "WireGuard interface is up but no peer has handshaked yet — normal \
                     immediately after connecting, but not yet verified"
                        .to_string(),
                )
            } else {
                (
                    SecurityState::Degraded,
                    "WireGuard tunnel is up and has handshaked, but is not carrying the default \
                     route"
                        .to_string(),
                )
            }
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
    profiles
}

async fn teardown(conn: &Connection, protocol: VpnProtocol, profile: &str) -> Result<(), String> {
    match protocol {
        VpnProtocol::WireGuard => wireguard::down(profile).map_err(|e| e.to_string()),
        VpnProtocol::OpenVpn => openvpn::down(conn, profile).await.map_err(|e| e.to_string()),
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
