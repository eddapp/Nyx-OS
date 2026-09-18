//! `VpnCommand::FetchFreeProvider` — the two real, genuinely free (no
//! account, no payment) public VPN directories NyxOS curates.
//!
//! Both endpoints below were fetched live and inspected while writing this
//! module:
//!
//! - **VPN Gate** (`https://www.vpngate.net/api/iphone/`, University of
//!   Tsukuba): a `*vpn_servers` CSV whose header is `#HostName,IP,Score,
//!   Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,
//!   TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64` — the
//!   last field is a ready-to-use `.ovpn` file, base64-encoded. The
//!   `Message` field (index 13) can itself contain commas, but the final
//!   field never does (it's pure base64), so every row is parsed
//!   right-to-left: peel the base64 field off with the *last* comma in the
//!   line first, then split what remains left-to-right — the fields this
//!   module actually needs (HostName/Ping/Speed/CountryShort) all sit
//!   before the point where `Message`'s own commas could shift anything.
//! - **Riseup**: `https://api.black.riseup.net/3/config/eip-service.json`
//!   (gateway list + OpenVPN parameters) and `https://api.black.riseup.net
//!   /3/cert` (a real client certificate + private key, concatenated PEM,
//!   issued fresh with zero signup) plus the CA that signs it,
//!   `https://black.riseup.net/ca.crt`. No `tls-auth`/`tls-crypt` static
//!   key is issued by this API, so this module doesn't emit one — the
//!   client cert/key plus `remote-cert-tls server` is the real, complete
//!   security story here.

use crate::util;
use nyx_core::protocol::FreeProvider;
use nyx_core::{NyxError, NyxResult};
use std::process::Command;

const VPN_GATE_URL: &str = "https://www.vpngate.net/api/iphone/";
const RISEUP_EIP_SERVICE_URL: &str = "https://api.black.riseup.net/3/config/eip-service.json";
const RISEUP_CERT_URL: &str = "https://api.black.riseup.net/3/cert";
const RISEUP_CA_URL: &str = "https://black.riseup.net/ca.crt";

/// A real outbound HTTPS GET against a named public directory — logged
/// plainly rather than hidden, per this command's own documented honesty
/// requirement (a lower-stakes disclosure than e.g. `nyx-diagnostics
/// public-ip`'s "reveals your IP to a random service", but still not
/// silent).
fn curl_get(url: &str, timeout_secs: u64) -> NyxResult<String> {
    tracing::info!("nyx-vpn: fetching {url} (real outbound request to this provider's public API)");
    let output = Command::new("curl")
        .args(["-s", "-f", "--max-time", &timeout_secs.to_string(), url])
        .output()
        .map_err(|e| NyxError::Network(format!("failed to spawn curl for {url}: {e}")))?;
    if !output.status.success() {
        return Err(NyxError::Network(format!("curl exited with {} fetching {url}", output.status)));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| NyxError::Network(format!("{url} returned non-UTF-8 data: {e}")))
}

fn sanitize_name(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    out.truncate(80);
    if out.is_empty() { "profile".to_string() } else { out }
}

/// One VPN Gate CSV row's fields this module actually uses. See the module
/// doc for why parsing is right-to-left.
struct VpnGateRow {
    hostname: String,
    country_short: String,
    speed_bps: u64,
    config_base64: String,
}

fn parse_vpn_gate_row(line: &str) -> Option<VpnGateRow> {
    let (rest, config_base64) = line.rsplit_once(',')?;
    let fields: Vec<&str> = rest.split(',').collect();
    if fields.len() < 7 {
        return None;
    }
    Some(VpnGateRow {
        hostname: fields[0].to_string(),
        speed_bps: fields[4].parse().ok()?,
        country_short: fields[6].to_string(),
        config_base64: config_base64.to_string(),
    })
}

fn fetch_vpn_gate(country: Option<&str>) -> NyxResult<(String, String)> {
    let csv = curl_get(VPN_GATE_URL, 30)?;

    let candidates: Vec<VpnGateRow> = csv
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('*') && !l.starts_with('#'))
        .filter_map(parse_vpn_gate_row)
        .filter(|row| match country {
            Some(code) => row.country_short.eq_ignore_ascii_case(code),
            None => true,
        })
        .collect();

    let best = candidates
        .into_iter()
        .max_by_key(|row| row.speed_bps)
        .ok_or_else(|| match country {
            Some(code) => {
                NyxError::Network(format!("VPN Gate has no relay currently listed for country '{code}'"))
            }
            None => NyxError::Network("VPN Gate's relay list is currently empty".to_string()),
        })?;

    let decoded = util::base64_decode(&best.config_base64)
        .ok_or_else(|| NyxError::Network(format!("VPN Gate relay '{}' has malformed base64 config data", best.hostname)))?;
    let config = String::from_utf8(decoded)
        .map_err(|e| NyxError::Network(format!("VPN Gate relay '{}' config isn't valid UTF-8: {e}", best.hostname)))?;

    let name = format!("vpngate-{}", sanitize_name(&best.hostname));
    Ok((name, config))
}

/// Split the concatenated PEM blob `/3/cert` returns into its private-key
/// and certificate halves — confirmed live: 27 lines of `RSA PRIVATE KEY`
/// immediately followed by 16 lines of `CERTIFICATE`, with no separator
/// other than the PEM headers themselves.
fn split_riseup_cert(blob: &str) -> Option<(String, String)> {
    let cert_start = blob.find("-----BEGIN CERTIFICATE-----")?;
    let key = blob[..cert_start].trim().to_string();
    let cert = blob[cert_start..].trim().to_string();
    if key.contains("PRIVATE KEY") && cert.starts_with("-----BEGIN CERTIFICATE-----") {
        Some((key, cert))
    } else {
        None
    }
}

fn fetch_riseup() -> NyxResult<(String, String)> {
    let eip_service = curl_get(RISEUP_EIP_SERVICE_URL, 20)?;
    let eip_service: serde_json::Value = serde_json::from_str(&eip_service)
        .map_err(|e| NyxError::Network(format!("Riseup's eip-service.json wasn't valid JSON: {e}")))?;

    let gateway = eip_service
        .get("gateways")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| NyxError::Network("Riseup's eip-service.json has no gateways[]".to_string()))?;
    let host = gateway
        .get("host")
        .and_then(|v| v.as_str())
        .or_else(|| gateway.get("ip_address").and_then(|v| v.as_str()))
        .ok_or_else(|| NyxError::Network("Riseup gateway has neither host nor ip_address".to_string()))?;
    let location = gateway.get("location").and_then(|v| v.as_str()).unwrap_or("riseup");

    let transports = gateway
        .get("capabilities")
        .and_then(|c| c.get("transport"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| NyxError::Network(format!("Riseup gateway '{host}' has no capabilities.transport")))?;
    let openvpn_transport = transports
        .iter()
        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("openvpn"))
        .ok_or_else(|| NyxError::Network(format!("Riseup gateway '{host}' offers no openvpn transport")))?;
    let protocols: Vec<&str> =
        openvpn_transport.get("protocols").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()).collect();
    let ports: Vec<&str> =
        openvpn_transport.get("ports").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()).collect();
    let proto = if protocols.contains(&"udp") { "udp" } else { protocols.first().copied().unwrap_or("udp") };
    let port = if ports.contains(&"1194") { "1194" } else { ports.first().copied().unwrap_or("1194") };

    let cfg = eip_service.get("openvpn_configuration").cloned().unwrap_or_default();
    let str_field = |key: &str, default: &str| -> String {
        cfg.get(key).and_then(|v| v.as_str()).unwrap_or(default).to_string()
    };
    let dev = str_field("dev", "tun");
    let auth = str_field("auth", "SHA512");
    let cipher = str_field("cipher", "AES-256-GCM");
    let data_ciphers = str_field("data-ciphers", &cipher);
    let tls_cipher = str_field("tls-cipher", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384");
    let tls_version_min = str_field("tls-version-min", "1.2");
    let verb = str_field("verb", "3");
    let keepalive = str_field("keepalive", "10 30");

    let cert_blob = curl_get(RISEUP_CERT_URL, 20)?;
    let (private_key, certificate) = split_riseup_cert(&cert_blob)
        .ok_or_else(|| NyxError::Network("Riseup's /3/cert response wasn't the expected key+cert PEM pair".to_string()))?;
    let ca_cert = curl_get(RISEUP_CA_URL, 20)?.trim().to_string();
    if !ca_cert.starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(NyxError::Network("Riseup's ca.crt wasn't a PEM certificate".to_string()));
    }

    let config = format!(
        "client\n\
         dev {dev}\n\
         proto {proto}\n\
         remote {host} {port}\n\
         resolv-retry infinite\n\
         nobind\n\
         persist-key\n\
         persist-tun\n\
         float\n\
         keepalive {keepalive}\n\
         remote-cert-tls server\n\
         tls-cipher {tls_cipher}\n\
         tls-version-min {tls_version_min}\n\
         auth {auth}\n\
         cipher {cipher}\n\
         data-ciphers {data_ciphers}\n\
         verb {verb}\n\
         <ca>\n{ca_cert}\n</ca>\n\
         <cert>\n{certificate}\n</cert>\n\
         <key>\n{private_key}\n</key>\n"
    );

    let name = format!("riseup-{}", sanitize_name(location));
    Ok((name, config))
}

/// Fetch a real relay/gateway from `provider`'s own public API and write
/// it as an immediately-usable OpenVPN profile at
/// `/etc/openvpn/client/<name>.conf`. Returns a detail message naming the
/// provider, the profile written, and (for VPN Gate) the relay chosen —
/// callers should surface this rather than swallow it, since a real
/// outbound request to a named third party just happened.
pub fn fetch(provider: FreeProvider, country: Option<&str>) -> NyxResult<String> {
    let (name, config) = match provider {
        FreeProvider::VpnGate => fetch_vpn_gate(country)?,
        FreeProvider::Riseup => fetch_riseup()?,
    };

    let dir = crate::openvpn::PROFILE_DIR;
    std::fs::create_dir_all(dir).map_err(|e| NyxError::Config(format!("creating {dir}: {e}")))?;
    let path = format!("{dir}/{name}.conf");
    util::write_private_file(&path, &config).map_err(|e| NyxError::Config(format!("writing {path}: {e}")))?;

    Ok(format!(
        "fetched a real relay from {provider:?}'s public API and wrote it as OpenVPN profile \
         '{name}' at {path} — ready to connect with no further setup"
    ))
}
