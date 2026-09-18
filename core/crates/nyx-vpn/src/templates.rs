//! `VpnCommand::WriteProviderTemplate` — real, correctly-shaped config
//! skeletons for the three commercial providers NyxOS can't embed a real
//! paid account for (see `nyx_core::TemplateProvider`). Every field that
//! genuinely requires the user's own account is left as an obvious
//! `<REPLACE_WITH_...>` placeholder (see `util::INCOMPLETE_MARKER`); every
//! other field is real, verified against each provider's own live public
//! infrastructure or documentation at the time this was written, not
//! invented:
//!
//! - **Mullvad**: `DNS = 10.64.0.1` and port `51820` and the
//!   `<code>-<city>-wg-NNN.relays.mullvad.net` hostname shape, plus one
//!   concrete relay (`al-tia-wg-001`, Tirana) and its public key, both read
//!   live from Mullvad's own public, unauthenticated relay directory
//!   (`https://api.mullvad.net/public/relays/wireguard/v2/`) — a relay's
//!   public key is not account-specific, only the client's own `PrivateKey`
//!   and the account-assigned tunnel `Address` are.
//! - **NordVPN**: the `<ca>`/`<tls-auth>` blocks below are byte-for-byte
//!   what `https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/
//!   <hostname>.nordvpn.com.udp.ovpn` serves publicly with no login for
//!   every server — confirmed live against `uk765.nordvpn.com`'s own
//!   config. That CA/static key pair is shared infrastructure, not
//!   per-account; only the per-account OpenVPN service credential
//!   (Nord Account → NordVPN app credentials, distinct from the account
//!   login) is a placeholder here.
//! - **ProtonVPN**: every download of a real `.ovpn` (including its
//!   `<ca>`/`<tls-crypt>` blocks) requires being logged into
//!   `account.protonvpn.com/downloads` first — confirmed no public,
//!   unauthenticated equivalent exists the way NordVPN's does — so both
//!   the cert material and the separate OpenVPN/IKEv2 credential are
//!   placeholders here.

use crate::util;
use nyx_core::protocol::TemplateProvider;
use nyx_core::{NyxError, NyxResult, VpnProtocol};

const MULLVAD_WIREGUARD_TEMPLATE: &str = r#"# NyxOS template for Mullvad WireGuard — see nyx-vpn's templates.rs for
# exactly which fields below are real vs. placeholders.
#
# To fill this in for real:
#   1. Generate (or reuse) a WireGuard keypair, then register the PUBLIC
#      half with your Mullvad account at
#      https://mullvad.net/en/account/wireguard-config — Mullvad will hand
#      back the private IP address it assigned your account for this key.
#   2. Put that keypair's PRIVATE key below, and the assigned address.
#   3. Optionally pick a different relay from
#      https://api.mullvad.net/public/relays/wireguard/v2/ — the one below
#      (Tirana, Albania) is just one real relay that was live when this
#      template was written.
[Interface]
PrivateKey = <REPLACE_WITH_YOUR_OWN_PRIVATE_KEY>
Address = <REPLACE_WITH_YOUR_OWN_ACCOUNT_ASSIGNED_ADDRESS>/32
DNS = 10.64.0.1

[Peer]
PublicKey = ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=
Endpoint = al-tia-wg-001.relays.mullvad.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
"#;

const PROTONVPN_OPENVPN_TEMPLATE: &str = r#"# NyxOS template for ProtonVPN OpenVPN — see nyx-vpn's templates.rs for
# exactly which fields below are real vs. placeholders.
#
# To fill this in for real:
#   1. Log into https://account.protonvpn.com/downloads , pick "OpenVPN
#      configuration files", pick a server, and download its real .ovpn.
#   2. Copy that file's own <ca> and <tls-crypt> blocks in place of the two
#      placeholders below (they're specific to the server you picked).
#   3. Your OpenVPN/IKEv2 username+password (Account -> OpenVPN/IKEv2
#      username) is DIFFERENT from your ProtonVPN account login — put it
#      in a separate 2-line file (username, then password) and point
#      auth-user-pass at it below, or leave the bare directive and OpenVPN
#      will prompt interactively.
client
dev tun
proto udp
remote <REPLACE_WITH_YOUR_CHOSEN_SERVER_HOSTNAME>.protonvpn.net 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass <REPLACE_WITH_YOUR_OWN_OPENVPN_CREDENTIALS_FILE>
cipher AES-256-CBC
auth SHA512
key-direction 1
verb 3
<ca>
<REPLACE_WITH_YOUR_DOWNLOADED_SERVERS_CA_CERTIFICATE>
</ca>
<tls-crypt>
<REPLACE_WITH_YOUR_DOWNLOADED_SERVERS_TLS_CRYPT_KEY>
</tls-crypt>
"#;

const NORDVPN_OPENVPN_TEMPLATE: &str = r#"# NyxOS template for NordVPN OpenVPN — see nyx-vpn's templates.rs for
# exactly which fields below are real vs. placeholders.
#
# The <ca>/<tls-auth> blocks below are NordVPN's own real, publicly
# published shared infrastructure (confirmed live against
# https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/ — every
# server's .ovpn there uses the same pair). Only the server you connect to
# and your OpenVPN service credential are actually per-user:
#   1. Pick a server hostname from https://nordvpn.com/servers/ (or
#      `https://api.nordvpn.com/v1/servers`) and put it below.
#   2. Your OpenVPN service credential (Nord Account -> NordVPN app,
#      "Set up NordVPN manually" -> service credentials) is DIFFERENT from
#      your Nord Account login — put it in a separate 2-line file
#      (username, then password) and point auth-user-pass at it below.
client
dev tun
proto udp
remote <REPLACE_WITH_YOUR_CHOSEN_SERVER_HOSTNAME>.nordvpn.com 1194
resolv-retry infinite
remote-random
nobind
persist-key
persist-tun
ping 15
ping-restart 0
ping-timer-rem
reneg-sec 0
comp-lzo no
remote-cert-tls server
auth-user-pass <REPLACE_WITH_YOUR_OWN_SERVICE_CREDENTIALS_FILE>
verb 3
pull
fast-io
cipher AES-256-CBC
auth SHA512
<ca>
-----BEGIN CERTIFICATE-----
MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ
MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2
MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV
BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF
kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr
XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU
eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV
skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu
MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA
37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR
hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s
Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy
WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6
MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST
LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG
SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g
nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/
k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S
DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/
pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo
k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp
+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd
NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa
wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC
VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S
PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==
-----END CERTIFICATE-----
</ca>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
e685bdaf659a25a200e2b9e39e51ff03
0fc72cf1ce07232bd8b2be5e6c670143
f51e937e670eee09d4f2ea5a6e4e6996
5db852c275351b86fc4ca892d78ae002
d6f70d029bd79c4d1c26cf14e9588033
cf639f8a74809f29f72b9d58f9b8f5fe
fc7938eade40e9fed6cb92184abb2cc1
0eb1a296df243b251df0643d53724cdb
5a92a1d6cb817804c4a9319b57d53be5
80815bcfcb2df55018cc83fc43bc7ff8
2d51f9b88364776ee9d12fc85cc7ea5b
9741c4f598c485316db066d52db4540e
212e1518a9bd4828219e24b20d88f598
a196c9de96012090e333519ae18d3509
9427e7b372d348d352dc4c85e18cd4b9
3f8a56ddb2e64eb67adfc9b337157ff4
-----END OpenVPN Static key V1-----
</tls-auth>
"#;

fn render(provider: TemplateProvider) -> (VpnProtocol, &'static str) {
    match provider {
        TemplateProvider::Mullvad => (VpnProtocol::WireGuard, MULLVAD_WIREGUARD_TEMPLATE),
        TemplateProvider::ProtonVpn => (VpnProtocol::OpenVpn, PROTONVPN_OPENVPN_TEMPLATE),
        TemplateProvider::NordVpn => (VpnProtocol::OpenVpn, NORDVPN_OPENVPN_TEMPLATE),
    }
}

/// Writes `provider`'s skeleton as a new profile named `name`, into
/// whichever `PROFILE_DIR` its protocol actually uses (`import.rs`'s own
/// `profile_dir_and_ext` — the same mapping `ImportProfile` uses, so a
/// template written here and a user-supplied config imported there land in
/// exactly the same place). Every template contains
/// [`crate::util::INCOMPLETE_MARKER`] somewhere, so the profile this
/// writes is always reported `incomplete: true` until the user edits it.
pub fn write_template(provider: TemplateProvider, name: &str) -> NyxResult<String> {
    crate::import::valid_profile_name(name).map_err(NyxError::Config)?;

    let (protocol, contents) = render(provider);
    let (dir, ext) = crate::import::profile_dir_and_ext(protocol);
    std::fs::create_dir_all(dir).map_err(|e| NyxError::Config(format!("creating {dir}: {e}")))?;
    let path = format!("{dir}/{name}.{ext}");
    util::write_private_file(&path, contents)
        .map_err(|e| NyxError::Config(format!("writing {path}: {e}")))?;

    Ok(format!(
        "wrote {provider:?} template as {protocol:?} profile '{name}' to {path} — it still \
         contains placeholder(s) and won't connect until you fill them in with your own \
         account's real values"
    ))
}
