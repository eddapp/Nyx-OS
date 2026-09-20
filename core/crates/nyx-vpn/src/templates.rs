//! `VpnCommand::WriteProviderTemplate` — real, correctly-shaped config
//! skeletons for the six commercial providers NyxOS can't embed a real
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
//! - **IVPN**: `DNS = 172.16.0.1`, the `<cc><n>.wg.ivpn.net` hostname shape
//!   and port `2049` are from IVPN's own Linux WireGuard guide
//!   (`ivpn.net/setup/linux-wireguard/`, which lists UDP 53, 80, 443, 1194,
//!   2049, 2050, 30587, 41893, 48574, 58237); the concrete relay
//!   (`ro1.wg.ivpn.net`, Bucharest) and its public key were read live from
//!   IVPN's public, unauthenticated server directory
//!   (`https://api.ivpn.net/v4/servers.json`, 59 WireGuard locations at the
//!   time). Only the client's own `PrivateKey` and account-assigned
//!   `Address` are placeholders.
//! - **Private Internet Access**: the whole config below, `<ca>` block
//!   included, is byte-for-byte PIA's own "strong" (RSA-4096 CA, AES-256-CBC,
//!   SHA-256) bundle served with no login from
//!   `https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip`
//!   (168 region files, all sharing `ca.rsa.4096.crt`) — confirmed live
//!   against `albania.ovpn`. Only the per-account username/password is a
//!   placeholder.
//! - **Surfshark**: every server's `.ovpn` is served with no login from
//!   `https://my.surfshark.com/vpn/api/v1/server/configurations` (284 files
//!   at the time); all share one `<ca>` and one `<tls-auth>` static key
//!   (confirmed identical across the bundle), reproduced below. Only the
//!   per-account OpenVPN service credential (Surfshark account →
//!   "Manual setup" credentials, distinct from the account login) is a
//!   placeholder.

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

const IVPN_WIREGUARD_TEMPLATE: &str = r#"# NyxOS template for IVPN WireGuard — see nyx-vpn's templates.rs for
# exactly which fields below are real vs. placeholders.
#
# To fill this in for real:
#   1. Generate (or reuse) a WireGuard keypair, then add the PUBLIC half to
#      your IVPN account at https://www.ivpn.net/account/wireguard-config
#      — IVPN will hand back the private IPv4 (and IPv6) address it
#      assigned your account for this key.
#   2. Put that keypair's PRIVATE key below, and the assigned address
#      (IPv4 with /32; optionally add the IPv6 one with /128 after a comma).
#   3. Optionally pick a different server from
#      https://api.ivpn.net/v4/servers.json — the one below (Bucharest,
#      Romania) is just one real host that was live when this template was
#      written. Any of UDP 53, 80, 443, 1194, 2049, 2050, 30587, 41893,
#      48574 or 58237 works as the endpoint port.
[Interface]
PrivateKey = <REPLACE_WITH_YOUR_OWN_PRIVATE_KEY>
Address = <REPLACE_WITH_YOUR_OWN_ACCOUNT_ASSIGNED_ADDRESS>/32
DNS = 172.16.0.1

[Peer]
PublicKey = F2uQ57hysZTlw8WYELnyCw9Lga80wNYoYwkrrxyXKmw=
Endpoint = ro1.wg.ivpn.net:2049
AllowedIPs = 0.0.0.0/0, ::/0
"#;

const PIA_OPENVPN_TEMPLATE: &str = r#"# NyxOS template for Private Internet Access OpenVPN — see nyx-vpn's
# templates.rs for exactly which fields below are real vs. placeholders.
#
# Everything below except the credentials file is PIA's own public "strong"
# config (https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip),
# including the RSA-4096 CA. To fill this in for real:
#   1. Pick a region hostname — the bundle uses `<cc>.privacy.network`
#      (e.g. `al`, `de`, `nl`, `us-california`); the one below is Albania.
#   2. Put your PIA username (p1234567) and password in a separate 2-line
#      file (username, then password) and point auth-user-pass at it below.
client
dev tun
proto udp
remote al.privacy.network 1197
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-256-cbc
auth sha256
tls-client
remote-cert-tls server
auth-user-pass <REPLACE_WITH_YOUR_OWN_CREDENTIALS_FILE>
compress
verb 1
reneg-sec 0
<ca>
-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----
</ca>
disable-occ
"#;

const SURFSHARK_OPENVPN_TEMPLATE: &str = r#"# NyxOS template for Surfshark OpenVPN — see nyx-vpn's templates.rs for
# exactly which fields below are real vs. placeholders.
#
# The <ca>/<tls-auth> blocks below are Surfshark's own real, publicly
# published shared infrastructure (every server's .ovpn from
# https://my.surfshark.com/vpn/api/v1/server/configurations uses the same
# pair). Only the server you connect to and your service credential are
# actually per-user:
#   1. Pick a server hostname from that bundle — they're all of the form
#      `<cc>-<city>.prod.surfshark.com`; the one below is Andorra.
#   2. Your OpenVPN service credential (Surfshark account → "Manual setup"
#      → credentials) is DIFFERENT from your account login — put it in a
#      separate 2-line file (username, then password) and point
#      auth-user-pass at it below.
client
dev tun
proto udp
remote ad-leu.prod.surfshark.com 1194
remote-random
nobind
tun-mtu 1500
mssfix 1450
ping 15
ping-restart 0
reneg-sec 0
remote-cert-tls server
auth-user-pass <REPLACE_WITH_YOUR_OWN_SERVICE_CREDENTIALS_FILE>
verb 3
fast-io
cipher AES-256-CBC
auth SHA512
<ca>
-----BEGIN CERTIFICATE-----
MIIFTTCCAzWgAwIBAgIJAMs9S3fqwv+mMA0GCSqGSIb3DQEBCwUAMD0xCzAJBgNV
BAYTAlZHMRIwEAYDVQQKDAlTdXJmc2hhcmsxGjAYBgNVBAMMEVN1cmZzaGFyayBS
b290IENBMB4XDTE4MDMxNDA4NTkyM1oXDTI4MDMxMTA4NTkyM1owPTELMAkGA1UE
BhMCVkcxEjAQBgNVBAoMCVN1cmZzaGFyazEaMBgGA1UEAwwRU3VyZnNoYXJrIFJv
b3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDEGMNj0aisM63o
SkmVJyZPaYX7aPsZtzsxo6m6p5Wta3MGASoryRsBuRaH6VVa0fwbI1nw5ubyxkua
Na4v3zHVwuSq6F1p8S811+1YP1av+jqDcMyojH0ujZSHIcb/i5LtaHNXBQ3qN48C
c7sqBnTIIFpmb5HthQ/4pW+a82b1guM5dZHsh7q+LKQDIGmvtMtO1+NEnmj81BAp
FayiaD1ggvwDI4x7o/Y3ksfWSCHnqXGyqzSFLh8QuQrTmWUm84YHGFxoI1/8AKdI
yVoB6BjcaMKtKs/pbctk6vkzmYf0XmGovDKPQF6MwUekchLjB5gSBNnptSQ9kNgn
TLqi0OpSwI6ixX52Ksva6UM8P01ZIhWZ6ua/T/tArgODy5JZMW+pQ1A6L0b7egIe
ghpwKnPRG+5CzgO0J5UE6gv000mqbmC3CbiS8xi2xuNgruAyY2hUOoV9/BuBev8t
tE5ZCsJH3YlG6NtbZ9hPc61GiBSx8NJnX5QHyCnfic/X87eST/amZsZCAOJ5v4EP
SaKrItt+HrEFWZQIq4fJmHJNNbYvWzCE08AL+5/6Z+lxb/Bm3dapx2zdit3x2e+m
iGHekuiE8lQWD0rXD4+T+nDRi3X+kyt8Ex/8qRiUfrisrSHFzVMRungIMGdO9O/z
CINFrb7wahm4PqU2f12Z9TRCOTXciQIDAQABo1AwTjAdBgNVHQ4EFgQUYRpbQwyD
ahLMN3F2ony3+UqOYOgwHwYDVR0jBBgwFoAUYRpbQwyDahLMN3F2ony3+UqOYOgw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAn9zV7F/XVnFNZhHFrt0Z
S1Yqz+qM9CojLmiyblMFh0p7t+Hh+VKVgMwrz0LwDH4UsOosXA28eJPmech6/bjf
ymkoXISy/NUSTFpUChGO9RabGGxJsT4dugOw9MPaIVZffny4qYOc/rXDXDSfF2b+
303lLPI43y9qoe0oyZ1vtk/UKG75FkWfFUogGNbpOkuz+et5Y0aIEiyg0yh6/l5Q
5h8+yom0HZnREHhqieGbkaGKLkyu7zQ4D4tRK/mBhd8nv+09GtPEG+D5LPbabFVx
KjBMP4Vp24WuSUOqcGSsURHevawPVBfgmsxf1UCjelaIwngdh6WfNCRXa5QQPQTK
ubQvkvXONCDdhmdXQccnRX1nJWhPYi0onffvjsWUfztRypsKzX4dvM9k7xnIcGSG
EnCC4RCgt1UiZIj7frcCMssbA6vJ9naM0s7JF7N3VKeHJtqe1OCRHMYnWUZt9vrq
X6IoIHlZCoLlv39wFW9QNxelcAOCVbD+19MZ0ZXt7LitjIqe7yF5WxDQN4xru087
FzQ4Hfj7eH1SNLLyKZkA1eecjmRoi/OoqAt7afSnwtQLtMUc2bQDg6rHt5C0e4dC
LqP/9PGZTSJiwmtRHJ/N5qYWIh9ju83APvLm/AGBTR2pXmj9G3KdVOkpIC7L35dI
623cSEC3Q3UZutsEm/UplsM=
-----END CERTIFICATE-----
</ca>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
b02cb1d7c6fee5d4f89b8de72b51a8d0
c7b282631d6fc19be1df6ebae9e2779e
6d9f097058a31c97f57f0c35526a44ae
09a01d1284b50b954d9246725a1ead1f
f224a102ed9ab3da0152a15525643b2e
ee226c37041dc55539d475183b889a10
e18bb94f079a4a49888da566b9978346
0ece01daaf93548beea6c827d9674897
e7279ff1a19cb092659e8c1860fbad0d
b4ad0ad5732f1af4655dbd66214e552f
04ed8fd0104e1d4bf99c249ac229ce16
9d9ba22068c6c0ab742424760911d463
6aafb4b85f0c952a9ce4275bc821391a
a65fcd0d2394f006e3fba0fd34c4bc4a
b260f4b45dec3285875589c97d3087c9
134d3a3aa2f904512e85aa2dc2202498
-----END OpenVPN Static key V1-----
</tls-auth>
"#;

fn render(provider: TemplateProvider) -> (VpnProtocol, &'static str) {
    let contents = match provider {
        TemplateProvider::Mullvad => MULLVAD_WIREGUARD_TEMPLATE,
        TemplateProvider::ProtonVpn => PROTONVPN_OPENVPN_TEMPLATE,
        TemplateProvider::NordVpn => NORDVPN_OPENVPN_TEMPLATE,
        TemplateProvider::Ivpn => IVPN_WIREGUARD_TEMPLATE,
        TemplateProvider::PrivateInternetAccess => PIA_OPENVPN_TEMPLATE,
        TemplateProvider::Surfshark => SURFSHARK_OPENVPN_TEMPLATE,
    };
    (provider.protocol(), contents)
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
