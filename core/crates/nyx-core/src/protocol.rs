//! Wire protocol between `nyx-health` (the root daemon that owns the kill
//! switch, firewall, and service lifecycle) and its clients — the dashboard,
//! and eventually a CLI. Transport is newline-delimited JSON over the Unix
//! socket at `/run/nyx/health.sock`.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Toggle {
    On,
    Off,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum HealthCommand {
    /// Report current state.
    Status,
    /// Immediately drop all traffic except loopback and stop Tor. One-way —
    /// only a fresh `nyx-health` restart clears it. Distinct from
    /// `KillSwitch { level: Armed }`: panic also stops Tor and cannot be
    /// undone by `Disarm` — only a daemon restart clears it.
    Panic,
    /// Start or stop the Tor daemon.
    Tor { action: Toggle },
    /// Set the kill-switch posture. This is a single selection out of four
    /// mutually exclusive levels, not an independent toggle — see
    /// [`KillSwitchLevel`] for what each one actually enforces.
    KillSwitch { level: KillSwitchLevel },
    /// Restart `tor.service` outright, forcing every circuit to be rebuilt
    /// from scratch. Used for Tor-over-VPN chaining (see nyx-workflow's
    /// `tor-over-vpn` workflow): once a VPN backend owns the default
    /// route, Tor's own traffic already flows over it automatically — Tor
    /// makes no routing decisions of its own — but any circuit built
    /// *before* the VPN connected may still be using the old route
    /// underneath. A plain restart is the deliberate choice over Tor's
    /// authenticated control-port protocol (`ControlPort 9051` +
    /// `AUTHENTICATE` + `SIGNAL NEWNYM`), which would rebuild circuits
    /// without the momentary restart blip but means implementing
    /// cookie/password authentication and a second long-lived control
    /// connection from scratch for a benefit that's purely about avoiding
    /// that blip — not worth it here.
    TorRestart,
}

/// The kill switch is a ladder of firewall postures, not a single on/off
/// bit — "on" meant different things to different callers in practice
/// (block new connections vs. sever everything instantly), so those are
/// separate, explicitly named levels instead of one boolean plus tribal
/// knowledge about what it currently does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchLevel {
    /// No restriction — traffic keeps flowing even if the tunnel dies.
    #[default]
    Off,
    /// Blocks new outbound connections; connections already established
    /// (e.g. before the tunnel dropped) are left alone until they close on
    /// their own.
    Soft,
    /// Everything Soft does, plus severs any already-established
    /// connection that isn't going out over the designated tunnel
    /// interface. If no tunnel interface can be detected, nyx-health
    /// refuses to silently claim this level and reports it as Soft instead
    /// (see `HealthState.kill_switch_warning`).
    Medium,
    /// Total, immediate lockdown in both directions except loopback —
    /// equivalent in effect to `Panic`'s network posture, but reversible
    /// via `KillSwitch { level: Off }` without restarting the daemon, and
    /// does not stop Tor or set `panic_mode`.
    Armed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthState {
    pub tor_active: bool,
    pub kill_switch_level: KillSwitchLevel,
    /// The tunnel interface nyx-health auto-detected (first `wg*`/`tun*`/
    /// `ppp*` interface it finds) and used the last time it enforced
    /// `Medium`. `None` means Medium can't currently be enforced as
    /// designed and falls back to Soft.
    pub kill_switch_tunnel_iface: Option<String>,
    /// Set when the last `KillSwitch` command couldn't do exactly what was
    /// asked (e.g. Medium requested with no tunnel interface present).
    pub kill_switch_warning: Option<String>,
    pub panic_mode: bool,
}

/// Coarse security posture shared by every subsystem that can actually
/// *assess* whether the property it owns is holding — never set to
/// `Protected` merely because a process happens to be running. Each daemon
/// derives this from its own real checks (socket state, listener presence,
/// live query behaviour, checksum comparison, ...), not from "did I try to
/// start the service".
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    /// No check has run yet.
    #[default]
    Unknown,
    /// A check is in flight / the subsystem is initializing.
    Starting,
    /// The property this subsystem owns is verified and holding.
    Protected,
    /// Partially verified — some expected control is missing or unverifiable,
    /// but nothing is actively leaking/broken as far as we can tell.
    Degraded,
    /// The property is not holding; traffic/state that should be blocked is
    /// (or may be) getting through.
    Blocked,
    /// A destructive/defensive lockdown is active (e.g. nyx-health panic).
    Emergency,
    /// The check itself failed (couldn't reach a service, bad permissions).
    Error,
}

// ---------------------------------------------------------------------------
// nyx-dns wire protocol — socket at `DNS_SOCKET`.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DnsCommand {
    /// Return the last computed report (computed fresh — checks here are
    /// cheap: file reads, /proc scans, one loopback query).
    Status,
    /// List nyx-dns's curated set of switchable DNS providers, plus which
    /// one(s) are currently active — read live from the deployed
    /// dnscrypt-proxy config's `server_names` line, not from the curated
    /// list itself.
    ListProviders,
    /// Switch dnscrypt-proxy to the named curated provider: rewrite the
    /// deployed config's `server_names` line to that provider's stamp
    /// name, restart `dnscrypt-proxy.service`, then verify a live query
    /// still resolves. `provider` must be one of the ids `ListProviders`
    /// returns — an arbitrary caller-supplied stamp name is rejected, so
    /// this can't be used to point NyxOS at an unverified resolver. On a
    /// failed verification query, the previous `server_names` line is
    /// restored and the service restarted again rather than leaving DNS
    /// broken.
    SwitchProvider { provider: String },
}

/// One entry in nyx-dns's curated list of switchable DNS providers. The
/// actual dnscrypt-proxy stamp name each id maps to is internal to
/// nyx-dns and never crosses the wire — callers only ever see and pass
/// back the id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsProvider {
    pub id: String,
    pub display_name: String,
    /// True if this provider's stamp name is present in the deployed
    /// dnscrypt-proxy config's `server_names` line right now.
    pub active: bool,
}

/// Result of actually checking the DNS path, not just "is a process running".
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsReport {
    /// `/etc/resolv.conf` lists only loopback nameservers.
    pub resolver_is_local: bool,
    /// Raw nameserver lines found in `/etc/resolv.conf`.
    pub resolver_addrs: Vec<String>,
    /// `dnscrypt-proxy.service` is active per systemd.
    pub dnscrypt_active: bool,
    /// A live query against 127.0.0.1:53 actually returned a response.
    pub resolves: bool,
    /// Something other than dnscrypt-proxy is bound to port 53 on a
    /// non-loopback address — a potential leak path around the enforced
    /// resolver.
    pub foreign_listener_on_53: bool,
    pub state: SecurityState,
    pub detail: String,
    /// Only populated in response to `DnsCommand::ListProviders`; empty
    /// otherwise. Kept on this one report type rather than a separate
    /// response shape so every `DnsCommand` can share the same
    /// `NyxOutput<DnsReport>` wire type.
    pub providers: Vec<DnsProvider>,
}

// ---------------------------------------------------------------------------
// nyx-integrity wire protocol — socket at `INTEGRITY_SOCKET`.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IntegrityCommand {
    /// Return the last completed report without re-scanning.
    Status,
    /// Re-run verification now. `quick=true` limits the pacman file-integrity
    /// scan to NyxOS-critical packages instead of the whole system (which can
    /// take minutes on a large install).
    Verify { quick: bool },
    /// Recompute and persist the manifest of Nyx-owned files (binaries,
    /// firewall ruleset, service units) from what's on disk *right now*.
    /// This is a trust-on-first-use operation — call it once, right after a
    /// known-good install/update, not routinely.
    Baseline,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct IntegrityReport {
    pub manifest_present: bool,
    pub manifest_checked: usize,
    pub manifest_mismatches: Vec<String>,
    pub package_scanned: usize,
    pub package_mismatches: Vec<String>,
    pub state: SecurityState,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// nyx-wipe wire types. nyx-wipe is deliberately a one-shot privileged CLI,
// not a resident daemon — see core/crates/nyx-wipe/src/main.rs for why. These
// types exist so its JSON output matches every other Nyx binary and so the
// dashboard can deserialize it after shelling out via pkexec.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WipeTarget {
    /// Shell history files (bash/zsh) for all local users.
    ShellHistory,
    /// `/tmp` and `/var/tmp` contents not currently held open.
    Tmp,
    /// Thumbnail cache (`~/.cache/thumbnails`) for all local users.
    Thumbnails,
    /// Recently-used file lists (`~/.local/share/recently-used.xbel`, XFCE/
    /// GTK recent-files chooser state) for all local users.
    RecentFiles,
    /// Rotate/vacuum the systemd journal down to nothing older than now.
    Logs,
    /// Overwrite unused disk blocks and inodes on `/` and `/home` (whichever
    /// mountpoints those actually resolve to) with `sfill`. Slow by nature —
    /// it writes until the target filesystem is full, then removes what it
    /// wrote.
    FreeSpace,
    /// Securely delete the *contents* of `~/Documents` (folder itself kept)
    /// for every real local account.
    ShredDocuments,
    /// Securely delete the *contents* of `~/Downloads` (folder itself kept)
    /// for every real local account.
    ShredDownloads,
    /// Securely delete the *contents* of `~/Desktop` (folder itself kept)
    /// for every real local account.
    ShredDesktop,
}

// ---------------------------------------------------------------------------
// nyx-vpn wire protocol — socket at `VPN_SOCKET`.
//
// Only protocols with a real backend on this system are represented here.
// There is no placeholder variant for a transport NyxOS doesn't actually
// implement yet — adding one to this enum should mean a working `up`/`down`/
// `status` path exists in nyx-vpn, not a UI button with nothing behind it.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum VpnProtocol {
    /// `wg-quick`, profiles at `/etc/wireguard/<name>.conf`.
    WireGuard,
    /// `openvpn-client@<name>.service`, profiles at
    /// `/etc/openvpn/client/<name>.conf`.
    OpenVpn,
    /// AmneziaWG — a WireGuard fork adding traffic-obfuscation parameters
    /// (`Jc`/`Jmin`/`Jmax`/`S1`/`S2`/`H1`-`H4`) to the same config format.
    /// `awg-quick`/`awg` mirror `wg-quick`/`wg`'s CLI exactly, profiles at
    /// `/etc/amnezia/amneziawg/<name>.conf`.
    AmneziaWg,
    /// Xray-core — one binary serving VLESS, VMess, Trojan, and REALITY
    /// (REALITY is a `streamSettings.realitySettings` option on a VLESS
    /// outbound, not a separate protocol). Run via `xray run -c
    /// <config>.json` under a templated systemd unit
    /// (`nyx-vpn-xray@<name>.service`), profiles at
    /// `/etc/nyx/xray/<name>.json`.
    Xray,
    /// shadowsocks-rust. Run via `ssservice local -c <config>.json` under
    /// that package's own upstream-shipped `shadowsocks-rust@<name>.service`
    /// template unit (not one nyx-vpn ships), profiles at
    /// `/etc/shadowsocks-rust/<name>.json`.
    Shadowsocks,
    /// Hysteria2 — a QUIC-based proxy. Run via `hysteria client -c
    /// <config>.yaml` under a templated systemd unit
    /// (`nyx-vpn-hysteria@<name>.service`), profiles at
    /// `/etc/nyx/hysteria/<name>.yaml`.
    Hysteria2,
    /// SOCKS5, bridged into a real TUN interface (and the OS default
    /// route) via `badvpn-tun2socks`. Deliberately not named/backed by the
    /// `dante` package: dante's own client-side story is `socksify`, an
    /// LD_PRELOAD wrapper for one application at a time, not a
    /// system-wide tunnel — see `dante.rs` for the full reasoning. SOCKS5
    /// itself has no built-in encryption or authentication, so this
    /// protocol is never reported fully `Protected` no matter how clean
    /// the route looks — see `handler.rs`.
    Socks5,
    /// mieru (github.com/enfein/mieru) — an anti-censorship SOCKS5/HTTP/
    /// HTTPS proxy protocol using XChaCha20-Poly1305 with random padding
    /// and a client+server replay cache, purpose-built to resist DPI/GFW
    /// classification. Client binary `mieru`, run via `mieru run` with
    /// `MIERU_CONFIG_JSON_FILE=<config>.json` under a templated systemd
    /// unit (`nyx-vpn-mieru@<name>.service`), profiles at
    /// `/etc/nyx/mieru/<name>.json`.
    Mieru,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VpnProfile {
    pub protocol: VpnProtocol,
    pub name: String,
    /// True when this profile still contains an unfilled
    /// `WriteProviderTemplate` placeholder — `nyx-vpn`'s own `List`/`Status`
    /// flags it so a caller can tell "not yet usable" from "ready to
    /// connect" without trying it and getting a confusing failure.
    /// `#[serde(default)]` so a profile reported by an older wire peer
    /// (before this field existed) still deserializes.
    #[serde(default)]
    pub incomplete: bool,
}

/// A curated, genuinely free-of-charge public VPN directory — no account,
/// no credentials, no payment, ever. Deliberately just these two: every
/// other widely-known "free VPN" either requires signup, caps
/// bandwidth/time, or isn't actually free end-to-end — these are the real
/// exceptions. See `nyx-vpn`'s `free_provider` module for the verified API
/// details behind each.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FreeProvider {
    /// University of Tsukuba's VPN Gate academic relay project — a public
    /// CSV directory of volunteer-run relays
    /// (`https://www.vpngate.net/api/iphone/`), each entry already
    /// carrying a ready-to-use base64-encoded OpenVPN config. No account
    /// of any kind.
    VpnGate,
    /// Riseup Networks' donation-funded VPN — `api.black.riseup.net`
    /// issues a real, immediately usable OpenVPN client certificate with
    /// zero signup (`/3/cert` for the client cert+key, `/3/config/
    /// eip-service.json` for the gateway list and OpenVPN parameters).
    Riseup,
}

/// A commercial VPN provider NyxOS cannot embed a real paid account for —
/// but can still write a real, correctly-shaped config skeleton for, with
/// an obvious placeholder over exactly the field(s) that need the user's
/// own account. Deliberately just these three. See `nyx-vpn`'s `templates`
/// module for the verified format details behind each.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateProvider {
    /// WireGuard skeleton — real shape confirmed against Mullvad's own
    /// public WireGuard relay directory (`api.mullvad.net`): internal
    /// resolver `10.64.0.1`, port `51820`, relay hostnames of the form
    /// `<code>-<city>-wg-<NNN>.relays.mullvad.net`. `PrivateKey` and the
    /// account-assigned tunnel `Address` are the placeholders — both are
    /// generated per-account by Mullvad, not something NyxOS can supply.
    Mullvad,
    /// OpenVPN skeleton — ProtonVPN issues a separate OpenVPN/IKEv2
    /// username+password per account (distinct from the account login)
    /// plus per-server `<ca>`/`<tls-crypt>` material downloaded from the
    /// logged-in account. Both are the placeholders here.
    ProtonVpn,
    /// OpenVPN skeleton — NordVPN publishes a public, unauthenticated
    /// server-list API (`api.nordvpn.com/v1/servers`) but still requires a
    /// separate per-account OpenVPN service credential (distinct from the
    /// account login), which is the placeholder here.
    NordVpn,
}

/// An upstream SOCKS5 proxy — in practice always Tor's SocksPort
/// (`127.0.0.1:9050`, per `iso/airootfs/etc/tor/torrc`) — that a VPN
/// backend should dial its own connection to its server through. See
/// [`VpnCommand::ConnectViaSocksProxy`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SocksProxyAddr {
    pub host: String,
    pub port: u16,
}

/// Real client-side config for `cbeuw/Cloak`'s obfuscation layer
/// (`ck-client`), specifically for wrapping OpenVPN — see
/// [`VpnCommand::ConnectViaCloak`]. Field names/shapes are confirmed
/// against upstream Cloak's own `internal/client/state.go` `RawConfig`
/// struct and its `example_config/ckclient.json` (Cloak v2.10.0, the
/// version `cloak-obfuscation-bin` on the AUR currently packages): Go
/// marshals a `[]byte` field as base64 JSON, which is why `public_key`/
/// `uid` are base64 strings here, not raw bytes.
///
/// This only covers Cloak's "direct" transport (`ck-client` dials
/// `remote_host`/`remote_port` itself) — Cloak's CDN-fronting transport
/// (`CDNOriginHost`/`CDNWsUrlPath`, dialing a CDN edge instead) is a real
/// but separate mode this struct doesn't expose.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CloakConfig {
    /// The Cloak server's real public address — confirmed against Cloak's
    /// own wiki: this is the *same* host:port the OpenVPN profile's own
    /// `remote` directive already points at, because `ck-server` is the
    /// thing actually answering on that port (masquerading as ordinary
    /// HTTPS) with the real OpenVPN server sitting behind it, reachable
    /// only via `ck-server`'s `ProxyBook`.
    pub remote_host: String,
    pub remote_port: u16,
    /// curve25519 public key Cloak's server operator issued, base64.
    pub public_key: String,
    /// User ID Cloak's server operator issued, base64.
    pub uid: String,
    /// The innocuous domain to present via SNI/Host (Cloak's domain-fronting
    /// disguise), e.g. `"www.bing.com"` — must be a real site the server's
    /// `RedirAddr`/censor's DPI would consider unremarkable.
    pub server_name: String,
    /// `"aes-256-gcm"`, `"aes-128-gcm"`, `"chacha20-poly1305"`, or `"plain"`
    /// — Cloak's own docs warn `"plain"` must not be used when wrapping
    /// OpenVPN specifically, since OpenVPN's own handshake has a
    /// recognizable fingerprint that plaintext framing would still expose;
    /// `nyx-vpn` rejects `"plain"` outright for this command rather than
    /// silently accepting a config that defeats the point of wrapping.
    pub encryption_method: String,
    /// Number of underlying TCP connections Cloak multiplexes over.
    /// `None` defers to Cloak's own default (4).
    pub num_conn: Option<u32>,
    /// TLS ClientHello fingerprint to mimic (`"chrome"`, `"firefox"`, ...).
    /// `None` defers to Cloak's own default (`"chrome"`).
    pub browser_sig: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum VpnCommand {
    /// Report current state, re-derived from live probes each call (active
    /// interfaces, handshake recency, default-route ownership) — never just
    /// "what did we last set".
    Status,
    /// List every profile found on disk for either backend.
    List,
    /// Bring up exactly one profile. If a different profile/protocol is
    /// already up, it is torn down first — NyxOS never runs two VPN
    /// tunnels at once, to avoid ambiguous routing.
    Connect { protocol: VpnProtocol, profile: String },
    /// VPN-over-Tor chaining: same as `Connect`, but dials the backend's
    /// own connection to its server through `socks_proxy` instead of
    /// directly. Only three backends have a real, upstream-documented way
    /// to do this and are honored: OpenVPN (`--socks-proxy`, and the
    /// profile must already specify `proto tcp-client`/`tcp4-client`/
    /// `tcp6-client` — SOCKS5 only carries TCP), Xray
    /// (`streamSettings.sockopt.dialerProxy`), and Shadowsocks
    /// (`outbound_proxy`). WireGuard and AmneziaWG are UDP-only in-kernel
    /// tunnels, Hysteria2's transport is QUIC (also UDP) with no
    /// proxy-chaining option of its own, and the SOCKS5/badvpn-tun2socks
    /// backend has only one upstream-proxy slot with no chaining flag —
    /// all four are rejected outright with an explanation rather than
    /// faking support. See `nyx-vpn`'s backend modules for the verified
    /// details behind each.
    ConnectViaSocksProxy { protocol: VpnProtocol, profile: String, socks_proxy: SocksProxyAddr },
    /// OpenVPN-over-Cloak: wraps `profile`'s OpenVPN connection in
    /// `cbeuw/Cloak`'s obfuscation layer (`ck-client`), a censorship
    /// circumvention tool that disguises the connection as ordinary HTTPS
    /// to `cloak_config.server_name` (domain fronting) — this is real
    /// traffic-shape obfuscation against DPI-based censorship, *not* an
    /// additional cryptographic guarantee: `handler.rs` still caps the
    /// resulting connection at whatever OpenVPN itself would honestly earn
    /// (`Protected` only once the interface has an address and carries the
    /// default route, same as plain OpenVPN). Only OpenVPN is honored —
    /// Cloak's own `ProxyBook`/config shape is generic, but this command is
    /// deliberately scoped to the one backend NyxOS has a verified real
    /// integration for.
    ConnectViaCloak { profile: String, cloak_config: CloakConfig },
    /// Tear down whatever is currently up, if anything.
    Disconnect,
    /// Validate and install a caller-supplied config as a new profile for
    /// `protocol`, named `name`. Contents travel over the socket as bytes
    /// rather than a filesystem path: the caller is normally unprivileged
    /// and has no write access to `protocol`'s root-owned profile
    /// directory, so the root daemon takes the data and performs the
    /// privileged write itself — the same "caller supplies data, daemon
    /// does the privileged write" shape every other mutating command here
    /// already uses (contrast a path-based design, which would require
    /// either the unprivileged caller already having filesystem access it
    /// doesn't have, or the daemon trusting a path it didn't write).
    /// Rejected with a clear error if `contents` doesn't parse as a
    /// well-formed profile for `protocol` — a real protocol-shaped check,
    /// not just "the write succeeded".
    ImportProfile { protocol: VpnProtocol, name: String, contents: String },
    /// Fetch a relay/gateway from a curated, genuinely free public VPN
    /// directory and write it as a ready-to-use OpenVPN profile at
    /// `/etc/openvpn/client/` — zero account, zero further user action.
    /// This makes a real outbound HTTPS request to the named provider's
    /// own public API; `nyx-vpn` logs that plainly rather than hiding it.
    /// `country` (an ISO 3166-1 alpha-2 code) narrows `FreeProvider::
    /// VpnGate`'s relay choice to the highest-bandwidth match; ignored for
    /// `FreeProvider::Riseup`, which has no country selection of its own.
    FetchFreeProvider { provider: FreeProvider, country: Option<String> },
    /// Write a real, correctly-shaped (but incomplete) config skeleton for
    /// a commercial provider NyxOS cannot embed a real paid account for —
    /// see [`TemplateProvider`]. The written profile is flagged
    /// `incomplete` by `List`/`Status` until the user replaces its
    /// placeholder(s) with their own account's real values.
    WriteProviderTemplate { provider: TemplateProvider, name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct VpnReport {
    pub connected: bool,
    pub protocol: Option<VpnProtocol>,
    pub profile: Option<String>,
    pub interface: Option<String>,
    /// WireGuard and AmneziaWG only — both expose the same
    /// handshake-recency concept over the same shape of CLI query
    /// (`wg`/`awg show <iface> latest-handshakes`). `None` means either
    /// not connected, connected but no peer has handshaked yet (normal
    /// immediately after bringing the tunnel up, not itself a fault), or
    /// connected via a protocol that has no such concept to report at all
    /// (OpenVPN, Xray, Shadowsocks, Hysteria2, SOCKS5).
    pub handshake_age_secs: Option<u64>,
    /// True only when the OS default route actually goes out the VPN
    /// interface. An "up" tunnel that isn't carrying the default route may
    /// not be protecting the traffic the caller cares about.
    pub default_route_via_vpn: bool,
    pub state: SecurityState,
    pub detail: String,
    /// Only populated in response to `VpnCommand::List`; empty otherwise.
    /// Kept on this one report type rather than a separate response shape
    /// so every `VpnCommand` can share the same `NyxOutput<VpnReport>`
    /// wire type.
    pub profiles: Vec<VpnProfile>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct WipeReport {
    pub target: String,
    /// False for every target here — all of them destroy the only copy of
    /// the data. Kept explicit so the CLI/dashboard never has to guess.
    pub reversible: bool,
    pub files_affected: usize,
    pub bytes_affected: u64,
    /// False on a `plan` (dry-run); true only after `execute --yes` actually
    /// ran.
    pub executed: bool,
    /// Non-fatal caveats, e.g. "target is SSD/NVMe — overwritten bytes are
    /// not guaranteed erased at the flash-translation-layer level".
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// nyx-identity wire protocol — socket at `IDENTITY_SOCKET`.
//
// Deliberately does NOT include "sync timezone to exit IP" or "decoy
// traffic" — both would mean this daemon making its own outbound network
// calls (to a geolocation service, or to generate cover traffic) by
// default, which is a real privacy/dependency trade-off this project isn't
// making silently. Randomize/restore/show only, for values that can be
// changed and verified locally.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IdentityCommand {
    /// Report current hostname, timezone, IPv6 posture, and every
    /// non-loopback interface's current MAC — re-read live each call.
    Status,
    /// Set `interface`'s cloned MAC to a fresh random address via
    /// NetworkManager (`cloned-mac-address random`), then reactivate the
    /// connection.
    RandomizeMac { interface: String },
    /// Set `interface`'s cloned MAC back to the hardware's permanent
    /// address (`cloned-mac-address permanent`) and reactivate.
    RestoreMac { interface: String },
    /// Set the hostname to a freshly generated one. The pre-randomization
    /// hostname is captured the first time this runs (if not already
    /// captured) so `RestoreHostname` has something real to go back to.
    RandomizeHostname,
    RestoreHostname,
    /// Pick a random IANA timezone from the system's own zoneinfo list.
    /// The original is captured the first time this runs, same as hostname.
    RandomizeTimezone,
    RestoreTimezone,
    /// System-wide IPv6 on/off via sysctl, persisted under
    /// `/etc/sysctl.d/` so it survives reboot.
    SetIpv6 { enabled: bool },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct InterfaceIdentity {
    pub interface: String,
    pub mac_address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityReport {
    pub hostname: Option<String>,
    /// The hostname captured before the first `RandomizeHostname`, if any
    /// randomization has happened yet this install.
    pub original_hostname: Option<String>,
    pub timezone: Option<String>,
    pub original_timezone: Option<String>,
    pub ipv6_enabled: Option<bool>,
    pub interfaces: Vec<InterfaceIdentity>,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// nyx-devices wire protocol — socket at `DEVICES_SOCKET`.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRadio {
    /// `nmcli radio wifi` — the application-layer radio switch NetworkManager
    /// itself owns, rather than a raw `rfkill`, so NM's own state stays
    /// consistent.
    Wifi,
    /// `rfkill block/unblock bluetooth` — there's no NetworkManager-level
    /// equivalent for Bluetooth.
    Bluetooth,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceModule {
    /// `uvcvideo` — covers USB Video Class webcams, not every webcam ever
    /// made, but the large majority on a modern laptop/USB camera.
    Webcam,
    /// `usb_storage` — mass-storage USB devices only. USB HID (keyboards,
    /// mice) use a different driver and keep working.
    UsbStorage,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DevicesCommand {
    /// Report everything — re-probed live each call: radio states, module
    /// states, USBGuard's actual configured policy (not just "is it
    /// running"), connected USB devices, and LUKS-encrypted block devices.
    Status,
    SetRadio { radio: DeviceRadio, on: bool },
    /// `enabled: false` also writes a modprobe blacklist file so the
    /// module doesn't come back on the next device (re)plug or reboot;
    /// `true` removes that blacklist file and reloads the module.
    SetModule { module: DeviceModule, enabled: bool },
    /// Mutes/unmutes the default PipeWire audio source via `wpctl` — there
    /// is no kernel module to unload without silencing every microphone
    /// input path at once, so this is done at the audio-server level.
    SetMicrophone { enabled: bool },
    SetUsbGuard { enabled: bool },
    /// Live device list from USBGuard's own IPC socket (`usbguard
    /// list-devices`) — currently-connected devices with their assigned
    /// rule IDs and attributes, not just the static policy file.
    ListUsbGuardDevices,
    /// Interactively authorizes one currently-connected device by the rule
    /// ID USBGuard assigned it (as shown by `ListUsbGuardDevices`).
    /// `permanent: true` also appends a matching rule to the policy file
    /// (`usbguard allow-device -p`) so the decision survives replug/reboot;
    /// `false` is a one-time allow for this connection only.
    AllowUsbGuardDevice { id: String, permanent: bool },
    /// Interactively rejects (disconnects) one currently-connected device
    /// by its USBGuard-assigned rule ID.
    RejectUsbGuardDevice { id: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DevicesReport {
    pub wifi_enabled: Option<bool>,
    pub bluetooth_enabled: Option<bool>,
    pub webcam_enabled: Option<bool>,
    pub microphone_enabled: Option<bool>,
    pub usb_storage_enabled: Option<bool>,
    pub usbguard_active: Option<bool>,
    /// True if USBGuard's own configured `ImplicitPolicyTarget` is `block`
    /// — i.e. unknown devices are refused by default, not merely that the
    /// service happens to be running.
    pub usbguard_default_deny: Option<bool>,
    /// True if the filesystem mounted at `/` sits on a `crypto_LUKS`
    /// device — a real block-device-topology check, not a settings flag.
    pub encrypted_root: Option<bool>,
    /// One line per `crypto_LUKS`-typed block device found by `lsblk`.
    pub luks_devices: Vec<String>,
    /// One line per USB device from `lsusb`.
    pub usb_devices: Vec<String>,
    /// Raw rule lines from USBGuard's own policy file
    /// (`/etc/usbguard/rules.conf`) — "allow"-prefixed lines are its
    /// whitelist.
    pub usbguard_policy: Vec<String>,
    /// Recent USBGuard connect/disconnect journal lines, if any.
    pub usbguard_history: Vec<String>,
    /// Live, currently-connected devices from USBGuard's own IPC socket
    /// (`usbguard list-devices`) — one raw line per device, including the
    /// rule ID needed to allow/reject it. Empty if USBGuard isn't running
    /// or the IPC call failed.
    pub usbguard_live_devices: Vec<String>,
    /// Summarizes USB authorization posture specifically: USBGuard active
    /// and default-deny means Protected. Radio/webcam/mic toggles are plain
    /// user settings and don't factor into this.
    pub state: SecurityState,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// nyx-telemetry wire protocol — socket at `TELEMETRY_SOCKET`.
//
// Unlike every other Nyx daemon, this one needs no privileged operation at
// all — every value here comes from `/proc` or `statvfs`, both readable by
// any user. It runs unprivileged (see its systemd unit's `DynamicUser=yes`)
// and its socket is world-readable; there is no security boundary to
// enforce over CPU/RAM/network numbers.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum TelemetryCommand {
    Status,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct CpuTelemetry {
    /// `None` on the daemon's first-ever `Status` call — CPU usage needs
    /// two samples to compute a rate, and there's no prior one yet.
    /// Reported as unknown rather than a fabricated 0%.
    pub usage_percent: Option<f64>,
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryTelemetry {
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub swap_total_kb: u64,
    pub swap_used_kb: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DiskTelemetry {
    pub mountpoint: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct NetworkInterfaceTelemetry {
    pub interface: String,
    /// `None` on the first sample seen for this interface this run.
    pub rx_bytes_per_sec: Option<f64>,
    pub tx_bytes_per_sec: Option<f64>,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TelemetryReport {
    pub cpu: CpuTelemetry,
    pub memory: MemoryTelemetry,
    /// Every real (non-pseudo) mounted filesystem found in `/proc/mounts`.
    pub disks: Vec<DiskTelemetry>,
    /// Every interface `/proc/net/dev` reports, including loopback.
    pub network: Vec<NetworkInterfaceTelemetry>,
    pub uptime_secs: u64,
    pub process_count: usize,
    pub detail: String,
}
