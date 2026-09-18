//! Curated list of DNS providers nyx-dns will switch dnscrypt-proxy to.
//!
//! Every stamp name below was confirmed against the real, current
//! `public-resolvers.md` fetched from
//! `https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md`
//! (the same source `dnscrypt-proxy.toml`'s `[sources.'public-resolvers']`
//! already points at) — none of these were guessed. `cloudflare` and
//! `quad9-dnscrypt-ip4-filter-pri` are the two already shipped in
//! `server_names` today. Mullvad's DoH stamps (`mullvad-doh` and friends)
//! were deliberately left out even though Mullvad is well known: every one
//! of them carries "- Deprecated, will be shot down on 11/02/2026" in that
//! same source file, a date already behind us.

/// A provider a caller can ask to switch to. `stamp` is the dnscrypt-proxy
/// `server_names` entry this id maps to and never crosses the wire — only
/// `id` does (see [`nyx_core::DnsCommand::SwitchProvider`]).
pub struct CuratedProvider {
    pub id: &'static str,
    pub display_name: &'static str,
    pub stamp: &'static str,
}

pub const PROVIDERS: &[CuratedProvider] = &[
    CuratedProvider { id: "cloudflare", display_name: "Cloudflare (1.1.1.1)", stamp: "cloudflare" },
    CuratedProvider {
        id: "quad9",
        display_name: "Quad9 (filtered, DNSCrypt)",
        stamp: "quad9-dnscrypt-ip4-filter-pri",
    },
    CuratedProvider {
        id: "adguard",
        display_name: "AdGuard DNS (default filtering)",
        stamp: "adguard-dns",
    },
    CuratedProvider {
        id: "adguard-unfiltered",
        display_name: "AdGuard DNS (unfiltered)",
        stamp: "adguard-dns-unfiltered",
    },
    CuratedProvider { id: "libredns", display_name: "LibreDNS", stamp: "libredns" },
    CuratedProvider {
        id: "libredns-noads",
        display_name: "LibreDNS (ad-blocking)",
        stamp: "libredns-noads",
    },
];

pub fn find(id: &str) -> Option<&'static CuratedProvider> {
    PROVIDERS.iter().find(|p| p.id == id)
}
