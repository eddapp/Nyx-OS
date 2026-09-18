//! nyx-core — shared foundation for all Nyx OS binaries.

pub mod error;
pub mod logging;
pub mod output;
pub mod protocol;

pub use error::{NyxError, NyxResult};
pub use output::{NyxOutput, Status};
pub use protocol::{
    DnsCommand, DnsReport, HealthCommand, HealthState, IntegrityCommand, IntegrityReport,
    KillSwitchLevel, SecurityState, Toggle, VpnCommand, VpnProfile, VpnProfileList, VpnProtocol,
    VpnReport, WipeReport, WipeTarget,
};

/// Path of the nyx-health control socket. Owned by root, group `wheel`,
/// mode 0660 — anyone who can `sudo` on this system can connect without a
/// prompt on every single action.
pub const HEALTH_SOCKET: &str = "/run/nyx/health.sock";

/// Path of the nyx-dns control socket. Same trust boundary as
/// [`HEALTH_SOCKET`]: owned by root, group `wheel`, mode 0660.
pub const DNS_SOCKET: &str = "/run/nyx/dns.sock";

/// Path of the nyx-integrity control socket. Same trust boundary as
/// [`HEALTH_SOCKET`].
pub const INTEGRITY_SOCKET: &str = "/run/nyx/integrity.sock";

/// Where nyx-integrity persists the checksum manifest it verifies against.
/// Root-owned, not writable by the daemon's own unprivileged callers —
/// only `nyx-integrity baseline`, run interactively as root, updates it.
pub const INTEGRITY_MANIFEST_PATH: &str = "/etc/nyx/integrity.manifest";

/// Path of the nyx-vpn control socket. Same trust boundary as
/// [`HEALTH_SOCKET`]: owned by root, group `wheel`, mode 0660.
pub const VPN_SOCKET: &str = "/run/nyx/vpn.sock";
