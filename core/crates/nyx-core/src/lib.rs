//! nyx-core — shared foundation for all Nyx OS binaries.

pub mod error;
pub mod logging;
pub mod output;
pub mod protocol;

pub use error::{NyxError, NyxResult};
pub use output::{NyxOutput, Status};
pub use protocol::{
    CpuTelemetry, DeviceModule, DeviceRadio, DevicesCommand, DevicesReport, DiskTelemetry,
    DnsCommand, DnsReport, HealthCommand, HealthState, IdentityCommand, IdentityReport,
    IntegrityCommand, IntegrityReport, InterfaceIdentity, KillSwitchLevel,
    MemoryTelemetry, NetworkInterfaceTelemetry, SecurityState, TelemetryCommand, TelemetryReport,
    Toggle, VpnCommand, VpnProfile, VpnProtocol, VpnReport, WipeReport, WipeTarget,
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

/// Path of the nyx-identity control socket. Same trust boundary as
/// [`HEALTH_SOCKET`].
pub const IDENTITY_SOCKET: &str = "/run/nyx/identity.sock";

/// Where nyx-identity persists the pre-randomization hostname/timezone, so
/// `RestoreHostname`/`RestoreTimezone` have something real to go back to
/// even across a daemon restart. Root-owned.
pub const IDENTITY_STATE_PATH: &str = "/etc/nyx/identity-state.json";

/// Path of the nyx-devices control socket. Same trust boundary as
/// [`HEALTH_SOCKET`].
pub const DEVICES_SOCKET: &str = "/run/nyx/devices.sock";

/// Path of the nyx-telemetry control socket. Deliberately NOT under
/// `/run/nyx` — that directory is root:wheel 0750, and this daemon runs
/// unprivileged (`DynamicUser=yes`) with no reason to share a runtime
/// directory it can't write to. World-readable: CPU/RAM/network numbers
/// aren't a security boundary.
pub const TELEMETRY_SOCKET: &str = "/run/nyx-telemetry/telemetry.sock";
