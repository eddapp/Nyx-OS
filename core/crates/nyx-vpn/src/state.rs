use nyx_core::VpnProtocol;
use tokio::sync::Mutex;

/// What nyx-vpn itself last connected, if anything — used so `Disconnect`
/// and `Connect`'s "tear down the previous one first" step know which
/// backend to call without re-probing. `Status` still verifies live state
/// independently rather than trusting this alone.
#[derive(Default)]
pub struct AppState {
    pub active: Mutex<Option<(VpnProtocol, String)>>,
}
