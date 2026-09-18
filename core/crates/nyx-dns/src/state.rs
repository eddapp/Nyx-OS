use nyx_core::DnsReport;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct AppState {
    pub last: Mutex<DnsReport>,
}
