use nyx_core::IntegrityReport;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct AppState {
    pub last: Mutex<IntegrityReport>,
}
