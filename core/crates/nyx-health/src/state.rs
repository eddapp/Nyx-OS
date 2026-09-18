use nyx_core::HealthState;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct AppState {
    pub health: Mutex<HealthState>,
}
