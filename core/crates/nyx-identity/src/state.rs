use crate::persisted::{self, PersistedState};
use tokio::sync::Mutex;

pub struct AppState {
    pub persisted: Mutex<PersistedState>,
}

impl Default for AppState {
    fn default() -> Self {
        Self { persisted: Mutex::new(persisted::load()) }
    }
}
