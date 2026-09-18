use crate::{cpu, network};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

/// The one piece of memory this otherwise-stateless daemon needs: the
/// previous CPU/network sample, so the next `Status` call can compute a
/// real rate instead of reporting raw, meaningless-alone counters.
pub struct AppState {
    pub last_cpu: Mutex<Option<cpu::CpuSample>>,
    pub last_network: Mutex<HashMap<String, (network::IfaceSample, Instant)>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            last_cpu: Mutex::new(None),
            last_network: Mutex::new(HashMap::new()),
        }
    }
}
