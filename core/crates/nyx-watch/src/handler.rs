use crate::protocol::{WatchCommand, WatchReport};
use crate::state::AppState;
use nyx_core::NyxOutput;

const BINARY: &str = "nyx-watch";

pub async fn dispatch(state: &AppState, cmd: WatchCommand) -> NyxOutput<WatchReport> {
    match cmd {
        WatchCommand::Status => {
            let report = state.report().await;
            let detail = report.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(report))
        }
    }
}
