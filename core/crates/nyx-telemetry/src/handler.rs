use crate::state::AppState;
use crate::{cpu, disk, memory, network, system};
use nyx_core::{CpuTelemetry, NyxOutput, TelemetryCommand, TelemetryReport};
use std::time::Instant;

const BINARY: &str = "nyx-telemetry";

pub async fn dispatch(state: &AppState, cmd: TelemetryCommand) -> NyxOutput<TelemetryReport> {
    match cmd {
        TelemetryCommand::Status => {
            let current_cpu = cpu::sample();
            let usage_percent = {
                let mut last_cpu = state.last_cpu.lock().await;
                let usage = current_cpu.and_then(|c| cpu::usage_percent(*last_cpu, c));
                if let Some(c) = current_cpu {
                    *last_cpu = Some(c);
                }
                usage
            };
            let (load_average_1m, load_average_5m, load_average_15m) = cpu::load_average();

            let now = Instant::now();
            let current_net = network::sample();
            let network_reports = {
                let mut last_network = state.last_network.lock().await;
                let reports = network::to_reports(&last_network, &current_net, now);
                *last_network = current_net.into_iter().map(|(k, v)| (k, (v, now))).collect();
                reports
            };

            let report = TelemetryReport {
                cpu: CpuTelemetry { usage_percent, load_average_1m, load_average_5m, load_average_15m },
                memory: memory::sample(),
                disks: disk::samples(),
                network: network_reports,
                uptime_secs: system::uptime_secs(),
                process_count: system::process_count(),
                detail: "live /proc + statvfs snapshot".to_string(),
            };

            let detail = report.detail.clone();
            NyxOutput::ok(BINARY, "status", detail, Some(report))
        }
    }
}
