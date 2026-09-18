use crate::client;
use crate::model::{Condition, Workflow, WorkflowCommand};
use nyx_core::{
    DnsCommand, DnsReport, HealthCommand, HealthState, IntegrityCommand, IntegrityReport,
    NyxOutput, Status, Toggle, VpnCommand, VpnReport, DNS_SOCKET, HEALTH_SOCKET,
    INTEGRITY_SOCKET, VPN_SOCKET,
};
use std::io::Write;

pub struct StepResult {
    pub description: String,
    pub ran: bool,
    pub ok: bool,
    pub message: String,
}

pub struct WorkflowReport {
    pub id: String,
    pub results: Vec<StepResult>,
}

fn ask_yes_no(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn call_health(cmd: HealthCommand) -> (bool, String) {
    match client::call::<HealthCommand, NyxOutput<HealthState>>(HEALTH_SOCKET, &cmd) {
        Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
        Err(e) => (false, e),
    }
}

fn execute(cmd: &WorkflowCommand) -> (bool, String) {
    match cmd {
        WorkflowCommand::Message(text) => {
            println!("{text}");
            (true, text.clone())
        }
        WorkflowCommand::Confirm(text) => (ask_yes_no(text), "operator confirmation".to_string()),
        WorkflowCommand::HealthStatus => call_health(HealthCommand::Status),
        WorkflowCommand::HealthTor { on } => call_health(HealthCommand::Tor {
            action: if *on { Toggle::On } else { Toggle::Off },
        }),
        WorkflowCommand::HealthKillSwitch { level } => {
            call_health(HealthCommand::KillSwitch { level: *level })
        }
        WorkflowCommand::HealthPanic => call_health(HealthCommand::Panic),
        WorkflowCommand::DnsStatus => {
            match client::call::<DnsCommand, NyxOutput<DnsReport>>(DNS_SOCKET, &DnsCommand::Status) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::IntegrityStatus => match client::call::<IntegrityCommand, NyxOutput<IntegrityReport>>(
            INTEGRITY_SOCKET,
            &IntegrityCommand::Status,
        ) {
            Ok(out) => (matches!(out.status, Status::Ok), out.message),
            Err(e) => (false, e),
        },
        WorkflowCommand::IntegrityVerify { quick } => {
            match client::call::<IntegrityCommand, NyxOutput<IntegrityReport>>(
                INTEGRITY_SOCKET,
                &IntegrityCommand::Verify { quick: *quick },
            ) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnStatus => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(VPN_SOCKET, &VpnCommand::Status)
            {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnConnect { protocol, profile } => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(
                VPN_SOCKET,
                &VpnCommand::Connect { protocol: *protocol, profile: profile.clone() },
            ) {
                Ok(out) => (matches!(out.status, Status::Ok | Status::Warning), out.message),
                Err(e) => (false, e),
            }
        }
        WorkflowCommand::VpnDisconnect => {
            match client::call::<VpnCommand, NyxOutput<VpnReport>>(
                VPN_SOCKET,
                &VpnCommand::Disconnect,
            ) {
                Ok(out) => (matches!(out.status, Status::Ok), out.message),
                Err(e) => (false, e),
            }
        }
    }
}

/// Run every step of `workflow` in order. `Condition::IfSuccess`/
/// `IfFailure` gate on whether the immediately preceding step (that
/// actually ran) succeeded — a skipped step doesn't count as either.
pub fn run(workflow: &Workflow) -> WorkflowReport {
    let mut results = Vec::new();
    let mut last_ok = true;

    for step in &workflow.steps {
        let gate_satisfied = match step.condition {
            Condition::Always => true,
            Condition::IfSuccess => last_ok,
            Condition::IfFailure => !last_ok,
        };

        if !gate_satisfied {
            results.push(StepResult {
                description: step.description.to_string(),
                ran: false,
                ok: true,
                message: "skipped (condition not met)".to_string(),
            });
            continue;
        }

        if step.confirm {
            let prompt = format!("[{:?}] {} — proceed?", step.danger, step.description);
            if !ask_yes_no(&prompt) {
                results.push(StepResult {
                    description: step.description.to_string(),
                    ran: false,
                    ok: false,
                    message: "declined by operator".to_string(),
                });
                last_ok = false;
                continue;
            }
        }

        println!("-> {}", step.description);
        let (ok, message) = execute(&step.cmd);
        println!("   {}", message);
        if !ok {
            println!("   rollback guidance: {}", step.rollback_hint);
        }

        last_ok = ok;
        results.push(StepResult {
            description: step.description.to_string(),
            ran: true,
            ok,
            message,
        });
    }

    WorkflowReport {
        id: workflow.id.to_string(),
        results,
    }
}
