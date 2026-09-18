use crate::client;
use gtk::glib;
use gtk::prelude::*;
use nyx_core::{
    DevicesCommand, DevicesReport, HealthCommand, HealthState, IdentityCommand, IdentityReport,
    KillSwitchLevel, NyxOutput, SecurityState, TelemetryCommand, TelemetryReport, Toggle,
    VpnCommand, VpnProtocol, VpnReport,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;

type ApplyFn = Rc<dyn Fn(Result<NyxOutput<HealthState>, String>)>;
type VpnApplyFn = Rc<dyn Fn(Result<NyxOutput<VpnReport>, String>)>;
type IdentityApplyFn = Rc<dyn Fn(Result<NyxOutput<IdentityReport>, String>)>;
type DevicesApplyFn = Rc<dyn Fn(Result<NyxOutput<DevicesReport>, String>)>;
type TelemetryApplyFn = Rc<dyn Fn(Result<NyxOutput<TelemetryReport>, String>)>;

/// Human-readable byte size, `1.0` == 1024 of the previous unit.
fn format_bytes(bytes: f64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_kb(kb: u64) -> String {
    format_bytes(kb as f64 * 1024.0)
}

fn format_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(
        "
        .dot { min-width: 12px; min-height: 12px; border-radius: 6px; margin-right: 6px; }
        .dot-on { background-color: #2ecc71; }
        .dot-off { background-color: #e74c3c; }
        .dot-soft { background-color: #f1c40f; }
        .dot-medium { background-color: #e67e22; }
        .selected { font-weight: bold; }
        ",
    );
    gtk::style_context_add_provider_for_display(
        &gtk::gdk::Display::default().expect("no display"),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

const DOT_CLASSES: &[&str] = &["dot-off", "dot-soft", "dot-medium", "dot-on"];

fn status_row(label: &str) -> (gtk::Box, gtk::Box, gtk::Label) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    dot.add_css_class("dot");
    dot.add_css_class("dot-off");
    let text = gtk::Label::new(Some(&format!("{label}: unknown")));
    text.set_halign(gtk::Align::Start);
    row.append(&dot);
    row.append(&text);
    (row, dot, text)
}

fn section_heading(text: &str) -> gtk::Label {
    let label = gtk::Label::new(None);
    label.set_markup(&format!("<b>{text}</b>"));
    label.set_halign(gtk::Align::Start);
    label.set_margin_top(6);
    label
}

fn set_dot(dot: &gtk::Box, on: bool) {
    dot.remove_css_class(if on { "dot-off" } else { "dot-on" });
    dot.add_css_class(if on { "dot-on" } else { "dot-off" });
}

fn set_dot_classes(dot: &gtk::Box, class: &str) {
    for c in DOT_CLASSES {
        dot.remove_css_class(c);
    }
    dot.add_css_class(class);
}

/// Same on/off dot, but takes an `Option<bool>` — `None` (the check itself
/// failed, or nothing to report) shows the same as off rather than lying
/// with a default.
fn set_dot_opt(dot: &gtk::Box, on: Option<bool>) {
    set_dot(dot, on.unwrap_or(false));
}

/// Kill-switch levels get their own four-colour scale instead of the plain
/// on/off dot: Off=red, Soft=yellow, Medium=orange, Armed=green (green here
/// means "fully enforced", not "safe" — Armed is the most disruptive level).
fn set_level_dot(dot: &gtk::Box, level: KillSwitchLevel) {
    let class = match level {
        KillSwitchLevel::Off => "dot-off",
        KillSwitchLevel::Soft => "dot-soft",
        KillSwitchLevel::Medium => "dot-medium",
        KillSwitchLevel::Armed => "dot-on",
    };
    set_dot_classes(dot, class);
}

/// Same four-colour scale, driven by the daemon's own assessed
/// `SecurityState` rather than a raw connected/disconnected bit — a
/// connected-but-unverified VPN (or a running-but-misconfigured USBGuard)
/// shows as Degraded (orange), not Protected.
fn set_security_dot(dot: &gtk::Box, state: SecurityState) {
    let class = match state {
        SecurityState::Protected => "dot-on",
        SecurityState::Degraded => "dot-medium",
        SecurityState::Starting => "dot-soft",
        SecurityState::Unknown | SecurityState::Blocked | SecurityState::Emergency | SecurityState::Error => {
            "dot-off"
        }
    };
    set_dot_classes(dot, class);
}

fn level_label(level: KillSwitchLevel) -> &'static str {
    match level {
        KillSwitchLevel::Off => "Off",
        KillSwitchLevel::Soft => "Soft",
        KillSwitchLevel::Medium => "Medium",
        KillSwitchLevel::Armed => "Armed",
    }
}

fn on_off(state: Option<bool>) -> &'static str {
    match state {
        Some(true) => "on",
        Some(false) => "off",
        None => "unknown",
    }
}

/// Runs `cmd` on a background thread (the socket call is blocking I/O) and
/// applies the result back on the GTK main thread once it arrives. Shared
/// shape for every daemon socket the dashboard talks to.
fn run_on_background<C, R, F>(cmd: C, send: F, apply: Rc<dyn Fn(Result<R, String>)>)
where
    C: Send + 'static,
    R: Send + 'static,
    F: FnOnce(C) -> Result<R, String> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = send(cmd);
        let _ = tx.send(result);
    });

    glib::idle_add_local(move || match rx.try_recv() {
        Ok(result) => {
            apply(result);
            glib::ControlFlow::Break
        }
        Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
        Err(TryRecvError::Disconnected) => glib::ControlFlow::Break,
    });
}

fn run_command(cmd: HealthCommand, apply: ApplyFn) {
    run_on_background(cmd, client::send, apply);
}

fn run_vpn_command(cmd: VpnCommand, apply: VpnApplyFn) {
    run_on_background(cmd, client::send_vpn, apply);
}

fn run_identity_command(cmd: IdentityCommand, apply: IdentityApplyFn) {
    run_on_background(cmd, client::send_identity, apply);
}

fn run_devices_command(cmd: DevicesCommand, apply: DevicesApplyFn) {
    run_on_background(cmd, client::send_devices, apply);
}

fn run_telemetry_command(cmd: TelemetryCommand, apply: TelemetryApplyFn) {
    run_on_background(cmd, client::send_telemetry, apply);
}

pub fn build(app: &gtk::Application) {
    load_css();

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("NyxOS Control")
        .default_width(440)
        .default_height(640)
        .build();

    let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root.set_margin_top(16);
    root.set_margin_bottom(16);
    root.set_margin_start(16);
    root.set_margin_end(16);

    let heading = gtk::Label::new(None);
    heading.set_markup("<b>NyxOS Control</b>");
    heading.set_halign(gtk::Align::Start);
    root.append(&heading);

    // --- Network health: Tor, kill switch, panic --------------------------
    let (tor_row, tor_dot, tor_label) = status_row("Tor");
    let (ks_row, ks_dot, ks_label) = status_row("Kill Switch");
    let (panic_row, panic_dot, panic_label) = status_row("Panic Mode");
    root.append(&tor_row);
    root.append(&ks_row);
    root.append(&panic_row);

    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    let tor_btn = gtk::Button::with_label("Toggle Tor");
    root.append(&tor_btn);

    let ks_heading = gtk::Label::new(Some("Kill switch level"));
    ks_heading.set_halign(gtk::Align::Start);
    root.append(&ks_heading);

    let ks_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let ks_off_btn = gtk::Button::with_label("Off");
    let ks_soft_btn = gtk::Button::with_label("Soft");
    let ks_medium_btn = gtk::Button::with_label("Medium");
    let ks_armed_btn = gtk::Button::with_label("Armed");
    ks_buttons.append(&ks_off_btn);
    ks_buttons.append(&ks_soft_btn);
    ks_buttons.append(&ks_medium_btn);
    ks_buttons.append(&ks_armed_btn);
    root.append(&ks_buttons);

    let panic_btn = gtk::Button::with_label("PANIC — lock down network");
    panic_btn.add_css_class("destructive-action");
    root.append(&panic_btn);

    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- VPN -----------------------------------------------------------
    let (vpn_row, vpn_dot, vpn_label) = status_row("VPN");
    root.append(&vpn_row);

    let vpn_detail_label = gtk::Label::new(None);
    vpn_detail_label.set_wrap(true);
    vpn_detail_label.set_halign(gtk::Align::Start);
    root.append(&vpn_detail_label);

    let vpn_protocol_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vpn_wg_btn = gtk::Button::with_label("WireGuard");
    let vpn_ovpn_btn = gtk::Button::with_label("OpenVPN");
    vpn_wg_btn.add_css_class("selected");
    vpn_protocol_row.append(&vpn_wg_btn);
    vpn_protocol_row.append(&vpn_ovpn_btn);
    root.append(&vpn_protocol_row);

    let vpn_profile_entry = gtk::Entry::new();
    vpn_profile_entry.set_placeholder_text(Some("profile name (e.g. /etc/wireguard/<name>.conf)"));
    root.append(&vpn_profile_entry);

    let vpn_action_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vpn_connect_btn = gtk::Button::with_label("Connect");
    let vpn_disconnect_btn = gtk::Button::with_label("Disconnect");
    vpn_action_row.append(&vpn_connect_btn);
    vpn_action_row.append(&vpn_disconnect_btn);
    root.append(&vpn_action_row);

    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Identity --------------------------------------------------------
    root.append(&section_heading("Identity"));

    let hostname_label = gtk::Label::new(Some("Hostname: unknown"));
    hostname_label.set_halign(gtk::Align::Start);
    root.append(&hostname_label);
    let hostname_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let hostname_randomize_btn = gtk::Button::with_label("Randomize");
    let hostname_restore_btn = gtk::Button::with_label("Restore original");
    hostname_row.append(&hostname_randomize_btn);
    hostname_row.append(&hostname_restore_btn);
    root.append(&hostname_row);

    let timezone_label = gtk::Label::new(Some("Timezone: unknown"));
    timezone_label.set_halign(gtk::Align::Start);
    root.append(&timezone_label);
    let timezone_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let timezone_randomize_btn = gtk::Button::with_label("Randomize");
    let timezone_restore_btn = gtk::Button::with_label("Restore original");
    timezone_row.append(&timezone_randomize_btn);
    timezone_row.append(&timezone_restore_btn);
    root.append(&timezone_row);

    let mac_label = gtk::Label::new(Some("MAC: unknown"));
    mac_label.set_halign(gtk::Align::Start);
    root.append(&mac_label);
    let mac_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let mac_randomize_btn = gtk::Button::with_label("Randomize");
    let mac_restore_btn = gtk::Button::with_label("Restore permanent");
    mac_row.append(&mac_randomize_btn);
    mac_row.append(&mac_restore_btn);
    root.append(&mac_row);

    let (ipv6_row, ipv6_dot, ipv6_label) = status_row("IPv6");
    root.append(&ipv6_row);
    let ipv6_row_btns = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let ipv6_on_btn = gtk::Button::with_label("Enable");
    let ipv6_off_btn = gtk::Button::with_label("Disable");
    ipv6_row_btns.append(&ipv6_on_btn);
    ipv6_row_btns.append(&ipv6_off_btn);
    root.append(&ipv6_row_btns);

    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Devices -----------------------------------------------------------
    root.append(&section_heading("Devices"));

    let (wifi_row, wifi_dot, wifi_label) = status_row("WiFi");
    let (bt_row, bt_dot, bt_label) = status_row("Bluetooth");
    let (cam_row, cam_dot, cam_label) = status_row("Webcam");
    let (mic_row, mic_dot, mic_label) = status_row("Microphone");
    let (usbstor_row, usbstor_dot, usbstor_label) = status_row("USB Storage");
    let (usbguard_row, usbguard_dot, usbguard_label) = status_row("USBGuard");
    for row in [&wifi_row, &bt_row, &cam_row, &mic_row, &usbstor_row, &usbguard_row] {
        root.append(row);
    }

    let devices_detail_label = gtk::Label::new(None);
    devices_detail_label.set_wrap(true);
    devices_detail_label.set_halign(gtk::Align::Start);
    root.append(&devices_detail_label);

    let device_toggle_row = |on_label: &str, off_label: &str| {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let on_btn = gtk::Button::with_label(on_label);
        let off_btn = gtk::Button::with_label(off_label);
        row.append(&on_btn);
        row.append(&off_btn);
        (row, on_btn, off_btn)
    };

    let (wifi_btn_row, wifi_on_btn, wifi_off_btn) = device_toggle_row("On", "Off");
    let (bt_btn_row, bt_on_btn, bt_off_btn) = device_toggle_row("On", "Off");
    let (cam_btn_row, cam_on_btn, cam_off_btn) = device_toggle_row("On", "Off");
    let (mic_btn_row, mic_on_btn, mic_off_btn) = device_toggle_row("On", "Off");
    let (usbstor_btn_row, usbstor_on_btn, usbstor_off_btn) = device_toggle_row("On", "Off");
    let (usbguard_btn_row, usbguard_start_btn, usbguard_stop_btn) = device_toggle_row("Start", "Stop");
    for row in [&wifi_btn_row, &bt_btn_row, &cam_btn_row, &mic_btn_row, &usbstor_btn_row, &usbguard_btn_row] {
        root.append(row);
    }

    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Telemetry ---------------------------------------------------------
    root.append(&section_heading("Telemetry"));

    let cpu_label = gtk::Label::new(Some("CPU: unknown"));
    cpu_label.set_halign(gtk::Align::Start);
    root.append(&cpu_label);

    let mem_label = gtk::Label::new(Some("Memory: unknown"));
    mem_label.set_halign(gtk::Align::Start);
    root.append(&mem_label);

    let disk_label = gtk::Label::new(Some("Disk (/): unknown"));
    disk_label.set_halign(gtk::Align::Start);
    root.append(&disk_label);

    let net_label = gtk::Label::new(Some("Network: unknown"));
    net_label.set_halign(gtk::Align::Start);
    net_label.set_wrap(true);
    root.append(&net_label);

    let uptime_label = gtk::Label::new(Some("Uptime: unknown"));
    uptime_label.set_halign(gtk::Align::Start);
    root.append(&uptime_label);

    let status_label = gtk::Label::new(Some("connecting to nyx-health…"));
    status_label.set_wrap(true);
    status_label.set_halign(gtk::Align::Start);
    root.append(&status_label);

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&root));
    scroller.set_hscrollbar_policy(gtk::PolicyType::Never);
    window.set_child(Some(&scroller));
    window.present();

    let cached = Rc::new(RefCell::new(HealthState::default()));
    let vpn_protocol = Rc::new(Cell::new(VpnProtocol::WireGuard));
    // The interface Randomize/Restore MAC act on — the first one reported
    // by nyx-identity. A future revision could let the user pick among
    // several; most machines only have one to worry about.
    let mac_interface = Rc::new(RefCell::new(None::<String>));

    let apply: ApplyFn = {
        let cached = Rc::clone(&cached);
        Rc::new(move |result: Result<NyxOutput<HealthState>, String>| match result {
            Ok(out) => {
                if let Some(state) = out.data.clone() {
                    set_dot(&tor_dot, state.tor_active);
                    set_level_dot(&ks_dot, state.kill_switch_level);
                    set_dot(&panic_dot, state.panic_mode);
                    tor_label.set_label(&format!(
                        "Tor: {}",
                        if state.tor_active { "active" } else { "inactive" }
                    ));
                    let iface_note = state
                        .kill_switch_tunnel_iface
                        .as_deref()
                        .map(|i| format!(" (via {i})"))
                        .unwrap_or_default();
                    ks_label.set_label(&format!(
                        "Kill Switch: {}{}",
                        level_label(state.kill_switch_level),
                        iface_note
                    ));
                    panic_label.set_label(&format!(
                        "Panic Mode: {}",
                        if state.panic_mode { "LOCKED DOWN" } else { "clear" }
                    ));
                    *cached.borrow_mut() = state;
                }
                status_label.set_label(&out.message);
            }
            Err(e) => status_label.set_label(&format!("error: {e}")),
        })
    };

    let vpn_apply: VpnApplyFn = Rc::new(move |result: Result<NyxOutput<VpnReport>, String>| match result
    {
        Ok(out) => {
            if let Some(report) = out.data {
                set_security_dot(&vpn_dot, report.state);
                let label = match (&report.protocol, &report.profile) {
                    (Some(protocol), Some(profile)) => {
                        format!("VPN: {profile} ({protocol:?})")
                    }
                    _ => "VPN: disconnected".to_string(),
                };
                vpn_label.set_label(&label);
                vpn_detail_label.set_label(&report.detail);
            }
        }
        Err(e) => vpn_detail_label.set_label(&format!("error: {e}")),
    });

    let identity_apply: IdentityApplyFn = {
        let mac_interface = Rc::clone(&mac_interface);
        Rc::new(move |result: Result<NyxOutput<IdentityReport>, String>| match result {
            Ok(out) => {
                if let Some(report) = out.data {
                    hostname_label.set_label(&format!(
                        "Hostname: {}",
                        report.hostname.as_deref().unwrap_or("unknown")
                    ));
                    timezone_label.set_label(&format!(
                        "Timezone: {}",
                        report.timezone.as_deref().unwrap_or("unknown")
                    ));
                    set_dot_opt(&ipv6_dot, report.ipv6_enabled);
                    ipv6_label.set_label(&format!("IPv6: {}", on_off(report.ipv6_enabled)));

                    if let Some(first) = report.interfaces.first() {
                        *mac_interface.borrow_mut() = Some(first.interface.clone());
                        mac_label.set_label(&format!(
                            "MAC ({}): {}",
                            first.interface,
                            first.mac_address.as_deref().unwrap_or("unknown")
                        ));
                    } else {
                        mac_label.set_label("MAC: no interface found");
                    }
                }
            }
            Err(e) => hostname_label.set_label(&format!("error: {e}")),
        })
    };

    let devices_apply: DevicesApplyFn =
        Rc::new(move |result: Result<NyxOutput<DevicesReport>, String>| match result {
            Ok(out) => {
                if let Some(report) = out.data {
                    set_dot_opt(&wifi_dot, report.wifi_enabled);
                    wifi_label.set_label(&format!("WiFi: {}", on_off(report.wifi_enabled)));
                    set_dot_opt(&bt_dot, report.bluetooth_enabled);
                    bt_label.set_label(&format!("Bluetooth: {}", on_off(report.bluetooth_enabled)));
                    set_dot_opt(&cam_dot, report.webcam_enabled);
                    cam_label.set_label(&format!("Webcam: {}", on_off(report.webcam_enabled)));
                    set_dot_opt(&mic_dot, report.microphone_enabled);
                    mic_label.set_label(&format!("Microphone: {}", on_off(report.microphone_enabled)));
                    set_dot_opt(&usbstor_dot, report.usb_storage_enabled);
                    usbstor_label
                        .set_label(&format!("USB Storage: {}", on_off(report.usb_storage_enabled)));
                    set_security_dot(&usbguard_dot, report.state);
                    usbguard_label
                        .set_label(&format!("USBGuard: {}", on_off(report.usbguard_active)));
                    devices_detail_label.set_label(&report.detail);
                }
            }
            Err(e) => devices_detail_label.set_label(&format!("error: {e}")),
        });

    let telemetry_apply: TelemetryApplyFn =
        Rc::new(move |result: Result<NyxOutput<TelemetryReport>, String>| match result {
            Ok(out) => {
                if let Some(report) = out.data {
                    let cpu = &report.cpu;
                    let cpu_text = match cpu.usage_percent {
                        Some(p) => format!(
                            "CPU: {p:.1}% (load {:.2} {:.2} {:.2})",
                            cpu.load_average_1m, cpu.load_average_5m, cpu.load_average_15m
                        ),
                        None => format!(
                            "CPU: measuring… (load {:.2} {:.2} {:.2})",
                            cpu.load_average_1m, cpu.load_average_5m, cpu.load_average_15m
                        ),
                    };
                    cpu_label.set_label(&cpu_text);

                    mem_label.set_label(&format!(
                        "Memory: {} / {}",
                        format_kb(report.memory.used_kb),
                        format_kb(report.memory.total_kb)
                    ));

                    match report.disks.iter().find(|d| d.mountpoint == "/") {
                        Some(root_disk) => disk_label.set_label(&format!(
                            "Disk (/): {} / {}",
                            format_bytes(root_disk.used_bytes as f64),
                            format_bytes(root_disk.total_bytes as f64)
                        )),
                        None => disk_label.set_label("Disk (/): not found"),
                    }

                    let net_summary = report
                        .network
                        .iter()
                        .filter(|n| n.interface != "lo")
                        .map(|n| {
                            let rx = n.rx_bytes_per_sec.map(format_rate).unwrap_or_else(|| "…".to_string());
                            let tx = n.tx_bytes_per_sec.map(format_rate).unwrap_or_else(|| "…".to_string());
                            format!("{}: ↓{rx} ↑{tx}", n.interface)
                        })
                        .collect::<Vec<_>>()
                        .join("  ");
                    net_label.set_label(&format!(
                        "Network: {}",
                        if net_summary.is_empty() { "no interfaces".to_string() } else { net_summary }
                    ));

                    let hours = report.uptime_secs / 3600;
                    let minutes = (report.uptime_secs % 3600) / 60;
                    uptime_label.set_label(&format!(
                        "Uptime: {hours}h {minutes}m — {} processes",
                        report.process_count
                    ));
                }
            }
            Err(e) => cpu_label.set_label(&format!("error: {e}")),
        });

    run_command(HealthCommand::Status, Rc::clone(&apply));
    run_vpn_command(VpnCommand::Status, Rc::clone(&vpn_apply));
    run_identity_command(IdentityCommand::Status, Rc::clone(&identity_apply));
    run_devices_command(DevicesCommand::Status, Rc::clone(&devices_apply));
    run_telemetry_command(TelemetryCommand::Status, Rc::clone(&telemetry_apply));

    {
        let apply = Rc::clone(&apply);
        let vpn_apply = Rc::clone(&vpn_apply);
        let identity_apply = Rc::clone(&identity_apply);
        let devices_apply = Rc::clone(&devices_apply);
        let telemetry_apply = Rc::clone(&telemetry_apply);
        glib::timeout_add_seconds_local(5, move || {
            run_command(HealthCommand::Status, Rc::clone(&apply));
            run_vpn_command(VpnCommand::Status, Rc::clone(&vpn_apply));
            run_identity_command(IdentityCommand::Status, Rc::clone(&identity_apply));
            run_devices_command(DevicesCommand::Status, Rc::clone(&devices_apply));
            run_telemetry_command(TelemetryCommand::Status, Rc::clone(&telemetry_apply));
            glib::ControlFlow::Continue
        });
    }

    tor_btn.connect_clicked({
        let cached = Rc::clone(&cached);
        let apply = Rc::clone(&apply);
        move |_| {
            let action = if cached.borrow().tor_active { Toggle::Off } else { Toggle::On };
            run_command(HealthCommand::Tor { action }, Rc::clone(&apply));
        }
    });

    for (button, level) in [
        (&ks_off_btn, KillSwitchLevel::Off),
        (&ks_soft_btn, KillSwitchLevel::Soft),
        (&ks_medium_btn, KillSwitchLevel::Medium),
        (&ks_armed_btn, KillSwitchLevel::Armed),
    ] {
        button.connect_clicked({
            let apply = Rc::clone(&apply);
            move |_| {
                run_command(HealthCommand::KillSwitch { level }, Rc::clone(&apply));
            }
        });
    }

    panic_btn.connect_clicked({
        let apply = Rc::clone(&apply);
        let window = window.clone();
        move |_| {
            let confirm = gtk::AlertDialog::builder()
                .modal(true)
                .message("Lock down the network?")
                .detail(
                    "This drops all traffic except loopback and stops Tor. \
                     Only restarting nyx-health clears it.",
                )
                .buttons(["Cancel", "Panic"])
                .cancel_button(0)
                .default_button(0)
                .build();

            let apply = Rc::clone(&apply);
            confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                if response == Ok(1) {
                    run_command(HealthCommand::Panic, Rc::clone(&apply));
                }
            });
        }
    });

    vpn_wg_btn.connect_clicked({
        let vpn_protocol = Rc::clone(&vpn_protocol);
        let vpn_wg_btn = vpn_wg_btn.clone();
        let vpn_ovpn_btn = vpn_ovpn_btn.clone();
        move |_| {
            vpn_protocol.set(VpnProtocol::WireGuard);
            vpn_wg_btn.add_css_class("selected");
            vpn_ovpn_btn.remove_css_class("selected");
        }
    });

    vpn_ovpn_btn.connect_clicked({
        let vpn_protocol = Rc::clone(&vpn_protocol);
        let vpn_wg_btn = vpn_wg_btn.clone();
        let vpn_ovpn_btn = vpn_ovpn_btn.clone();
        move |_| {
            vpn_protocol.set(VpnProtocol::OpenVpn);
            vpn_ovpn_btn.add_css_class("selected");
            vpn_wg_btn.remove_css_class("selected");
        }
    });

    vpn_connect_btn.connect_clicked({
        let vpn_apply = Rc::clone(&vpn_apply);
        let vpn_protocol = Rc::clone(&vpn_protocol);
        let vpn_profile_entry = vpn_profile_entry.clone();
        move |_| {
            let profile = vpn_profile_entry.text().to_string();
            if profile.trim().is_empty() {
                return;
            }
            run_vpn_command(
                VpnCommand::Connect { protocol: vpn_protocol.get(), profile },
                Rc::clone(&vpn_apply),
            );
        }
    });

    vpn_disconnect_btn.connect_clicked({
        let vpn_apply = Rc::clone(&vpn_apply);
        move |_| {
            run_vpn_command(VpnCommand::Disconnect, Rc::clone(&vpn_apply));
        }
    });

    hostname_randomize_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| run_identity_command(IdentityCommand::RandomizeHostname, Rc::clone(&identity_apply))
    });
    hostname_restore_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| run_identity_command(IdentityCommand::RestoreHostname, Rc::clone(&identity_apply))
    });
    timezone_randomize_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| run_identity_command(IdentityCommand::RandomizeTimezone, Rc::clone(&identity_apply))
    });
    timezone_restore_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| run_identity_command(IdentityCommand::RestoreTimezone, Rc::clone(&identity_apply))
    });
    mac_randomize_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        let mac_interface = Rc::clone(&mac_interface);
        move |_| {
            if let Some(interface) = mac_interface.borrow().clone() {
                run_identity_command(
                    IdentityCommand::RandomizeMac { interface },
                    Rc::clone(&identity_apply),
                );
            }
        }
    });
    mac_restore_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        let mac_interface = Rc::clone(&mac_interface);
        move |_| {
            if let Some(interface) = mac_interface.borrow().clone() {
                run_identity_command(
                    IdentityCommand::RestoreMac { interface },
                    Rc::clone(&identity_apply),
                );
            }
        }
    });
    ipv6_on_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| {
            run_identity_command(IdentityCommand::SetIpv6 { enabled: true }, Rc::clone(&identity_apply))
        }
    });
    ipv6_off_btn.connect_clicked({
        let identity_apply = Rc::clone(&identity_apply);
        move |_| {
            run_identity_command(IdentityCommand::SetIpv6 { enabled: false }, Rc::clone(&identity_apply))
        }
    });

    wifi_on_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetRadio { radio: nyx_core::DeviceRadio::Wifi, on: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    wifi_off_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetRadio { radio: nyx_core::DeviceRadio::Wifi, on: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    bt_on_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetRadio { radio: nyx_core::DeviceRadio::Bluetooth, on: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    bt_off_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetRadio { radio: nyx_core::DeviceRadio::Bluetooth, on: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    cam_on_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetModule { module: nyx_core::DeviceModule::Webcam, enabled: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    cam_off_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetModule { module: nyx_core::DeviceModule::Webcam, enabled: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    mic_on_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetMicrophone { enabled: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    mic_off_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetMicrophone { enabled: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbstor_on_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetModule { module: nyx_core::DeviceModule::UsbStorage, enabled: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbstor_off_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetModule { module: nyx_core::DeviceModule::UsbStorage, enabled: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbguard_start_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetUsbGuard { enabled: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbguard_stop_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(
                DevicesCommand::SetUsbGuard { enabled: false },
                Rc::clone(&devices_apply),
            )
        }
    });
}
