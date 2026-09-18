use crate::client;
use crate::diagnostics::{self, DefaultRoute, PublicIpResult};
use crate::schedule;
use crate::workflow;
use gtk::gio::prelude::*;
use gtk::glib;
use gtk::prelude::*;
use nyx_core::protocol::{FreeProvider, TemplateProvider};
use nyx_core::{
    CloakConfig, DevicesCommand, DevicesReport, DnsCommand, DnsProvider, DnsReport, HealthCommand,
    HealthState, IdentityCommand, IdentityReport, IntegrityCommand, IntegrityReport, KillSwitchLevel,
    NyxOutput, SecurityState, SocksProxyAddr, TelemetryCommand, TelemetryReport, Toggle,
    VpnCommand, VpnProtocol, VpnReport,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;

type ApplyFn = Rc<dyn Fn(Result<NyxOutput<HealthState>, String>)>;
type VpnApplyFn = Rc<dyn Fn(Result<NyxOutput<VpnReport>, String>)>;
type IdentityApplyFn = Rc<dyn Fn(Result<NyxOutput<IdentityReport>, String>)>;
type DevicesApplyFn = Rc<dyn Fn(Result<NyxOutput<DevicesReport>, String>)>;
type TelemetryApplyFn = Rc<dyn Fn(Result<NyxOutput<TelemetryReport>, String>)>;
type DnsApplyFn = Rc<dyn Fn(Result<NyxOutput<DnsReport>, String>)>;
type IntegrityApplyFn = Rc<dyn Fn(Result<NyxOutput<IntegrityReport>, String>)>;
type DefaultRouteApplyFn = Rc<dyn Fn(Result<DefaultRoute, String>)>;
type PublicIpApplyFn = Rc<dyn Fn(Result<PublicIpResult, String>)>;
type PostureListApplyFn = Rc<dyn Fn(Result<Vec<workflow::WorkflowListEntry>, String>)>;
type PostureApplyFn = Rc<dyn Fn(Result<workflow::WorkflowReport, String>)>;
type ScheduleStatusApplyFn = Rc<dyn Fn(Result<Vec<schedule::TaskStatus>, String>)>;
type ScheduleActionResults = Vec<(String, Result<String, String>)>;
type ScheduleActionsApplyFn = Rc<dyn Fn(Result<ScheduleActionResults, String>)>;

/// Every VPN backend `nyx-vpn` actually implements (see
/// `nyx_core::protocol::VpnProtocol`), in the order the Network tab's
/// protocol dropdown lists them.
const VPN_PROTOCOLS: &[(VpnProtocol, &str)] = &[
    (VpnProtocol::WireGuard, "WireGuard"),
    (VpnProtocol::OpenVpn, "OpenVPN"),
    (VpnProtocol::AmneziaWg, "AmneziaWG"),
    (VpnProtocol::Xray, "Xray"),
    (VpnProtocol::Shadowsocks, "Shadowsocks"),
    (VpnProtocol::Hysteria2, "Hysteria2"),
    (VpnProtocol::Socks5, "SOCKS5"),
    (VpnProtocol::Mieru, "mieru"),
];

/// Tor's SocksPort only carries TCP, so only the three backends that dial
/// their own upstream connection over an ordinary TCP SOCKS proxy can be
/// chained through it — see `nyx_core::VpnCommand::ConnectViaSocksProxy`'s
/// doc comment for exactly why WireGuard/AmneziaWG (UDP in-kernel tunnels),
/// Hysteria2 (QUIC/UDP), and SOCKS5 (single upstream-proxy slot, no
/// chaining flag) are rejected outright by nyx-vpn itself, not just hidden
/// here.
fn protocol_supports_tor_chaining(protocol: VpnProtocol) -> bool {
    matches!(
        protocol,
        VpnProtocol::OpenVpn | VpnProtocol::Xray | VpnProtocol::Shadowsocks | VpnProtocol::Mieru
    )
}

/// Each backend's real, on-disk profile directory — see the `PROFILE_DIR`
/// constant in the matching `nyx-vpn` backend module. These are root-only
/// directories the dashboard cannot read directly (confirmed on this very
/// sandbox); the only honest way to show them is quoting the real path
/// and, for browsing, going through `nyx-vpn`'s own `VpnCommand::List` or a
/// root-privileged file manager.
fn profile_dir(protocol: VpnProtocol) -> &'static str {
    match protocol {
        VpnProtocol::WireGuard => "/etc/wireguard",
        VpnProtocol::OpenVpn => "/etc/openvpn/client",
        VpnProtocol::AmneziaWg => "/etc/amnezia/amneziawg",
        VpnProtocol::Xray => "/etc/nyx/xray",
        VpnProtocol::Shadowsocks => "/etc/shadowsocks-rust",
        VpnProtocol::Hysteria2 => "/etc/nyx/hysteria",
        VpnProtocol::Socks5 => "/etc/nyx/socks5",
        VpnProtocol::Mieru => "/etc/nyx/mieru",
    }
}

/// The two curated, genuinely free public VPN directories `nyx-vpn`'s
/// `FetchFreeProvider` knows how to fetch from (see
/// `nyx_core::protocol::FreeProvider`), in the order the Fetch Free
/// Provider dropdown lists them.
const FREE_PROVIDERS: &[(FreeProvider, &str)] = &[
    (FreeProvider::VpnGate, "VPN Gate"),
    (FreeProvider::Riseup, "Riseup"),
];

/// Only `FreeProvider::VpnGate`'s relay choice can be narrowed by country —
/// `Riseup` has no country selection of its own, per
/// `VpnCommand::FetchFreeProvider`'s own doc comment.
fn free_provider_supports_country(provider: FreeProvider) -> bool {
    matches!(provider, FreeProvider::VpnGate)
}

/// The three commercial providers `nyx-vpn`'s `WriteProviderTemplate` can
/// write a config skeleton for (see `nyx_core::protocol::TemplateProvider`),
/// in the order the Write Provider Template dropdown lists them.
const TEMPLATE_PROVIDERS: &[(TemplateProvider, &str)] = &[
    (TemplateProvider::Mullvad, "Mullvad"),
    (TemplateProvider::ProtonVpn, "ProtonVPN"),
    (TemplateProvider::NordVpn, "NordVPN"),
];

/// Real encryption methods `cbeuw/Cloak` accepts. `"plain"` is deliberately
/// left off this list — `nyx-vpn` itself always rejects it when wrapping
/// OpenVPN (see `CloakConfig::encryption_method`'s doc comment), so
/// offering it here would just be an option guaranteed to fail.
const CLOAK_ENCRYPTION_METHODS: &[&str] = &["aes-256-gcm", "aes-128-gcm", "chacha20-poly1305"];

struct PeriodicTask {
    id: &'static str,
    label: &'static str,
    dangerous: bool,
    needs_interface: bool,
}

/// The 12 task ids from `nyx-hardening`'s `ScheduleTask::ALL` (see
/// `core/crates/nyx-hardening/src/schedule/mod.rs`). Labels/dangerous-flag
/// are hardcoded here rather than fetched from the CLI because
/// `TaskStatus` (the JSON `schedule status` actually returns) carries only
/// `task`/`scope`/`installed`/`enabled`/`interval_secs` — no human
/// description field to reuse.
const PERIODIC_TASKS: &[PeriodicTask] = &[
    PeriodicTask { id: "wipe-shell-history", label: "Wipe shell history", dangerous: false, needs_interface: false },
    PeriodicTask { id: "wipe-tmp", label: "Wipe /tmp", dangerous: false, needs_interface: false },
    PeriodicTask {
        id: "wipe-thumbnails",
        label: "Wipe thumbnail cache",
        dangerous: false,
        needs_interface: false,
    },
    PeriodicTask {
        id: "wipe-recent-files",
        label: "Wipe recent-files lists",
        dangerous: false,
        needs_interface: false,
    },
    PeriodicTask { id: "wipe-logs", label: "Wipe/vacuum logs", dangerous: false, needs_interface: false },
    PeriodicTask {
        id: "wipe-free-space",
        label: "Wipe free disk space (sfill) — slow, can take hours",
        dangerous: true,
        needs_interface: false,
    },
    PeriodicTask {
        id: "shred-documents",
        label: "Shred every user's Documents folder — irreversible",
        dangerous: true,
        needs_interface: false,
    },
    PeriodicTask {
        id: "shred-downloads",
        label: "Shred every user's Downloads folder — irreversible",
        dangerous: true,
        needs_interface: false,
    },
    PeriodicTask {
        id: "shred-desktop",
        label: "Shred every user's Desktop folder — irreversible",
        dangerous: true,
        needs_interface: false,
    },
    PeriodicTask {
        id: "randomize-mac",
        label: "Randomize MAC address",
        dangerous: false,
        needs_interface: true,
    },
    PeriodicTask { id: "lock-screen", label: "Lock screen", dangerous: false, needs_interface: false },
    PeriodicTask {
        id: "renew-tor-circuit",
        label: "Renew Tor circuit",
        dangerous: false,
        needs_interface: false,
    },
];

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
        .hint { font-size: 90%; color: #888888; }
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

/// Vertical box with the same margins every tab's root content box uses,
/// so switching a section between tabs never has to think about spacing.
fn new_tab_box() -> gtk::Box {
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 10);
    box_.set_margin_top(16);
    box_.set_margin_bottom(16);
    box_.set_margin_start(16);
    box_.set_margin_end(16);
    box_
}

/// Wraps a tab's content box in its own scroller — each tab scrolls
/// independently rather than the whole notebook, which matters once a
/// long tab (Devices, Hardening) and a short one (Browsers) share the same
/// window height.
fn wrap_scrolled(content: &gtk::Box) -> gtk::ScrolledWindow {
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(content));
    scroller.set_hscrollbar_policy(gtk::PolicyType::Never);
    scroller.set_vexpand(true);
    scroller
}

fn append_tab(notebook: &gtk::Notebook, title: &str, content: &gtk::Box) {
    let scroller = wrap_scrolled(content);
    notebook.append_page(&scroller, Some(&gtk::Label::new(Some(title))));
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

fn run_dns_command(cmd: DnsCommand, apply: DnsApplyFn) {
    run_on_background(cmd, client::send_dns, apply);
}

fn run_integrity_command(cmd: IntegrityCommand, apply: IntegrityApplyFn) {
    run_on_background(cmd, client::send_integrity, apply);
}

/// Unprivileged, purely local (`ip route show`) — safe to refresh on the
/// same timer as the rest of the dashboard, unlike the public-IP check.
fn run_default_route_command(apply: DefaultRouteApplyFn) {
    run_on_background((), |_| diagnostics::fetch_default_route(), apply);
}

/// Sends exactly one outbound request to an external service — only ever
/// called from the "Check Public IP" button handler, never from the
/// periodic refresh timer.
fn run_public_ip_command(apply: PublicIpApplyFn) {
    run_on_background((), |_| diagnostics::fetch_public_ip(), apply);
}

/// Fetches the three posture ids/descriptions once, when the Hardening tab
/// is built — not on the periodic refresh timer, since this text is static
/// for the lifetime of the running `nyx-workflow` binary.
fn run_posture_list_command(apply: PostureListApplyFn) {
    run_on_background((), |_| workflow::fetch_postures(), apply);
}

/// Runs `nyx-workflow posture --level <level> --apply --json` in the
/// background — only from the Hardening tab's "Apply" button, after the
/// operator has confirmed the posture they picked.
fn run_posture_apply_command(level: String, apply: PostureApplyFn) {
    run_on_background((), move |()| workflow::apply_posture(&level), apply);
}

/// Runs `pkexec nyx-hardening schedule status` in the background — once
/// when the Periodic Tasks tab is built, and again after every
/// install/remove batch to reflect the real on-disk result. Every call
/// pops its own polkit prompt, per `schedule.rs`'s module doc: unlike
/// `nyx-workflow`, `nyx-hardening` refuses to run at all as non-root, so
/// even this read needs `pkexec`.
fn run_schedule_status_command(apply: ScheduleStatusApplyFn) {
    run_on_background((), |_| schedule::status(), apply);
}

/// Runs a batch of `pkexec nyx-hardening schedule install|remove` calls in
/// the background, one per checked/unchecked task — only from the
/// Periodic Tasks tab's "Activate Timer" button, after any dangerous-task
/// confirmation has been accepted.
fn run_schedule_actions_command(actions: Vec<schedule::ScheduleAction>, apply: ScheduleActionsApplyFn) {
    run_on_background(actions, |actions| Ok(schedule::run_actions(actions)), apply);
}

/// Spawns one of the four `nyx-browsers` launcher binaries detached —
/// never `.wait()`s on it. Each launcher manages its own lifetime
/// (including, for the disposable one, securely erasing its own profile on
/// exit) with no dashboard involvement, so the dashboard's only job is to
/// start it and immediately let go.
fn spawn_browser(binary: &str) -> Result<(), String> {
    std::process::Command::new(binary).spawn().map(|_child| ()).map_err(|e| format!("{binary}: {e}"))
}

/// Opens a VPN backend's real, root-only profile directory in a
/// root-privileged file manager window via `pkexec` + the desktop's own
/// `xdg-open` — the same `pkexec env DISPLAY=... XAUTHORITY=...` shape
/// `install/thunar/nyx-thunar-root.sh`'s "NyxOS Open As Root" action
/// already uses elsewhere in this project. Spawned detached, never
/// `.wait()`ed on, exactly like `spawn_browser` above: the dashboard's job
/// is to start it and let go, not to babysit a file manager window.
fn spawn_show_config_dir(dir: &str) -> Result<(), String> {
    let display = std::env::var("DISPLAY").unwrap_or_default();
    let xauthority = std::env::var("XAUTHORITY").unwrap_or_else(|_| {
        format!("{}/.Xauthority", std::env::var("HOME").unwrap_or_default())
    });
    std::process::Command::new("pkexec")
        .arg("env")
        .arg(format!("DISPLAY={display}"))
        .arg(format!("XAUTHORITY={xauthority}"))
        .arg("xdg-open")
        .arg(dir)
        .spawn()
        .map(|_child| ())
        .map_err(|e| format!("{dir}: {e}"))
}

pub fn build(app: &gtk::Application) {
    load_css();

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("NyxOS Control")
        .default_width(480)
        .default_height(680)
        .build();

    let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root.set_margin_top(16);
    root.set_margin_bottom(6);
    root.set_margin_start(16);
    root.set_margin_end(16);

    let heading = gtk::Label::new(None);
    heading.set_markup("<b>NyxOS Control</b>");
    heading.set_halign(gtk::Align::Start);
    root.append(&heading);

    // A compact, always-visible status strip — unlike every value below,
    // which is buried inside whichever tab owns it, these four read only
    // from calls the tabs beneath them already make on the same 5s timer
    // (see the timer closure further down): no second socket/subprocess
    // call is issued just for this header.
    let header_grid = gtk::Grid::new();
    header_grid.set_column_spacing(18);
    header_grid.set_row_spacing(2);
    header_grid.set_margin_top(4);
    header_grid.set_margin_bottom(4);

    let (header_vpn_row, header_vpn_dot, header_vpn_label) = status_row("VPN");
    let (header_tor_row, header_tor_dot, header_tor_label) = status_row("Tor");
    let (header_dns_row, header_dns_dot, header_dns_label) = status_row("DNS");
    let header_route_label = gtk::Label::new(Some("Route: unknown"));
    header_route_label.set_halign(gtk::Align::Start);

    header_grid.attach(&header_vpn_row, 0, 0, 1, 1);
    header_grid.attach(&header_tor_row, 1, 0, 1, 1);
    header_grid.attach(&header_route_label, 2, 0, 1, 1);
    header_grid.attach(&header_dns_row, 3, 0, 1, 1);
    root.append(&header_grid);
    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    let notebook = gtk::Notebook::new();
    notebook.set_vexpand(true);
    root.append(&notebook);

    let status_label = gtk::Label::new(Some("connecting to nyx-health…"));
    status_label.set_wrap(true);
    status_label.set_halign(gtk::Align::Start);
    status_label.set_margin_top(6);
    root.append(&status_label);

    window.set_child(Some(&root));
    window.present();

    // =======================================================================
    // Network tab: Tor, VPN (all backends + Connect-via-Tor), Connection Info
    // =======================================================================
    let network_tab = new_tab_box();

    let (tor_row, tor_dot, tor_label) = status_row("Tor");
    network_tab.append(&tor_row);
    let tor_action_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let tor_btn = gtk::Button::with_label("Toggle Tor");
    // Renewing a circuit only means something once Tor is actually up —
    // disabled here and re-enabled/disabled in `apply` below as
    // `HealthState.tor_active` changes, same low-risk/reversible category
    // as the "lock screen" periodic task, so no confirmation dialog.
    let tor_renew_btn = gtk::Button::with_label("Renew Tor Circuit");
    tor_renew_btn.set_sensitive(false);
    tor_action_row.append(&tor_btn);
    tor_action_row.append(&tor_renew_btn);
    network_tab.append(&tor_action_row);

    let tor_renew_status_label = gtk::Label::new(None);
    tor_renew_status_label.set_wrap(true);
    tor_renew_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&tor_renew_status_label);

    network_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    network_tab.append(&section_heading("VPN"));

    let (vpn_row, vpn_dot, vpn_label) = status_row("VPN");
    network_tab.append(&vpn_row);

    let vpn_detail_label = gtk::Label::new(None);
    vpn_detail_label.set_wrap(true);
    vpn_detail_label.set_halign(gtk::Align::Start);
    network_tab.append(&vpn_detail_label);

    let protocol_labels: Vec<&str> = VPN_PROTOCOLS.iter().map(|(_, label)| *label).collect();
    let vpn_protocol_dropdown = gtk::DropDown::from_strings(&protocol_labels);
    vpn_protocol_dropdown.set_selected(0);
    network_tab.append(&vpn_protocol_dropdown);

    let vpn_profile_dropdown = gtk::DropDown::from_strings(&[]);
    network_tab.append(&vpn_profile_dropdown);

    let vpn_profile_empty_label = gtk::Label::new(Some("loading profiles…"));
    vpn_profile_empty_label.set_wrap(true);
    vpn_profile_empty_label.set_halign(gtk::Align::Start);
    vpn_profile_empty_label.set_visible(false);
    network_tab.append(&vpn_profile_empty_label);

    let vpn_profile_dir_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vpn_show_config_dir_btn = gtk::Button::with_label("Show config directory");
    vpn_profile_dir_row.append(&vpn_show_config_dir_btn);
    network_tab.append(&vpn_profile_dir_row);

    let vpn_profile_status_label = gtk::Label::new(None);
    vpn_profile_status_label.set_wrap(true);
    vpn_profile_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&vpn_profile_status_label);

    // Real profile names (plus each one's `incomplete` flag) for whichever
    // protocol is currently selected, in the same order as
    // `vpn_profile_dropdown`'s model — `VpnCommand::List` is the only
    // source of truth here; the dashboard never guesses a name or reads
    // `/etc/wireguard` (or any other backend's profile dir) itself, since
    // these are root-only directories it cannot see into.
    let vpn_profiles_state: Rc<RefCell<Vec<(String, bool)>>> = Rc::new(RefCell::new(Vec::new()));

    fn refresh_vpn_profiles(
        protocol: VpnProtocol,
        protocol_label: &'static str,
        dropdown: gtk::DropDown,
        empty_label: gtk::Label,
        profiles_state: Rc<RefCell<Vec<(String, bool)>>>,
    ) {
        let apply: VpnApplyFn = Rc::new(move |result| match result {
            Ok(out) => {
                let entries: Vec<(String, bool)> = out
                    .data
                    .map(|report| {
                        report
                            .profiles
                            .into_iter()
                            .filter(|p| p.protocol == protocol)
                            .map(|p| (p.name, p.incomplete))
                            .collect()
                    })
                    .unwrap_or_default();
                if entries.is_empty() {
                    dropdown.set_model(gtk::gio::ListModel::NONE);
                    dropdown.set_visible(false);
                    empty_label.set_label(&format!(
                        "no profiles found for {protocol_label} — add one at {}",
                        profile_dir(protocol)
                    ));
                    empty_label.set_visible(true);
                } else {
                    // A profile still carrying an unfilled `WriteProviderTemplate`
                    // placeholder gets a visible marker in its own dropdown
                    // entry, so picking it isn't a silent trap — see the
                    // `incomplete` check in `vpn_connect_btn`'s handler below.
                    let labels: Vec<String> = entries
                        .iter()
                        .map(|(name, incomplete)| {
                            if *incomplete {
                                format!("{name} (incomplete — needs your own credentials)")
                            } else {
                                name.clone()
                            }
                        })
                        .collect();
                    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                    dropdown.set_model(Some(&gtk::StringList::new(&refs)));
                    dropdown.set_selected(0);
                    dropdown.set_visible(true);
                    empty_label.set_visible(false);
                }
                *profiles_state.borrow_mut() = entries;
            }
            Err(e) => {
                dropdown.set_model(gtk::gio::ListModel::NONE);
                dropdown.set_visible(false);
                empty_label.set_label(&format!("could not list {protocol_label} profiles: {e}"));
                empty_label.set_visible(true);
            }
        });
        run_vpn_command(VpnCommand::List, apply);
    }

    refresh_vpn_profiles(
        VPN_PROTOCOLS[0].0,
        VPN_PROTOCOLS[0].1,
        vpn_profile_dropdown.clone(),
        vpn_profile_empty_label.clone(),
        Rc::clone(&vpn_profiles_state),
    );

    vpn_show_config_dir_btn.connect_clicked({
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        let vpn_profile_status_label = vpn_profile_status_label.clone();
        move |_| {
            let selected = vpn_protocol_dropdown.selected() as usize;
            let Some((protocol, _)) = VPN_PROTOCOLS.get(selected).copied() else {
                return;
            };
            let dir = profile_dir(protocol);
            match spawn_show_config_dir(dir) {
                Ok(()) => vpn_profile_status_label.set_label(&format!("Opening {dir} as root…")),
                Err(e) => vpn_profile_status_label.set_label(&format!("Failed to open {dir}: {e}")),
            }
        }
    });

    let connect_via_tor_check = gtk::CheckButton::with_label("Connect via Tor (SOCKS 127.0.0.1:9050)");
    connect_via_tor_check.set_sensitive(protocol_supports_tor_chaining(VPN_PROTOCOLS[0].0));
    connect_via_tor_check.set_tooltip_text(Some(
        "VPN-over-Tor chaining. Only available for OpenVPN, Xray, and Shadowsocks — Tor's SOCKS \
         proxy is TCP-only, so WireGuard/AmneziaWG (UDP tunnels), Hysteria2 (QUIC/UDP), and SOCKS5 \
         (no chaining slot) can't be routed through it.",
    ));
    network_tab.append(&connect_via_tor_check);

    // --- OpenVPN-over-Cloak (censorship circumvention) ------------------
    // A secondary, collapsible section rather than always-visible fields:
    // `CloakConfig` has six real inputs, and the common case (a plain
    // OpenVPN connect) needs none of them — see
    // `nyx_core::protocol::CloakConfig` for the verified field set this
    // mirrors exactly. Only ever relevant for OpenVPN, so it's hidden
    // outright for every other protocol, the same way `connect_via_tor_check`
    // is merely disabled (not hidden) since Tor-chaining is meaningful for
    // more than one protocol but Cloak is meaningful for exactly one.
    let cloak_expander = gtk::Expander::new(Some("OpenVPN-over-Cloak (censorship circumvention)"));
    cloak_expander.set_tooltip_text(Some(
        "Wraps this OpenVPN connection in cbeuw/Cloak's obfuscation layer, disguising it as \
         ordinary HTTPS to the server name below. Requires a Cloak server you already have \
         real credentials for.",
    ));
    let cloak_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    cloak_box.set_margin_top(6);
    cloak_box.set_margin_start(12);

    let cloak_remote_host_entry = gtk::Entry::new();
    cloak_remote_host_entry.set_placeholder_text(Some("remote host (same host the OpenVPN profile's 'remote' points at)"));
    cloak_box.append(&cloak_remote_host_entry);

    let cloak_remote_port_entry = gtk::Entry::new();
    cloak_remote_port_entry.set_placeholder_text(Some("remote port"));
    cloak_box.append(&cloak_remote_port_entry);

    let cloak_public_key_entry = gtk::Entry::new();
    cloak_public_key_entry.set_placeholder_text(Some("public key (base64, issued by the Cloak server operator)"));
    cloak_box.append(&cloak_public_key_entry);

    let cloak_uid_entry = gtk::Entry::new();
    cloak_uid_entry.set_placeholder_text(Some("UID (base64, issued by the Cloak server operator)"));
    cloak_box.append(&cloak_uid_entry);

    let cloak_server_name_entry = gtk::Entry::new();
    cloak_server_name_entry.set_placeholder_text(Some("server name to present via SNI/Host, e.g. www.bing.com"));
    cloak_box.append(&cloak_server_name_entry);

    let cloak_encryption_labels: Vec<&str> = CLOAK_ENCRYPTION_METHODS.to_vec();
    let cloak_encryption_dropdown = gtk::DropDown::from_strings(&cloak_encryption_labels);
    cloak_encryption_dropdown.set_selected(0);
    cloak_box.append(&cloak_encryption_dropdown);

    let cloak_num_conn_entry = gtk::Entry::new();
    cloak_num_conn_entry.set_placeholder_text(Some("number of connections (optional, default 4)"));
    cloak_box.append(&cloak_num_conn_entry);

    let cloak_browser_sig_entry = gtk::Entry::new();
    cloak_browser_sig_entry.set_placeholder_text(Some("TLS fingerprint to mimic (optional, default \"chrome\")"));
    cloak_box.append(&cloak_browser_sig_entry);

    let cloak_status_label = gtk::Label::new(None);
    cloak_status_label.set_wrap(true);
    cloak_status_label.set_halign(gtk::Align::Start);
    cloak_box.append(&cloak_status_label);

    cloak_expander.set_child(Some(&cloak_box));
    cloak_expander.set_visible(VPN_PROTOCOLS[0].0 == VpnProtocol::OpenVpn);
    network_tab.append(&cloak_expander);

    // Cloak and VPN-over-Tor chaining are two different mechanisms for the
    // same connection — `ConnectViaCloak` has no socks-proxy slot, so
    // opening the Cloak section and using Tor chaining at once would be
    // ambiguous. Expanding Cloak wins: it disables (and unchecks) the Tor
    // checkbox for as long as it stays expanded.
    cloak_expander.connect_expanded_notify({
        let connect_via_tor_check = connect_via_tor_check.clone();
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        move |expander| {
            if expander.is_expanded() {
                connect_via_tor_check.set_active(false);
                connect_via_tor_check.set_sensitive(false);
            } else {
                let selected = vpn_protocol_dropdown.selected() as usize;
                let supported = VPN_PROTOCOLS
                    .get(selected)
                    .map(|(protocol, _)| protocol_supports_tor_chaining(*protocol))
                    .unwrap_or(false);
                connect_via_tor_check.set_sensitive(supported);
            }
        }
    });

    vpn_protocol_dropdown.connect_selected_notify({
        let connect_via_tor_check = connect_via_tor_check.clone();
        let vpn_profile_dropdown = vpn_profile_dropdown.clone();
        let vpn_profile_empty_label = vpn_profile_empty_label.clone();
        let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
        let cloak_expander = cloak_expander.clone();
        move |dropdown| {
            let selected = dropdown.selected() as usize;
            let protocol = VPN_PROTOCOLS.get(selected).map(|(protocol, _)| *protocol);
            let supported = protocol.map(protocol_supports_tor_chaining).unwrap_or(false);

            let is_openvpn = protocol == Some(VpnProtocol::OpenVpn);
            if !is_openvpn {
                cloak_expander.set_expanded(false);
            }
            cloak_expander.set_visible(is_openvpn);

            connect_via_tor_check.set_sensitive(supported && !cloak_expander.is_expanded());
            if !supported {
                connect_via_tor_check.set_active(false);
            }

            if let Some((protocol, label)) = VPN_PROTOCOLS.get(selected).copied() {
                refresh_vpn_profiles(
                    protocol,
                    label,
                    vpn_profile_dropdown.clone(),
                    vpn_profile_empty_label.clone(),
                    Rc::clone(&vpn_profiles_state),
                );
            }
        }
    });

    let vpn_action_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vpn_connect_btn = gtk::Button::with_label("Connect");
    let vpn_disconnect_btn = gtk::Button::with_label("Disconnect");
    vpn_action_row.append(&vpn_connect_btn);
    vpn_action_row.append(&vpn_disconnect_btn);
    network_tab.append(&vpn_action_row);

    network_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Manage VPN Profiles ---------------------------------------------
    network_tab.append(&section_heading("Manage VPN Profiles"));

    // - Import Profile -----------------------------------------------------
    let vpn_import_name_entry = gtk::Entry::new();
    vpn_import_name_entry.set_placeholder_text(Some("name for the imported profile"));
    network_tab.append(&vpn_import_name_entry);

    let vpn_import_btn = gtk::Button::with_label("Import Profile from File…");
    network_tab.append(&vpn_import_btn);

    let vpn_import_status_label = gtk::Label::new(None);
    vpn_import_status_label.set_wrap(true);
    vpn_import_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&vpn_import_status_label);

    vpn_import_btn.connect_clicked({
        let window = window.clone();
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        let vpn_import_name_entry = vpn_import_name_entry.clone();
        let vpn_import_status_label = vpn_import_status_label.clone();
        let vpn_profile_dropdown = vpn_profile_dropdown.clone();
        let vpn_profile_empty_label = vpn_profile_empty_label.clone();
        let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
        move |_| {
            let name = vpn_import_name_entry.text().to_string();
            if name.trim().is_empty() {
                vpn_import_status_label.set_label("Enter a name for the imported profile first.");
                return;
            }
            let selected = vpn_protocol_dropdown.selected() as usize;
            let Some((protocol, protocol_label)) = VPN_PROTOCOLS.get(selected).copied() else {
                return;
            };

            let dialog = gtk::FileDialog::builder().title("Import VPN Profile").build();
            let window = window.clone();
            let vpn_import_status_label = vpn_import_status_label.clone();
            let vpn_profile_dropdown = vpn_profile_dropdown.clone();
            let vpn_profile_empty_label = vpn_profile_empty_label.clone();
            let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
            dialog.open(Some(&window), gtk::gio::Cancellable::NONE, move |result| {
                let file = match result {
                    Ok(file) => file,
                    Err(e) => {
                        vpn_import_status_label.set_label(&format!("File selection cancelled: {e}"));
                        return;
                    }
                };
                let Some(path) = file.path() else {
                    vpn_import_status_label.set_label("Selected file has no local path.");
                    return;
                };
                // The dashboard runs as the unprivileged desktop user and is
                // only reading a file that user already has read access to
                // — the privileged validation/write happens in nyx-vpn over
                // the socket, per `VpnCommand::ImportProfile`'s own design.
                let contents = match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(e) => {
                        vpn_import_status_label
                            .set_label(&format!("Could not read {}: {e}", path.display()));
                        return;
                    }
                };

                vpn_import_status_label.set_label("Importing…");
                let vpn_import_status_label = vpn_import_status_label.clone();
                let vpn_profile_dropdown = vpn_profile_dropdown.clone();
                let vpn_profile_empty_label = vpn_profile_empty_label.clone();
                let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
                let apply: VpnApplyFn = Rc::new(move |result| match result {
                    Ok(out) => {
                        vpn_import_status_label.set_label(&out.message);
                        if out.data.is_some() {
                            refresh_vpn_profiles(
                                protocol,
                                protocol_label,
                                vpn_profile_dropdown.clone(),
                                vpn_profile_empty_label.clone(),
                                Rc::clone(&vpn_profiles_state),
                            );
                        }
                    }
                    Err(e) => vpn_import_status_label.set_label(&format!("error: {e}")),
                });
                run_vpn_command(
                    VpnCommand::ImportProfile { protocol, name, contents },
                    apply,
                );
            });
        }
    });

    // - Fetch Free Provider --------------------------------------------------
    let free_provider_labels: Vec<&str> = FREE_PROVIDERS.iter().map(|(_, label)| *label).collect();
    let vpn_free_provider_dropdown = gtk::DropDown::from_strings(&free_provider_labels);
    vpn_free_provider_dropdown.set_selected(0);
    network_tab.append(&vpn_free_provider_dropdown);

    let vpn_free_country_entry = gtk::Entry::new();
    vpn_free_country_entry.set_placeholder_text(Some("country code, e.g. JP (VPN Gate only, optional)"));
    network_tab.append(&vpn_free_country_entry);

    vpn_free_provider_dropdown.connect_selected_notify({
        let vpn_free_country_entry = vpn_free_country_entry.clone();
        move |dropdown| {
            let selected = dropdown.selected() as usize;
            let supported = FREE_PROVIDERS
                .get(selected)
                .map(|(provider, _)| free_provider_supports_country(*provider))
                .unwrap_or(false);
            vpn_free_country_entry.set_sensitive(supported);
        }
    });

    let vpn_fetch_free_btn = gtk::Button::with_label("Fetch Free Provider");
    network_tab.append(&vpn_fetch_free_btn);

    let vpn_fetch_free_hint = gtk::Label::new(Some(
        "Clicking sends a real outbound request to the selected provider's own public VPN \
         directory (VPN Gate or Riseup) to fetch a ready-to-use relay. Never fetched automatically.",
    ));
    vpn_fetch_free_hint.add_css_class("hint");
    vpn_fetch_free_hint.set_halign(gtk::Align::Start);
    vpn_fetch_free_hint.set_wrap(true);
    network_tab.append(&vpn_fetch_free_hint);

    let vpn_fetch_free_status_label = gtk::Label::new(None);
    vpn_fetch_free_status_label.set_wrap(true);
    vpn_fetch_free_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&vpn_fetch_free_status_label);

    vpn_fetch_free_btn.connect_clicked({
        let vpn_free_provider_dropdown = vpn_free_provider_dropdown.clone();
        let vpn_free_country_entry = vpn_free_country_entry.clone();
        let vpn_fetch_free_status_label = vpn_fetch_free_status_label.clone();
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        let vpn_profile_dropdown = vpn_profile_dropdown.clone();
        let vpn_profile_empty_label = vpn_profile_empty_label.clone();
        let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
        move |_| {
            let selected = vpn_free_provider_dropdown.selected() as usize;
            let Some((provider, _)) = FREE_PROVIDERS.get(selected).copied() else {
                return;
            };
            let country_text = vpn_free_country_entry.text().to_string();
            let country = if free_provider_supports_country(provider) && !country_text.trim().is_empty() {
                Some(country_text.trim().to_string())
            } else {
                None
            };

            vpn_fetch_free_status_label.set_label("Fetching… (contacting the provider's public API)");

            let vpn_fetch_free_status_label = vpn_fetch_free_status_label.clone();
            let currently_selected_protocol =
                VPN_PROTOCOLS.get(vpn_protocol_dropdown.selected() as usize).copied();
            let vpn_profile_dropdown = vpn_profile_dropdown.clone();
            let vpn_profile_empty_label = vpn_profile_empty_label.clone();
            let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
            let apply: VpnApplyFn = Rc::new(move |result| match result {
                Ok(out) => {
                    vpn_fetch_free_status_label.set_label(&out.message);
                    if out.data.is_some() {
                        // `FetchFreeProvider` always writes an OpenVPN
                        // profile — only refresh the visible dropdown if
                        // OpenVPN happens to be selected right now.
                        if let Some((VpnProtocol::OpenVpn, label)) = currently_selected_protocol {
                            refresh_vpn_profiles(
                                VpnProtocol::OpenVpn,
                                label,
                                vpn_profile_dropdown.clone(),
                                vpn_profile_empty_label.clone(),
                                Rc::clone(&vpn_profiles_state),
                            );
                        }
                    }
                }
                Err(e) => vpn_fetch_free_status_label.set_label(&format!("error: {e}")),
            });
            run_vpn_command(VpnCommand::FetchFreeProvider { provider, country }, apply);
        }
    });

    // - Write Provider Template -----------------------------------------------
    let template_provider_labels: Vec<&str> = TEMPLATE_PROVIDERS.iter().map(|(_, label)| *label).collect();
    let vpn_template_provider_dropdown = gtk::DropDown::from_strings(&template_provider_labels);
    vpn_template_provider_dropdown.set_selected(0);
    network_tab.append(&vpn_template_provider_dropdown);

    let vpn_template_name_entry = gtk::Entry::new();
    vpn_template_name_entry.set_placeholder_text(Some("name for the new template profile"));
    network_tab.append(&vpn_template_name_entry);

    let vpn_write_template_btn = gtk::Button::with_label("Write Template");
    network_tab.append(&vpn_write_template_btn);

    let vpn_template_status_label = gtk::Label::new(None);
    vpn_template_status_label.set_wrap(true);
    vpn_template_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&vpn_template_status_label);

    vpn_write_template_btn.connect_clicked({
        let vpn_template_provider_dropdown = vpn_template_provider_dropdown.clone();
        let vpn_template_name_entry = vpn_template_name_entry.clone();
        let vpn_template_status_label = vpn_template_status_label.clone();
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        let vpn_profile_dropdown = vpn_profile_dropdown.clone();
        let vpn_profile_empty_label = vpn_profile_empty_label.clone();
        let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
        move |_| {
            let name = vpn_template_name_entry.text().to_string();
            if name.trim().is_empty() {
                vpn_template_status_label.set_label("Enter a name for the new profile first.");
                return;
            }
            let selected = vpn_template_provider_dropdown.selected() as usize;
            let Some((provider, _)) = TEMPLATE_PROVIDERS.get(selected).copied() else {
                return;
            };

            let vpn_template_status_label = vpn_template_status_label.clone();
            let currently_selected_protocol =
                VPN_PROTOCOLS.get(vpn_protocol_dropdown.selected() as usize).copied();
            let vpn_profile_dropdown = vpn_profile_dropdown.clone();
            let vpn_profile_empty_label = vpn_profile_empty_label.clone();
            let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
            let apply: VpnApplyFn = Rc::new(move |result| match result {
                Ok(out) => {
                    vpn_template_status_label.set_label(&out.message);
                    if out.data.is_some() {
                        // Mullvad's template is WireGuard, ProtonVPN's and
                        // NordVPN's are OpenVPN — only refresh the visible
                        // dropdown if the currently selected protocol
                        // matches the one this template was actually
                        // written for.
                        let template_protocol = match provider {
                            TemplateProvider::Mullvad => VpnProtocol::WireGuard,
                            TemplateProvider::ProtonVpn | TemplateProvider::NordVpn => VpnProtocol::OpenVpn,
                        };
                        if let Some((protocol, label)) = currently_selected_protocol
                            && protocol == template_protocol
                        {
                            refresh_vpn_profiles(
                                protocol,
                                label,
                                vpn_profile_dropdown.clone(),
                                vpn_profile_empty_label.clone(),
                                Rc::clone(&vpn_profiles_state),
                            );
                        }
                    }
                }
                Err(e) => vpn_template_status_label.set_label(&format!("error: {e}")),
            });
            run_vpn_command(VpnCommand::WriteProviderTemplate { provider, name }, apply);
        }
    });

    network_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Connection Info -----------------------------------------------
    network_tab.append(&section_heading("Connection Info"));

    let route_label = gtk::Label::new(Some("Default route: unknown"));
    route_label.set_halign(gtk::Align::Start);
    network_tab.append(&route_label);

    let (dns_row, dns_dot, dns_label) = status_row("DNS");
    network_tab.append(&dns_row);

    let dns_resolver_label = gtk::Label::new(Some("Resolver: unknown"));
    dns_resolver_label.set_halign(gtk::Align::Start);
    dns_resolver_label.set_wrap(true);
    network_tab.append(&dns_resolver_label);

    let dns_detail_label = gtk::Label::new(None);
    dns_detail_label.set_halign(gtk::Align::Start);
    dns_detail_label.set_wrap(true);
    network_tab.append(&dns_detail_label);

    // --- DNS provider switching ------------------------------------------
    // Curated providers + which one is live, from `DnsCommand::ListProviders`
    // (read from the deployed dnscrypt-proxy config, not the curated list
    // itself) — populated once when this tab is built, same "fetched once,
    // not on the timer" convention as the Hardening tab's posture list.
    let dns_provider_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let dns_provider_dropdown = gtk::DropDown::from_strings(&[]);
    let dns_provider_switch_btn = gtk::Button::with_label("Switch");
    dns_provider_row.append(&dns_provider_dropdown);
    dns_provider_row.append(&dns_provider_switch_btn);
    network_tab.append(&dns_provider_row);

    let dns_provider_empty_label = gtk::Label::new(Some("loading DNS providers…"));
    dns_provider_empty_label.set_wrap(true);
    dns_provider_empty_label.set_halign(gtk::Align::Start);
    network_tab.append(&dns_provider_empty_label);

    let dns_provider_status_label = gtk::Label::new(None);
    dns_provider_status_label.set_wrap(true);
    dns_provider_status_label.set_halign(gtk::Align::Start);
    network_tab.append(&dns_provider_status_label);

    // Real provider ids/display-names/active-flags, in the same order as
    // `dns_provider_dropdown`'s model — `DnsCommand::ListProviders` is the
    // only source of truth; the id (never the internal stamp name) is what
    // gets sent back on `SwitchProvider`.
    let dns_providers_state: Rc<RefCell<Vec<DnsProvider>>> = Rc::new(RefCell::new(Vec::new()));

    fn refresh_dns_providers(
        dropdown: gtk::DropDown,
        empty_label: gtk::Label,
        providers_state: Rc<RefCell<Vec<DnsProvider>>>,
    ) {
        let apply: DnsApplyFn = Rc::new(move |result| match result {
            Ok(out) => {
                let providers: Vec<DnsProvider> =
                    out.data.map(|report| report.providers).unwrap_or_default();
                if providers.is_empty() {
                    dropdown.set_model(gtk::gio::ListModel::NONE);
                    dropdown.set_visible(false);
                    empty_label.set_label("no DNS providers reported by nyx-dns");
                    empty_label.set_visible(true);
                } else {
                    let labels: Vec<String> = providers
                        .iter()
                        .map(|p| {
                            if p.active {
                                format!("{} (active)", p.display_name)
                            } else {
                                p.display_name.clone()
                            }
                        })
                        .collect();
                    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                    dropdown.set_model(Some(&gtk::StringList::new(&refs)));
                    let active_idx = providers.iter().position(|p| p.active).unwrap_or(0);
                    dropdown.set_selected(active_idx as u32);
                    dropdown.set_visible(true);
                    empty_label.set_visible(false);
                }
                *providers_state.borrow_mut() = providers;
            }
            Err(e) => {
                dropdown.set_model(gtk::gio::ListModel::NONE);
                dropdown.set_visible(false);
                empty_label.set_label(&format!("could not list DNS providers: {e}"));
                empty_label.set_visible(true);
            }
        });
        run_dns_command(DnsCommand::ListProviders, apply);
    }

    refresh_dns_providers(
        dns_provider_dropdown.clone(),
        dns_provider_empty_label.clone(),
        Rc::clone(&dns_providers_state),
    );

    let public_ip_label = gtk::Label::new(Some("Public IP: not checked"));
    public_ip_label.set_halign(gtk::Align::Start);
    public_ip_label.set_wrap(true);
    network_tab.append(&public_ip_label);

    let public_ip_btn = gtk::Button::with_label("Check Public IP");
    network_tab.append(&public_ip_btn);

    let public_ip_hint = gtk::Label::new(Some(
        "Clicking sends one live request to an external service (icanhazip.com by default), \
         which will see this machine's real public IP. Never checked automatically.",
    ));
    public_ip_hint.add_css_class("hint");
    public_ip_hint.set_halign(gtk::Align::Start);
    public_ip_hint.set_wrap(true);
    network_tab.append(&public_ip_hint);

    append_tab(&notebook, "Network", &network_tab);

    // =======================================================================
    // Identity tab
    // =======================================================================
    let identity_tab = new_tab_box();

    let hostname_label = gtk::Label::new(Some("Hostname: unknown"));
    hostname_label.set_halign(gtk::Align::Start);
    identity_tab.append(&hostname_label);
    let hostname_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let hostname_randomize_btn = gtk::Button::with_label("Randomize");
    let hostname_restore_btn = gtk::Button::with_label("Restore original");
    hostname_row.append(&hostname_randomize_btn);
    hostname_row.append(&hostname_restore_btn);
    identity_tab.append(&hostname_row);

    let timezone_label = gtk::Label::new(Some("Timezone: unknown"));
    timezone_label.set_halign(gtk::Align::Start);
    identity_tab.append(&timezone_label);
    let timezone_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let timezone_randomize_btn = gtk::Button::with_label("Randomize");
    let timezone_restore_btn = gtk::Button::with_label("Restore original");
    timezone_row.append(&timezone_randomize_btn);
    timezone_row.append(&timezone_restore_btn);
    identity_tab.append(&timezone_row);

    let mac_label = gtk::Label::new(Some("MAC: unknown"));
    mac_label.set_halign(gtk::Align::Start);
    identity_tab.append(&mac_label);
    let mac_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let mac_randomize_btn = gtk::Button::with_label("Randomize");
    let mac_restore_btn = gtk::Button::with_label("Restore permanent");
    mac_row.append(&mac_randomize_btn);
    mac_row.append(&mac_restore_btn);
    identity_tab.append(&mac_row);

    let (ipv6_row, ipv6_dot, ipv6_label) = status_row("IPv6");
    identity_tab.append(&ipv6_row);
    let ipv6_row_btns = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let ipv6_on_btn = gtk::Button::with_label("Enable");
    let ipv6_off_btn = gtk::Button::with_label("Disable");
    ipv6_row_btns.append(&ipv6_on_btn);
    ipv6_row_btns.append(&ipv6_off_btn);
    identity_tab.append(&ipv6_row_btns);

    append_tab(&notebook, "Identity", &identity_tab);

    // =======================================================================
    // Devices tab
    // =======================================================================
    let devices_tab = new_tab_box();

    let (wifi_row, wifi_dot, wifi_label) = status_row("WiFi");
    let (bt_row, bt_dot, bt_label) = status_row("Bluetooth");
    let (cam_row, cam_dot, cam_label) = status_row("Webcam");
    let (mic_row, mic_dot, mic_label) = status_row("Microphone");
    let (usbstor_row, usbstor_dot, usbstor_label) = status_row("USB Storage");
    let (usbguard_row, usbguard_dot, usbguard_label) = status_row("USBGuard");
    for row in [&wifi_row, &bt_row, &cam_row, &mic_row, &usbstor_row, &usbguard_row] {
        devices_tab.append(row);
    }

    let devices_detail_label = gtk::Label::new(None);
    devices_detail_label.set_wrap(true);
    devices_detail_label.set_halign(gtk::Align::Start);
    devices_tab.append(&devices_detail_label);

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
        devices_tab.append(row);
    }

    let usbguard_devices_label = gtk::Label::new(None);
    usbguard_devices_label.set_wrap(true);
    usbguard_devices_label.set_halign(gtk::Align::Start);
    devices_tab.append(&usbguard_devices_label);

    let usbguard_refresh_btn = gtk::Button::with_label("Refresh connected devices");
    devices_tab.append(&usbguard_refresh_btn);

    let usbguard_device_entry = gtk::Entry::new();
    usbguard_device_entry.set_placeholder_text(Some("device rule ID (from list above)"));
    devices_tab.append(&usbguard_device_entry);

    let usbguard_device_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let usbguard_allow_btn = gtk::Button::with_label("Allow");
    let usbguard_allow_permanent_btn = gtk::Button::with_label("Allow permanently");
    let usbguard_reject_btn = gtk::Button::with_label("Reject");
    usbguard_device_row.append(&usbguard_allow_btn);
    usbguard_device_row.append(&usbguard_allow_permanent_btn);
    usbguard_device_row.append(&usbguard_reject_btn);
    devices_tab.append(&usbguard_device_row);

    append_tab(&notebook, "Devices", &devices_tab);

    // =======================================================================
    // Hardening tab (new) — wired to nyx-workflow's posture system
    // =======================================================================
    let hardening_tab = new_tab_box();
    hardening_tab.append(&section_heading("Security posture"));

    let posture_desc_label = gtk::Label::new(Some("Loading postures from nyx-workflow…"));
    posture_desc_label.set_wrap(true);
    posture_desc_label.set_halign(gtk::Align::Start);

    let posture_buttons_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let posture_standard_btn = gtk::ToggleButton::with_label("Standard");
    let posture_medium_btn = gtk::ToggleButton::with_label("Medium");
    let posture_paranoid_btn = gtk::ToggleButton::with_label("Paranoid");
    posture_medium_btn.set_group(Some(&posture_standard_btn));
    posture_paranoid_btn.set_group(Some(&posture_standard_btn));
    posture_standard_btn.set_active(true);
    posture_buttons_row.append(&posture_standard_btn);
    posture_buttons_row.append(&posture_medium_btn);
    posture_buttons_row.append(&posture_paranoid_btn);
    hardening_tab.append(&posture_buttons_row);
    hardening_tab.append(&posture_desc_label);

    let apply_posture_btn = gtk::Button::with_label("Apply");
    apply_posture_btn.add_css_class("suggested-action");
    hardening_tab.append(&apply_posture_btn);

    let posture_results_label = gtk::Label::new(None);
    posture_results_label.set_wrap(true);
    posture_results_label.set_halign(gtk::Align::Start);
    hardening_tab.append(&posture_results_label);

    append_tab(&notebook, "Hardening", &hardening_tab);

    // The three posture ids/descriptions, fetched once from `nyx-workflow
    // list --json` (see workflow.rs) rather than hardcoded here.
    let postures: Rc<RefCell<Vec<workflow::WorkflowListEntry>>> = Rc::new(RefCell::new(Vec::new()));
    let selected_posture_level: Rc<RefCell<String>> = Rc::new(RefCell::new("standard".to_string()));

    fn update_posture_description(
        level: &str,
        postures: &[workflow::WorkflowListEntry],
        label: &gtk::Label,
    ) {
        let id = format!("posture-{level}");
        match postures.iter().find(|p| p.id == id) {
            Some(entry) => label.set_label(&entry.description),
            None => label.set_label("description unavailable — is nyx-workflow installed?"),
        }
    }

    let posture_list_apply: PostureListApplyFn = {
        let postures = Rc::clone(&postures);
        let selected_posture_level = Rc::clone(&selected_posture_level);
        let posture_desc_label = posture_desc_label.clone();
        Rc::new(move |result: Result<Vec<workflow::WorkflowListEntry>, String>| match result {
            Ok(entries) => {
                update_posture_description(&selected_posture_level.borrow(), &entries, &posture_desc_label);
                *postures.borrow_mut() = entries;
            }
            Err(e) => posture_desc_label.set_label(&format!("could not load postures: {e}")),
        })
    };
    run_posture_list_command(Rc::clone(&posture_list_apply));

    for (button, level) in [
        (&posture_standard_btn, "standard"),
        (&posture_medium_btn, "medium"),
        (&posture_paranoid_btn, "paranoid"),
    ] {
        button.connect_toggled({
            let postures = Rc::clone(&postures);
            let selected_posture_level = Rc::clone(&selected_posture_level);
            let posture_desc_label = posture_desc_label.clone();
            let button = button.clone();
            move |_| {
                if !button.is_active() {
                    return;
                }
                *selected_posture_level.borrow_mut() = level.to_string();
                update_posture_description(level, &postures.borrow(), &posture_desc_label);
            }
        });
    }

    let posture_apply: PostureApplyFn = {
        let posture_results_label = posture_results_label.clone();
        Rc::new(move |result: Result<workflow::WorkflowReport, String>| match result {
            Ok(report) => {
                let lines: Vec<String> = report
                    .results
                    .iter()
                    .map(|r| {
                        let mark = if !r.ran {
                            "skip"
                        } else if r.ok {
                            " ok "
                        } else {
                            "FAIL"
                        };
                        format!("[{mark}] {} — {}", r.description, r.message)
                    })
                    .collect();
                posture_results_label.set_label(&lines.join("\n"));
            }
            Err(e) => posture_results_label.set_label(&format!("error applying posture: {e}")),
        })
    };

    apply_posture_btn.connect_clicked({
        let selected_posture_level = Rc::clone(&selected_posture_level);
        let posture_apply = Rc::clone(&posture_apply);
        let posture_results_label = posture_results_label.clone();
        let window = window.clone();
        move |_| {
            let level = selected_posture_level.borrow().clone();
            let confirm = gtk::AlertDialog::builder()
                .modal(true)
                .message(format!("Apply the {level} posture?"))
                .detail(
                    "This runs nyx-workflow's posture workflow now — kill switch, identity, and \
                     device settings will change per that posture's description above.",
                )
                .buttons(["Cancel", "Apply"])
                .cancel_button(0)
                .default_button(0)
                .build();

            let posture_apply = Rc::clone(&posture_apply);
            let posture_results_label = posture_results_label.clone();
            confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                if response == Ok(1) {
                    posture_results_label.set_label("applying…");
                    run_posture_apply_command(level, Rc::clone(&posture_apply));
                }
            });
        }
    });

    // =======================================================================
    // Periodic Tasks tab (new) — wired to nyx-hardening's `schedule`
    // subcommand family. A separate tab rather than a section inside
    // Hardening: the Hardening tab above is already a full posture picker
    // plus per-step results, and 12 task rows plus a dangerous-task
    // section would roughly triple that tab's length.
    // =======================================================================
    let schedule_tab = new_tab_box();
    schedule_tab.append(&section_heading("Periodic Tasks"));

    let schedule_hint = gtk::Label::new(Some(
        "Recurring maintenance, run on real systemd timers by nyx-hardening (root, via a polkit \
         prompt for every action below — including just checking current status). Check a task, \
         set the interval, then Activate Timer. Unchecking a task that's currently active and \
         clicking Activate Timer removes its timer.",
    ));
    schedule_hint.set_wrap(true);
    schedule_hint.set_halign(gtk::Align::Start);
    schedule_hint.add_css_class("hint");
    schedule_tab.append(&schedule_hint);

    let interval_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let interval_row_label = gtk::Label::new(Some("Interval (seconds):"));
    let interval_spin = gtk::SpinButton::with_range(60.0, 2_592_000.0, 60.0);
    interval_spin.set_digits(0);
    interval_spin.set_value(3600.0);
    interval_row.append(&interval_row_label);
    interval_row.append(&interval_spin);
    schedule_tab.append(&interval_row);

    let interface_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let interface_row_label = gtk::Label::new(Some("Interface (Randomize MAC only):"));
    let schedule_interface_entry = gtk::Entry::new();
    schedule_interface_entry.set_placeholder_text(Some("e.g. wlan0"));
    interface_row.append(&interface_row_label);
    interface_row.append(&schedule_interface_entry);
    schedule_tab.append(&interface_row);

    // Pre-fill from the same interface the Identity tab's MAC
    // randomize/restore buttons already act on (`mac_interface`, populated
    // from `IdentityReport::interfaces.first()`) rather than leaving this
    // a blind free-text field — see `identity_apply` further down, which
    // updates `mac_interface` on every identity refresh.
    schedule_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    let mut schedule_task_ids: Vec<&'static str> = Vec::new();
    let mut schedule_task_checks: Vec<gtk::CheckButton> = Vec::new();
    let mut schedule_task_status_labels: Vec<gtk::Label> = Vec::new();

    schedule_tab.append(&section_heading("Routine tasks"));
    for task in PERIODIC_TASKS.iter().filter(|t| !t.dangerous) {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let check = gtk::CheckButton::with_label(task.label);
        let status = gtk::Label::new(Some("checking…"));
        status.add_css_class("hint");
        row.append(&check);
        row.append(&status);
        schedule_tab.append(&row);
        schedule_task_ids.push(task.id);
        schedule_task_checks.push(check);
        schedule_task_status_labels.push(status);
    }

    schedule_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    schedule_tab.append(&section_heading("Dangerous tasks"));
    let schedule_dangerous_warning = gtk::Label::new(Some(
        "These four run genuinely slow and/or irreversible nyx-wipe operations: multi-hour \
         free-space overwriting, and recursive secure shredding of every local user's Documents, \
         Downloads, or Desktop folder. Activating one asks for confirmation first.",
    ));
    schedule_dangerous_warning.set_wrap(true);
    schedule_dangerous_warning.set_halign(gtk::Align::Start);
    schedule_dangerous_warning.add_css_class("hint");
    schedule_tab.append(&schedule_dangerous_warning);
    for task in PERIODIC_TASKS.iter().filter(|t| t.dangerous) {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let check = gtk::CheckButton::with_label(task.label);
        check.add_css_class("destructive-action");
        let status = gtk::Label::new(Some("checking…"));
        status.add_css_class("hint");
        row.append(&check);
        row.append(&status);
        schedule_tab.append(&row);
        schedule_task_ids.push(task.id);
        schedule_task_checks.push(check);
        schedule_task_status_labels.push(status);
    }

    let schedule_action_btn = gtk::Button::with_label("Activate Timer");
    schedule_action_btn.add_css_class("suggested-action");
    schedule_tab.append(&schedule_action_btn);

    let schedule_result_label = gtk::Label::new(None);
    schedule_result_label.set_wrap(true);
    schedule_result_label.set_halign(gtk::Align::Start);
    schedule_tab.append(&schedule_result_label);

    append_tab(&notebook, "Periodic Tasks", &schedule_tab);

    // Real installed/enabled/interval state, as last reported by `schedule
    // status` — indexed in parallel with `schedule_task_ids`/
    // `schedule_task_checks` above. Used by the Activate Timer handler to
    // decide which unchecked tasks actually need a `remove` call, rather
    // than firing a harmless-but-needless pkexec prompt for every task
    // that was never installed in the first place.
    let schedule_task_installed: Rc<RefCell<Vec<bool>>> =
        Rc::new(RefCell::new(vec![false; schedule_task_ids.len()]));

    let schedule_status_apply: ScheduleStatusApplyFn = {
        let schedule_task_ids = schedule_task_ids.clone();
        let schedule_task_checks = schedule_task_checks.clone();
        let schedule_task_status_labels = schedule_task_status_labels.clone();
        let schedule_task_installed = Rc::clone(&schedule_task_installed);
        Rc::new(move |result: Result<Vec<schedule::TaskStatus>, String>| match result {
            Ok(statuses) => {
                let mut installed_vec = vec![false; schedule_task_ids.len()];
                for (i, task_id) in schedule_task_ids.iter().enumerate() {
                    match statuses.iter().find(|s| s.task == *task_id) {
                        Some(s) => {
                            installed_vec[i] = s.installed;
                            schedule_task_checks[i].set_active(s.installed && s.enabled);
                            let base = if s.installed {
                                if s.enabled { "installed, enabled" } else { "installed, disabled" }
                            } else {
                                "not installed"
                            };
                            let interval_note = s
                                .interval_secs
                                .map(|secs| format!(", every {secs}s"))
                                .unwrap_or_default();
                            schedule_task_status_labels[i].set_label(&format!("{base}{interval_note}"));
                        }
                        None => schedule_task_status_labels[i].set_label("unknown"),
                    }
                }
                *schedule_task_installed.borrow_mut() = installed_vec;
            }
            Err(e) => {
                for label in &schedule_task_status_labels {
                    label.set_label(&format!("status error: {e}"));
                }
            }
        })
    };
    run_schedule_status_command(Rc::clone(&schedule_status_apply));

    let schedule_actions_apply: ScheduleActionsApplyFn = {
        let schedule_result_label = schedule_result_label.clone();
        let schedule_status_apply = Rc::clone(&schedule_status_apply);
        Rc::new(move |result: Result<ScheduleActionResults, String>| match result {
            Ok(results) => {
                let lines: Vec<String> = results
                    .iter()
                    .map(|(task_id, r)| match r {
                        Ok(msg) => format!("[ ok ] {task_id}: {msg}"),
                        Err(e) => format!("[FAIL] {task_id}: {e}"),
                    })
                    .collect();
                schedule_result_label.set_label(&lines.join("\n"));
                run_schedule_status_command(Rc::clone(&schedule_status_apply));
            }
            Err(e) => schedule_result_label.set_label(&format!("error: {e}")),
        })
    };

    schedule_action_btn.connect_clicked({
        let schedule_task_ids = schedule_task_ids.clone();
        let schedule_task_checks = schedule_task_checks.clone();
        let schedule_task_installed = Rc::clone(&schedule_task_installed);
        let interval_spin = interval_spin.clone();
        let schedule_interface_entry = schedule_interface_entry.clone();
        let schedule_result_label = schedule_result_label.clone();
        let schedule_actions_apply = Rc::clone(&schedule_actions_apply);
        let window = window.clone();
        move |_| {
            let interval_secs = interval_spin.value() as u64;
            let installed = schedule_task_installed.borrow().clone();
            let mut actions = Vec::new();
            let mut dangerous_activating: Vec<&'static str> = Vec::new();

            for (i, task_id) in schedule_task_ids.iter().enumerate() {
                let def = PERIODIC_TASKS
                    .iter()
                    .find(|t| t.id == *task_id)
                    .expect("schedule_task_ids only ever holds PERIODIC_TASKS ids");
                let checked = schedule_task_checks[i].is_active();
                if checked {
                    if def.dangerous {
                        dangerous_activating.push(task_id);
                    }
                    let interface = if def.needs_interface {
                        let text = schedule_interface_entry.text().to_string();
                        if text.trim().is_empty() { None } else { Some(text) }
                    } else {
                        None
                    };
                    actions.push(schedule::ScheduleAction {
                        task_id: task_id.to_string(),
                        kind: schedule::ScheduleActionKind::Install { interval_secs, interface },
                    });
                } else if installed.get(i).copied().unwrap_or(false) {
                    actions.push(schedule::ScheduleAction {
                        task_id: task_id.to_string(),
                        kind: schedule::ScheduleActionKind::Remove,
                    });
                }
            }

            if actions.is_empty() {
                schedule_result_label.set_label("nothing to change");
                return;
            }

            if dangerous_activating.is_empty() {
                schedule_result_label.set_label("applying…");
                run_schedule_actions_command(actions, Rc::clone(&schedule_actions_apply));
            } else {
                let list = dangerous_activating.join(", ");
                let confirm = gtk::AlertDialog::builder()
                    .modal(true)
                    .message("Activate a dangerous periodic task?")
                    .detail(format!(
                        "This schedules the following task(s) to run unattended, on a recurring \
                         timer, from now on: {list}. Free-space wiping and Documents/Downloads/\
                         Desktop shredding are slow and cannot be undone once a run starts."
                    ))
                    .buttons(["Cancel", "Activate"])
                    .cancel_button(0)
                    .default_button(0)
                    .build();

                let schedule_actions_apply = Rc::clone(&schedule_actions_apply);
                let schedule_result_label = schedule_result_label.clone();
                confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                    if response == Ok(1) {
                        schedule_result_label.set_label("applying…");
                        run_schedule_actions_command(actions, Rc::clone(&schedule_actions_apply));
                    }
                });
            }
        }
    });

    // =======================================================================
    // Browsers tab (new)
    // =======================================================================
    let browsers_tab = new_tab_box();
    browsers_tab.append(&section_heading("Browsers"));

    let nyx_browser_btn = gtk::Button::with_label("Nyx Browser");
    let nyx_oniux_browser_btn = gtk::Button::with_label("Nyx Oniux Browser");
    let nyx_tor_browser_btn = gtk::Button::with_label("Nyx Tor Browser");
    let nyx_disposable_browser_btn = gtk::Button::with_label("Nyx Disposable Browser");
    for button in [
        &nyx_browser_btn,
        &nyx_oniux_browser_btn,
        &nyx_tor_browser_btn,
        &nyx_disposable_browser_btn,
    ] {
        browsers_tab.append(button);
    }

    let browsers_status_label = gtk::Label::new(None);
    browsers_status_label.set_wrap(true);
    browsers_status_label.set_halign(gtk::Align::Start);
    browsers_tab.append(&browsers_status_label);

    append_tab(&notebook, "Browsers", &browsers_tab);

    for (button, binary, name) in [
        (&nyx_browser_btn, "/usr/bin/nyx-browser", "Nyx Browser"),
        (&nyx_oniux_browser_btn, "/usr/bin/nyx-oniux-browser", "Nyx Oniux Browser"),
        (&nyx_tor_browser_btn, "/usr/bin/nyx-tor-browser", "Nyx Tor Browser"),
        (&nyx_disposable_browser_btn, "/usr/bin/nyx-disposable-browser", "Nyx Disposable Browser"),
    ] {
        button.connect_clicked({
            let browsers_status_label = browsers_status_label.clone();
            move |_| match spawn_browser(binary) {
                Ok(()) => browsers_status_label.set_label(&format!("Launched {name}")),
                Err(e) => browsers_status_label.set_label(&format!("Failed to launch {name}: {e}")),
            }
        });
    }

    // =======================================================================
    // Emergency tab: Kill Switch level + Panic Mode
    // =======================================================================
    let emergency_tab = new_tab_box();

    let (ks_row, ks_dot, ks_label) = status_row("Kill Switch");
    let (panic_row, panic_dot, panic_label) = status_row("Panic Mode");
    emergency_tab.append(&ks_row);
    emergency_tab.append(&panic_row);

    let ks_heading = gtk::Label::new(Some("Kill switch level"));
    ks_heading.set_halign(gtk::Align::Start);
    emergency_tab.append(&ks_heading);

    let ks_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let ks_off_btn = gtk::Button::with_label("Off");
    let ks_soft_btn = gtk::Button::with_label("Soft");
    let ks_medium_btn = gtk::Button::with_label("Medium");
    let ks_armed_btn = gtk::Button::with_label("Armed");
    ks_buttons.append(&ks_off_btn);
    ks_buttons.append(&ks_soft_btn);
    ks_buttons.append(&ks_medium_btn);
    ks_buttons.append(&ks_armed_btn);
    emergency_tab.append(&ks_buttons);

    let panic_btn = gtk::Button::with_label("PANIC — lock down network");
    panic_btn.add_css_class("destructive-action");
    emergency_tab.append(&panic_btn);

    emergency_tab.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    emergency_tab.append(&section_heading("Installation Integrity"));

    let (integrity_row, integrity_dot, integrity_label) = status_row("Integrity");
    emergency_tab.append(&integrity_row);

    let integrity_action_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let verify_installation_btn = gtk::Button::with_label("Verify Installation");
    let rebaseline_btn = gtk::Button::with_label("Re-baseline (Trust Current State)");
    rebaseline_btn.add_css_class("destructive-action");
    integrity_action_row.append(&verify_installation_btn);
    integrity_action_row.append(&rebaseline_btn);
    emergency_tab.append(&integrity_action_row);

    let integrity_detail_label = gtk::Label::new(None);
    integrity_detail_label.set_wrap(true);
    integrity_detail_label.set_halign(gtk::Align::Start);
    emergency_tab.append(&integrity_detail_label);

    append_tab(&notebook, "Emergency", &emergency_tab);

    // =======================================================================
    // Telemetry tab
    // =======================================================================
    let telemetry_tab = new_tab_box();

    let cpu_label = gtk::Label::new(Some("CPU: unknown"));
    cpu_label.set_halign(gtk::Align::Start);
    telemetry_tab.append(&cpu_label);

    let mem_label = gtk::Label::new(Some("Memory: unknown"));
    mem_label.set_halign(gtk::Align::Start);
    telemetry_tab.append(&mem_label);

    let disk_label = gtk::Label::new(Some("Disk (/): unknown"));
    disk_label.set_halign(gtk::Align::Start);
    telemetry_tab.append(&disk_label);

    let net_label = gtk::Label::new(Some("Network: unknown"));
    net_label.set_halign(gtk::Align::Start);
    net_label.set_wrap(true);
    telemetry_tab.append(&net_label);

    let uptime_label = gtk::Label::new(Some("Uptime: unknown"));
    uptime_label.set_halign(gtk::Align::Start);
    telemetry_tab.append(&uptime_label);

    append_tab(&notebook, "Telemetry", &telemetry_tab);

    // =======================================================================
    // State + polling + signal wiring
    // =======================================================================
    let cached = Rc::new(RefCell::new(HealthState::default()));
    // The interface Randomize/Restore MAC act on — the first one reported
    // by nyx-identity. A future revision could let the user pick among
    // several; most machines only have one to worry about.
    let mac_interface = Rc::new(RefCell::new(None::<String>));

    let apply: ApplyFn = {
        let cached = Rc::clone(&cached);
        let tor_renew_btn = tor_renew_btn.clone();
        Rc::new(move |result: Result<NyxOutput<HealthState>, String>| match result {
            Ok(out) => {
                if let Some(state) = out.data.clone() {
                    set_dot(&tor_dot, state.tor_active);
                    set_dot(&header_tor_dot, state.tor_active);
                    tor_renew_btn.set_sensitive(state.tor_active);
                    set_level_dot(&ks_dot, state.kill_switch_level);
                    set_dot(&panic_dot, state.panic_mode);
                    tor_label.set_label(&format!(
                        "Tor: {}",
                        if state.tor_active { "active" } else { "inactive" }
                    ));
                    header_tor_label.set_label(&format!(
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

    // Wraps `apply` so a manual circuit renewal also shows nyx-health's
    // real result message on its own label, next to the button, rather
    // than only in the shared status bar at the bottom of the window.
    let tor_renew_apply: ApplyFn = {
        let tor_renew_status_label = tor_renew_status_label.clone();
        let apply = Rc::clone(&apply);
        Rc::new(move |result: Result<NyxOutput<HealthState>, String>| {
            match &result {
                Ok(out) => tor_renew_status_label.set_label(&out.message),
                Err(e) => tor_renew_status_label.set_label(&format!("error: {e}")),
            }
            apply(result);
        })
    };

    let vpn_apply: VpnApplyFn = Rc::new(move |result: Result<NyxOutput<VpnReport>, String>| match result
    {
        Ok(out) => {
            if let Some(report) = out.data {
                set_security_dot(&vpn_dot, report.state);
                set_security_dot(&header_vpn_dot, report.state);
                let label = match (&report.protocol, &report.profile) {
                    (Some(protocol), Some(profile)) => {
                        format!("VPN: {profile} ({protocol:?})")
                    }
                    _ => "VPN: disconnected".to_string(),
                };
                vpn_label.set_label(&label);
                header_vpn_label.set_label(&label);
                vpn_detail_label.set_label(&report.detail);
            }
        }
        Err(e) => vpn_detail_label.set_label(&format!("error: {e}")),
    });

    let identity_apply: IdentityApplyFn = {
        let mac_interface = Rc::clone(&mac_interface);
        let schedule_interface_entry = schedule_interface_entry.clone();
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
                        // Pre-fills the Periodic Tasks tab's Randomize MAC
                        // interface field with the same interface the
                        // Identity tab's own Randomize/Restore buttons act
                        // on — only while the operator hasn't typed
                        // anything else in there themselves.
                        if schedule_interface_entry.text().is_empty() {
                            schedule_interface_entry.set_text(&first.interface);
                        }
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
                    if report.usbguard_live_devices.is_empty() {
                        usbguard_devices_label.set_label("no connected devices reported");
                    } else {
                        usbguard_devices_label.set_label(&report.usbguard_live_devices.join("\n"));
                    }
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

    let default_route_apply: DefaultRouteApplyFn =
        Rc::new(move |result: Result<DefaultRoute, String>| match result {
            Ok(route) => {
                let text = match (&route.interface, &route.gateway) {
                    (Some(iface), Some(gateway)) => format!("Default route: {iface} via {gateway}"),
                    (Some(iface), None) => format!("Default route: {iface}"),
                    _ => "Default route: none found".to_string(),
                };
                route_label.set_label(&text);
                header_route_label.set_label(&format!(
                    "Route: {}",
                    route.interface.as_deref().unwrap_or("none")
                ));
            }
            Err(e) => {
                route_label.set_label(&format!("Default route: error ({e})"));
                header_route_label.set_label("Route: error");
            }
        });

    let dns_apply: DnsApplyFn = Rc::new(move |result: Result<NyxOutput<DnsReport>, String>| match result {
        Ok(out) => {
            if let Some(report) = out.data {
                set_security_dot(&dns_dot, report.state);
                set_security_dot(&header_dns_dot, report.state);
                dns_label.set_label(&format!(
                    "DNS: {}",
                    if report.resolves { "resolving" } else { "not resolving" }
                ));
                header_dns_label.set_label(&format!(
                    "DNS: {}",
                    if report.resolves { "resolving" } else { "not resolving" }
                ));
                let resolvers = if report.resolver_addrs.is_empty() {
                    "none".to_string()
                } else {
                    report.resolver_addrs.join(", ")
                };
                dns_resolver_label.set_label(&format!(
                    "Resolver: {resolvers} ({}) — DNSCrypt {}{}",
                    if report.resolver_is_local { "local" } else { "not local" },
                    if report.dnscrypt_active { "active" } else { "inactive" },
                    if report.foreign_listener_on_53 {
                        " — foreign listener on port 53"
                    } else {
                        ""
                    }
                ));
                dns_detail_label.set_label(&report.detail);
            }
        }
        Err(e) => dns_resolver_label.set_label(&format!("Resolver: error ({e})")),
    });

    let public_ip_label_for_btn = public_ip_label.clone();
    let public_ip_apply: PublicIpApplyFn =
        Rc::new(move |result: Result<PublicIpResult, String>| match result {
            Ok(res) => public_ip_label.set_label(&format!("Public IP: {} (via {})", res.ip, res.endpoint)),
            Err(e) => public_ip_label.set_label(&format!("Public IP: check failed ({e})")),
        });

    let integrity_apply: IntegrityApplyFn =
        Rc::new(move |result: Result<NyxOutput<IntegrityReport>, String>| match result {
            Ok(out) => {
                if let Some(report) = out.data {
                    set_security_dot(&integrity_dot, report.state);
                    integrity_label.set_label(&format!(
                        "Integrity: {} manifest file(s), {} package(s) checked",
                        report.manifest_checked, report.package_scanned
                    ));
                    let mismatches = report.manifest_mismatches.len() + report.package_mismatches.len();
                    integrity_detail_label.set_label(&if mismatches > 0 {
                        format!("{mismatches} mismatch(es) — {}", report.detail)
                    } else {
                        report.detail.clone()
                    });
                }
            }
            Err(e) => integrity_detail_label.set_label(&format!("error: {e}")),
        });

    run_command(HealthCommand::Status, Rc::clone(&apply));
    run_vpn_command(VpnCommand::Status, Rc::clone(&vpn_apply));
    run_identity_command(IdentityCommand::Status, Rc::clone(&identity_apply));
    run_devices_command(DevicesCommand::Status, Rc::clone(&devices_apply));
    run_telemetry_command(TelemetryCommand::Status, Rc::clone(&telemetry_apply));
    run_default_route_command(Rc::clone(&default_route_apply));
    run_dns_command(DnsCommand::Status, Rc::clone(&dns_apply));
    // Verify Installation deliberately isn't fetched here either, beyond
    // this one cheap `Status` read of whatever nyx-integrity last computed
    // (no rescan) — the actual manifest/pacman scan only ever runs from an
    // explicit click of "Verify Installation" below, same reasoning as
    // Public IP above: a real scan is neither free nor instant enough to
    // run silently on a timer.
    run_integrity_command(IntegrityCommand::Status, Rc::clone(&integrity_apply));
    // Public IP is deliberately NOT fetched here — only ever on an explicit
    // click of "Check Public IP" (see `public_ip_btn`'s handler below).

    {
        let apply = Rc::clone(&apply);
        let vpn_apply = Rc::clone(&vpn_apply);
        let identity_apply = Rc::clone(&identity_apply);
        let devices_apply = Rc::clone(&devices_apply);
        let telemetry_apply = Rc::clone(&telemetry_apply);
        let default_route_apply = Rc::clone(&default_route_apply);
        let dns_apply = Rc::clone(&dns_apply);
        glib::timeout_add_seconds_local(5, move || {
            run_command(HealthCommand::Status, Rc::clone(&apply));
            run_vpn_command(VpnCommand::Status, Rc::clone(&vpn_apply));
            run_identity_command(IdentityCommand::Status, Rc::clone(&identity_apply));
            run_devices_command(DevicesCommand::Status, Rc::clone(&devices_apply));
            run_telemetry_command(TelemetryCommand::Status, Rc::clone(&telemetry_apply));
            run_default_route_command(Rc::clone(&default_route_apply));
            run_dns_command(DnsCommand::Status, Rc::clone(&dns_apply));
            // Public IP stays out of this timer permanently — see the note
            // above and the button handler below, which is the only place
            // `run_public_ip_command` is ever called.
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

    vpn_connect_btn.connect_clicked({
        let vpn_apply = Rc::clone(&vpn_apply);
        let vpn_profile_dropdown = vpn_profile_dropdown.clone();
        let vpn_protocol_dropdown = vpn_protocol_dropdown.clone();
        let connect_via_tor_check = connect_via_tor_check.clone();
        let vpn_profiles_state = Rc::clone(&vpn_profiles_state);
        let cloak_expander = cloak_expander.clone();
        let cloak_remote_host_entry = cloak_remote_host_entry.clone();
        let cloak_remote_port_entry = cloak_remote_port_entry.clone();
        let cloak_public_key_entry = cloak_public_key_entry.clone();
        let cloak_uid_entry = cloak_uid_entry.clone();
        let cloak_server_name_entry = cloak_server_name_entry.clone();
        let cloak_encryption_dropdown = cloak_encryption_dropdown.clone();
        let cloak_num_conn_entry = cloak_num_conn_entry.clone();
        let cloak_browser_sig_entry = cloak_browser_sig_entry.clone();
        let cloak_status_label = cloak_status_label.clone();
        let window = window.clone();
        move |_| {
            let selected_profile = vpn_profiles_state
                .borrow()
                .get(vpn_profile_dropdown.selected() as usize)
                .cloned();
            let Some((profile, incomplete)) = selected_profile else {
                return;
            };
            let selected = vpn_protocol_dropdown.selected() as usize;
            let Some((protocol, _)) = VPN_PROTOCOLS.get(selected).copied() else {
                return;
            };

            let cmd = if protocol == VpnProtocol::OpenVpn && cloak_expander.is_expanded() {
                let remote_host = cloak_remote_host_entry.text().to_string();
                let public_key = cloak_public_key_entry.text().to_string();
                let uid = cloak_uid_entry.text().to_string();
                let server_name = cloak_server_name_entry.text().to_string();
                if remote_host.trim().is_empty()
                    || public_key.trim().is_empty()
                    || uid.trim().is_empty()
                    || server_name.trim().is_empty()
                {
                    cloak_status_label.set_label(
                        "Cloak: remote host, public key, UID, and server name are all required.",
                    );
                    return;
                }
                let Ok(remote_port) = cloak_remote_port_entry.text().trim().parse::<u16>() else {
                    cloak_status_label
                        .set_label("Cloak: remote port must be a valid port number (0-65535).");
                    return;
                };
                let num_conn_text = cloak_num_conn_entry.text().to_string();
                let num_conn = if num_conn_text.trim().is_empty() {
                    None
                } else {
                    match num_conn_text.trim().parse::<u32>() {
                        Ok(n) => Some(n),
                        Err(_) => {
                            cloak_status_label
                                .set_label("Cloak: number of connections must be a whole number.");
                            return;
                        }
                    }
                };
                let browser_sig_text = cloak_browser_sig_entry.text().to_string();
                let browser_sig = if browser_sig_text.trim().is_empty() {
                    None
                } else {
                    Some(browser_sig_text.trim().to_string())
                };
                let encryption_method = CLOAK_ENCRYPTION_METHODS
                    .get(cloak_encryption_dropdown.selected() as usize)
                    .copied()
                    .unwrap_or("aes-256-gcm")
                    .to_string();

                cloak_status_label.set_label("");
                VpnCommand::ConnectViaCloak {
                    profile,
                    cloak_config: CloakConfig {
                        remote_host: remote_host.trim().to_string(),
                        remote_port,
                        public_key: public_key.trim().to_string(),
                        uid: uid.trim().to_string(),
                        server_name: server_name.trim().to_string(),
                        encryption_method,
                        num_conn,
                        browser_sig,
                    },
                }
            } else if connect_via_tor_check.is_sensitive() && connect_via_tor_check.is_active() {
                VpnCommand::ConnectViaSocksProxy {
                    protocol,
                    profile,
                    socks_proxy: SocksProxyAddr { host: "127.0.0.1".to_string(), port: 9050 },
                }
            } else {
                VpnCommand::Connect { protocol, profile }
            };

            if incomplete {
                let vpn_apply = Rc::clone(&vpn_apply);
                let confirm = gtk::AlertDialog::builder()
                    .modal(true)
                    .message("This profile is incomplete")
                    .detail(
                        "It still contains an unfilled template placeholder and needs your own \
                         account credentials before it can connect. Connecting now will most \
                         likely fail.",
                    )
                    .buttons(["Cancel", "Connect Anyway"])
                    .cancel_button(0)
                    .default_button(0)
                    .build();
                confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                    if response == Ok(1) {
                        run_vpn_command(cmd, vpn_apply);
                    }
                });
            } else {
                run_vpn_command(cmd, Rc::clone(&vpn_apply));
            }
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
    usbguard_refresh_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        move |_| {
            run_devices_command(DevicesCommand::ListUsbGuardDevices, Rc::clone(&devices_apply))
        }
    });
    usbguard_allow_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        let usbguard_device_entry = usbguard_device_entry.clone();
        move |_| {
            let id = usbguard_device_entry.text().to_string();
            if id.trim().is_empty() {
                return;
            }
            run_devices_command(
                DevicesCommand::AllowUsbGuardDevice { id, permanent: false },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbguard_allow_permanent_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        let usbguard_device_entry = usbguard_device_entry.clone();
        move |_| {
            let id = usbguard_device_entry.text().to_string();
            if id.trim().is_empty() {
                return;
            }
            run_devices_command(
                DevicesCommand::AllowUsbGuardDevice { id, permanent: true },
                Rc::clone(&devices_apply),
            )
        }
    });
    usbguard_reject_btn.connect_clicked({
        let devices_apply = Rc::clone(&devices_apply);
        let usbguard_device_entry = usbguard_device_entry.clone();
        move |_| {
            let id = usbguard_device_entry.text().to_string();
            if id.trim().is_empty() {
                return;
            }
            run_devices_command(
                DevicesCommand::RejectUsbGuardDevice { id },
                Rc::clone(&devices_apply),
            )
        }
    });

    // The only place the public-IP check is ever triggered: an explicit
    // click, never a timer. See `run_public_ip_command`'s doc comment.
    public_ip_btn.connect_clicked({
        let public_ip_apply = Rc::clone(&public_ip_apply);
        let public_ip_label_for_btn = public_ip_label_for_btn.clone();
        move |_| {
            public_ip_label_for_btn.set_label("Public IP: checking… (contacting external service)");
            run_public_ip_command(Rc::clone(&public_ip_apply));
        }
    });

    // The only place a real (non-`Status`) integrity scan is ever
    // triggered — an explicit click, never the 5s timer. `quick: true`
    // limits the pacman file-integrity half of the scan to NyxOS-critical
    // packages rather than the whole system, matching the CLI's own
    // documented reason for that flag.
    verify_installation_btn.connect_clicked({
        let integrity_apply = Rc::clone(&integrity_apply);
        move |_| {
            run_integrity_command(IntegrityCommand::Verify { quick: true }, Rc::clone(&integrity_apply));
        }
    });

    // Re-baselining trusts whatever is on disk right now — genuinely
    // dangerous if the system is already compromised, since it would
    // "bless" the compromise into the manifest a future Verify checks
    // against. Gated behind a confirmation naming that risk explicitly,
    // same pattern as Panic/posture-apply/dangerous-periodic-tasks above.
    rebaseline_btn.connect_clicked({
        let integrity_apply = Rc::clone(&integrity_apply);
        let window = window.clone();
        move |_| {
            let confirm = gtk::AlertDialog::builder()
                .modal(true)
                .message("Re-baseline the integrity manifest?")
                .detail(
                    "This overwrites the trust manifest with hashes of whatever is on disk right \
                     now. Only do this right after a known-good install or update — if the system \
                     is already compromised, this makes that compromise the new trusted baseline. \
                     Never use this just to clear a failed Verify result.",
                )
                .buttons(["Cancel", "Re-baseline"])
                .cancel_button(0)
                .default_button(0)
                .build();

            let integrity_apply = Rc::clone(&integrity_apply);
            confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                if response == Ok(1) {
                    run_integrity_command(IntegrityCommand::Baseline, Rc::clone(&integrity_apply));
                }
            });
        }
    });

    tor_renew_btn.connect_clicked({
        let tor_renew_apply = Rc::clone(&tor_renew_apply);
        let tor_renew_status_label = tor_renew_status_label.clone();
        move |_| {
            tor_renew_status_label.set_label("Renewing Tor circuit…");
            run_command(HealthCommand::TorRestart, Rc::clone(&tor_renew_apply));
        }
    });

    // DNS provider switching changes the resolver the whole system uses,
    // so it's gated behind a confirmation naming the provider — same
    // pattern as Panic/posture-apply above. `SwitchProvider` already does
    // its own live-query verification and automatic rollback on failure
    // server-side, so this only ever surfaces nyx-dns's real result
    // message, never re-verifies client-side.
    dns_provider_switch_btn.connect_clicked({
        let dns_provider_dropdown = dns_provider_dropdown.clone();
        let dns_provider_empty_label = dns_provider_empty_label.clone();
        let dns_provider_status_label = dns_provider_status_label.clone();
        let dns_providers_state = Rc::clone(&dns_providers_state);
        let dns_apply = Rc::clone(&dns_apply);
        let window = window.clone();
        move |_| {
            let selected = dns_provider_dropdown.selected() as usize;
            let Some(provider) = dns_providers_state.borrow().get(selected).cloned() else {
                return;
            };

            let confirm = gtk::AlertDialog::builder()
                .modal(true)
                .message(format!("Switch DNS provider to {}?", provider.display_name))
                .detail(
                    "This changes the DNS resolver dnscrypt-proxy uses for the whole system. \
                     nyx-dns verifies a live query still resolves after switching and \
                     automatically rolls back to the previous provider if it doesn't.",
                )
                .buttons(["Cancel", "Switch"])
                .cancel_button(0)
                .default_button(0)
                .build();

            let dns_provider_dropdown = dns_provider_dropdown.clone();
            let dns_provider_empty_label = dns_provider_empty_label.clone();
            let dns_provider_status_label = dns_provider_status_label.clone();
            let dns_providers_state = Rc::clone(&dns_providers_state);
            let dns_apply = Rc::clone(&dns_apply);
            confirm.choose(Some(&window), gtk::gio::Cancellable::NONE, move |response| {
                if response != Ok(1) {
                    return;
                }
                dns_provider_status_label.set_label("Switching…");
                let dns_provider_dropdown = dns_provider_dropdown.clone();
                let dns_provider_empty_label = dns_provider_empty_label.clone();
                let dns_provider_status_label = dns_provider_status_label.clone();
                let dns_providers_state = Rc::clone(&dns_providers_state);
                let dns_apply = Rc::clone(&dns_apply);
                let apply: DnsApplyFn = Rc::new(move |result| {
                    match &result {
                        Ok(out) => dns_provider_status_label.set_label(&out.message),
                        Err(e) => dns_provider_status_label.set_label(&format!("error: {e}")),
                    }
                    refresh_dns_providers(
                        dns_provider_dropdown.clone(),
                        dns_provider_empty_label.clone(),
                        Rc::clone(&dns_providers_state),
                    );
                    run_dns_command(DnsCommand::Status, Rc::clone(&dns_apply));
                });
                run_dns_command(
                    DnsCommand::SwitchProvider { provider: provider.id.clone() },
                    apply,
                );
            });
        }
    });
}
