use crate::client;
use gtk::glib;
use gtk::prelude::*;
use nyx_core::{HealthCommand, HealthState, KillSwitchLevel, NyxOutput, Toggle};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;

type ApplyFn = Rc<dyn Fn(Result<NyxOutput<HealthState>, String>)>;

fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(
        "
        .dot { min-width: 12px; min-height: 12px; border-radius: 6px; margin-right: 6px; }
        .dot-on { background-color: #2ecc71; }
        .dot-off { background-color: #e74c3c; }
        .dot-soft { background-color: #f1c40f; }
        .dot-medium { background-color: #e67e22; }
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

fn set_dot(dot: &gtk::Box, on: bool) {
    dot.remove_css_class(if on { "dot-off" } else { "dot-on" });
    dot.add_css_class(if on { "dot-on" } else { "dot-off" });
}

/// Kill-switch levels get their own four-colour scale instead of the plain
/// on/off dot: Off=red, Soft=yellow, Medium=orange, Armed=green (green here
/// means "fully enforced", not "safe" — Armed is the most disruptive level).
fn set_level_dot(dot: &gtk::Box, level: KillSwitchLevel) {
    for class in DOT_CLASSES {
        dot.remove_css_class(class);
    }
    let class = match level {
        KillSwitchLevel::Off => "dot-off",
        KillSwitchLevel::Soft => "dot-soft",
        KillSwitchLevel::Medium => "dot-medium",
        KillSwitchLevel::Armed => "dot-on",
    };
    dot.add_css_class(class);
}

fn level_label(level: KillSwitchLevel) -> &'static str {
    match level {
        KillSwitchLevel::Off => "Off",
        KillSwitchLevel::Soft => "Soft",
        KillSwitchLevel::Medium => "Medium",
        KillSwitchLevel::Armed => "Armed",
    }
}

/// Runs `cmd` on a background thread (the health socket is blocking I/O) and
/// applies the result back on the GTK main thread once it arrives.
fn run_command(cmd: HealthCommand, apply: ApplyFn) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = client::send(cmd);
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

pub fn build(app: &gtk::Application) {
    load_css();

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("NyxOS Control")
        .default_width(380)
        .default_height(400)
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

    let (tor_row, tor_dot, tor_label) = status_row("Tor");
    let (ks_row, ks_dot, ks_label) = status_row("Kill Switch");
    let (panic_row, panic_dot, panic_label) = status_row("Panic Mode");
    root.append(&tor_row);
    root.append(&ks_row);
    root.append(&panic_row);

    let sep = gtk::Separator::new(gtk::Orientation::Horizontal);
    root.append(&sep);

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

    let status_label = gtk::Label::new(Some("connecting to nyx-health…"));
    status_label.set_wrap(true);
    status_label.set_halign(gtk::Align::Start);
    root.append(&status_label);

    window.set_child(Some(&root));
    window.present();

    let cached = Rc::new(RefCell::new(HealthState::default()));

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

    run_command(HealthCommand::Status, Rc::clone(&apply));

    {
        let apply = Rc::clone(&apply);
        glib::timeout_add_seconds_local(5, move || {
            run_command(HealthCommand::Status, Rc::clone(&apply));
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
}
