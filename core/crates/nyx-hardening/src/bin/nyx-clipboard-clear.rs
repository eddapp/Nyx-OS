//! nyx-clipboard-clear — clears the X11 clipboard after it's sat unchanged
//! for too long, so a copied password/secret doesn't linger indefinitely.
//!
//! Deliberately NOT part of the root `nyx-hardening` binary: this has to
//! run as the logged-in desktop user (it reads/writes *that* user's X11
//! clipboard selection), never as root, so it's its own binary meant to
//! be run as a `systemd --user` service tied to `graphical-session.target`
//! — the real, correct target for a per-session GUI helper (it's only
//! reached once a graphical session actually exists, and stops when it
//! ends), rather than the default-on `default.target`.
//!
//! Mechanism: NyxOS's desktop profile is XFCE/X11 and already packages
//! `xclip` (`iso/packages.x86_64`). `xclip -o -selection clipboard` reads
//! the current CLIPBOARD selection (the one Ctrl+C/Ctrl+V use — X11 has
//! three selections; PRIMARY and SECONDARY are intentionally left alone,
//! since clearing those out from under a live mouse-selection would be
//! actively annoying rather than a privacy win). Every `POLL_INTERVAL`,
//! the current content is compared against what was last seen; once it
//! has been non-empty and unchanged for `timeout_secs`, it's overwritten
//! with an empty string via `xclip -selection clipboard` fed empty stdin
//! (the real equivalent of `echo -n | xclip -selection clipboard`).
//! Clearing happens once per "still the same secret" streak, not on every
//! poll tick once the timeout has passed.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "nyx-clipboard-clear",
    about = "Clears the X11 CLIPBOARD selection after it's been idle for a configurable timeout"
)]
struct Cli {
    /// Seconds of unchanged clipboard content before it's cleared.
    #[arg(long, default_value_t = 45)]
    timeout_secs: u64,
    /// How often to poll the clipboard, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,
}

/// `xclip -o -selection clipboard` — the real invocation to read the
/// current CLIPBOARD selection. `None` covers both "xclip isn't
/// installed/DISPLAY unreachable" and "clipboard has no owner right now"
/// (xclip exits non-zero in that case) — both are treated the same way:
/// nothing actionable to track this tick.
fn read_clipboard() -> Option<String> {
    let output = Command::new("xclip")
        .args(["-o", "-selection", "clipboard"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The real equivalent of `echo -n | xclip -selection clipboard`: spawn
/// xclip with empty stdin so it takes ownership of CLIPBOARD with empty
/// content (xclip forks into the background to hold the selection once
/// it has read stdin to EOF, so this returns promptly).
fn clear_clipboard() {
    let Ok(mut child) = Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"");
    }
    let _ = child.wait();
}

fn main() {
    nyx_core::logging::init();

    if nix::unistd::Uid::effective().is_root() {
        nyx_core::output::print_error(
            "nyx-clipboard-clear",
            "root-check",
            "refusing to run as root — it must run as the logged-in desktop user against that \
             user's own X11 session",
        );
        std::process::exit(1);
    }

    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout_secs);
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);

    // Most single-seat XFCE/LightDM sessions land on display :0 with
    // ~/.Xauthority — a reasonable fallback if the systemd --user
    // environment wasn't seeded with DISPLAY/XAUTHORITY (that seeding is
    // the desktop session's job, e.g. via
    // `dbus-update-activation-environment --systemd DISPLAY XAUTHORITY`;
    // this fallback just keeps the service from being dead on arrival if
    // that hasn't been wired up).
    // Safety: this process is still single-threaded at startup (no worker
    // threads spawned yet), which is exactly what makes mutating the
    // environment here sound.
    unsafe {
        if std::env::var_os("DISPLAY").is_none() {
            std::env::set_var("DISPLAY", ":0");
        }
        if std::env::var_os("XAUTHORITY").is_none()
            && let Some(home) = std::env::var_os("HOME")
        {
            let candidate = Path::new(&home).join(".Xauthority");
            if candidate.exists() {
                std::env::set_var("XAUTHORITY", candidate);
            }
        }
    }

    tracing::info!("nyx-clipboard-clear watching CLIPBOARD, {}s idle timeout", cli.timeout_secs);

    let mut last_seen = String::new();
    let mut last_changed = Instant::now();
    let mut cleared_since_last_change = false;

    loop {
        std::thread::sleep(poll_interval);

        match read_clipboard() {
            Some(text) if !text.is_empty() => {
                if text != last_seen {
                    last_seen = text;
                    last_changed = Instant::now();
                    cleared_since_last_change = false;
                } else if !cleared_since_last_change && last_changed.elapsed() >= timeout {
                    clear_clipboard();
                    tracing::info!("cleared clipboard after {}s idle", cli.timeout_secs);
                    last_seen.clear();
                    cleared_since_last_change = true;
                }
            }
            _ => {
                // Empty or unreadable: nothing to track. Reset so the
                // next non-empty copy starts a fresh timeout window.
                last_seen.clear();
                cleared_since_last_change = false;
            }
        }
    }
}
