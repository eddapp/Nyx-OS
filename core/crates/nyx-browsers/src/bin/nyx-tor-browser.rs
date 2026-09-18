//! Nyx Tor Browser — thin launcher around the already-packaged
//! `tor-browser` (BlackArch repo). Deliberately does not manage or touch
//! any profile of its own: Tor Browser already has its own correct,
//! deliberately-different security model (profile lives under
//! `~/.local/opt/tor-browser`, managed by its own `/usr/bin/tor-browser`
//! launcher script), and layering Nyx hardening or a Nyx-managed profile
//! on top of it would be a regression, not an improvement. This binary
//! is nothing more than a labeled menu entry that execs the real thing.

const BINARY: &str = "nyx-tor-browser";

fn main() {
    nyx_core::logging::init();

    tracing::info!(
        "launching Tor Browser via its own unmodified launcher and profile -- no Nyx hardening \
         applied on top"
    );

    let args: Vec<String> = std::env::args().skip(1).collect();
    let err = nyx_browsers::exec_replace("tor-browser", &args);
    nyx_browsers::fail(BINARY, &format!("failed to exec tor-browser: {err}"));
}
