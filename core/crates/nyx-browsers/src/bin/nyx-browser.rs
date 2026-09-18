//! Nyx Browser — everyday hardened browsing. Wraps Zen Browser with its
//! own dedicated, persistent profile directory under
//! `$XDG_DATA_HOME/nyx/browsers/browser`, isolated from any other Zen
//! profile on the system (including the raw `zen-browser` command a user
//! might also have on their PATH). This is NyxOS's default browser and
//! the system default handler for HTML/HTTP/HTTPS — see the shipped
//! `mimeapps.list`.

const BINARY: &str = "nyx-browser";

fn main() {
    nyx_core::logging::init();

    let profile = nyx_browsers::persistent_profile_dir("browser")
        .unwrap_or_else(|e| nyx_browsers::fail(BINARY, &format!("failed to prepare profile directory: {e}")));

    tracing::info!("launching Zen Browser with persistent Nyx profile at {}", profile.display());

    let mut args = vec!["--profile".to_string(), profile.display().to_string()];
    args.extend(std::env::args().skip(1));

    let err = nyx_browsers::exec_replace("zen-browser", &args);
    nyx_browsers::fail(BINARY, &format!("failed to exec zen-browser: {err}"));
}
