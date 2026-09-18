//! Nyx Disposable Browser — ephemeral, single-use browsing. Creates a
//! fresh, unique tmpfs-backed profile directory, launches Zen Browser
//! against it, waits for the browser to exit, then securely destroys the
//! profile with `srm -r` (from `secure-delete`) rather than a plain
//! `rm -rf` — the point of "disposable" is leaving no forensic trace,
//! matching this project's existing `nyx-wipe`/`nyx-hardening` philosophy.
//!
//! Unlike the other three launchers this can't exec-replace itself: it
//! has to remain alive after the browser exits in order to run the
//! secure-erase step, so it spawns the browser as a child and waits.

const BINARY: &str = "nyx-disposable-browser";

fn main() {
    nyx_core::logging::init();

    let (profile, tmpfs) = nyx_browsers::disposable_profile_dir()
        .unwrap_or_else(|e| nyx_browsers::fail(BINARY, &format!("failed to create ephemeral profile directory: {e}")));

    if tmpfs {
        tracing::info!("ephemeral profile at {} (tmpfs -- never touches a real disk)", profile.display());
    } else {
        tracing::warn!(
            "ephemeral profile at {} is NOT on tmpfs -- srm -r will still securely overwrite it, \
             just without tmpfs's extra guarantee that it was never written to a real disk",
            profile.display()
        );
    }

    let mut args = vec!["--profile".to_string(), profile.display().to_string()];
    args.extend(std::env::args().skip(1));

    let launch_result = nyx_browsers::spawn_and_wait("zen-browser", &args);

    match &launch_result {
        Ok(status) => tracing::info!("Zen Browser exited with {status}, erasing ephemeral profile"),
        Err(e) => tracing::warn!("failed to launch Zen Browser ({e}), erasing ephemeral profile anyway"),
    }

    let wipe_result = nyx_browsers::secure_delete_dir(&profile);

    let launch_ok = matches!(&launch_result, Ok(status) if status.success());
    let wipe_ok = matches!(&wipe_result, Ok(status) if status.success());

    if !wipe_ok {
        let detail = match wipe_result {
            Ok(status) => format!("srm -r exited with {status}"),
            Err(e) => format!("failed to spawn srm: {e}"),
        };
        nyx_browsers::fail(BINARY, &format!("ephemeral profile at {} may not be fully erased: {detail}", profile.display()));
    }

    if !launch_ok {
        let detail = match launch_result {
            Ok(status) => format!("Zen Browser exited with {status}"),
            Err(e) => format!("failed to launch Zen Browser: {e}"),
        };
        nyx_browsers::fail(BINARY, &detail);
    }
}
