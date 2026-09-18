//! Nyx Oniux Browser — per-application Tor isolation for Zen Browser
//! using the real `oniux` tool (Tor Project, MIT/Apache-2.0): `oniux
//! <command...>` puts the child in its own network/mount/PID/user
//! namespace (via `clone(2)`) and routes it through Tor using
//! Arti+onionmasq, giving it a custom `onion0` interface instead of
//! access to real system interfaces. Uses its own dedicated, persistent
//! profile directory under `$XDG_DATA_HOME/nyx/browsers/oniux`, separate
//! from Nyx Browser's own profile.
//!
//! `oniux`'s own authors call it experimental — "relatively new... using
//! new Tor software such as Arti and onionmasq" — and explicitly not yet
//! as battle-tested as `torsocks`, which has 15+ years in the field. That
//! caveat is surfaced honestly below rather than oversold.

const BINARY: &str = "nyx-oniux-browser";

fn main() {
    nyx_core::logging::init();

    tracing::warn!(
        "oniux is experimental (its own authors' description) and not yet as battle-tested as \
         torsocks -- per-application Tor isolation here is best-effort, not a guarantee"
    );

    let profile = nyx_browsers::persistent_profile_dir("oniux")
        .unwrap_or_else(|e| nyx_browsers::fail(BINARY, &format!("failed to prepare profile directory: {e}")));

    tracing::info!("launching Zen Browser under oniux with persistent Nyx profile at {}", profile.display());

    let mut args = vec!["zen-browser".to_string(), "--profile".to_string(), profile.display().to_string()];
    args.extend(std::env::args().skip(1));

    let err = nyx_browsers::exec_replace("oniux", &args);
    nyx_browsers::fail(BINARY, &format!("failed to exec oniux: {err}"));
}
