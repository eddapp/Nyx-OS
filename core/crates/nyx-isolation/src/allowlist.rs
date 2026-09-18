//! The curated identity table for `app:<id>` launches. Deliberately small
//! and hand-reviewed, unlike `profile:<name>` (see `validate.rs`), which is
//! open to any program that already has a root-owned Firejail profile.

pub struct AppSpec {
    pub id: &'static str,
    pub executable: &'static str,
}

/// Every entry here must correspond to a package actually listed in
/// `iso/packages.x86_64` — this table describes what NyxOS ships, not an
/// aspirational list. Extend it as more apps get packaged.
pub const APP_SPECS: &[AppSpec] = &[
    AppSpec { id: "thunar", executable: "/usr/bin/thunar" },
    AppSpec { id: "xfce4-terminal", executable: "/usr/bin/xfce4-terminal" },
    AppSpec { id: "xterm", executable: "/usr/bin/xterm" },
    AppSpec { id: "keepassxc", executable: "/usr/bin/keepassxc" },
];

pub fn find(id: &str) -> Option<&'static AppSpec> {
    APP_SPECS.iter().find(|a| a.id == id)
}
