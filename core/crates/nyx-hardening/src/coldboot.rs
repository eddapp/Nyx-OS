//! Cold-boot defense: install/remove a `systemd-sleep` hook that evicts
//! LUKS master keys from kernel memory before every suspend/hibernate
//! (`cryptsetup luksSuspend`) and restores them on resume
//! (`cryptsetup luksResume`).
//!
//! Contract verified against `systemd-sleep(8)`: every executable file
//! under `/usr/lib/systemd/system-sleep/` is run automatically around
//! every sleep transition, invoked as `<script> pre|post <mode>` (`mode`
//! is one of `suspend`/`hibernate`/`hybrid-sleep`/`suspend-then-
//! hibernate`); every "pre" script must finish before the kernel is
//! actually told to sleep, and every "post" script runs once it's back.
//!
//! Real mechanism verified against `cryptsetup(8)`: `luksSuspend <name>`
//! "suspends an active device ... and wipes the encryption key from
//! kernel memory"; `luksResume <name>` "resumes a suspended device and
//! reinstates the encryption key" (re-deriving it from the on-disk LUKS
//! header via passphrase/token/key file). That pairing is the actual,
//! standard mitigation for a machine that gets suspended rather than
//! powered off: without it, every LUKS key sits resident in RAM for as
//! long as the machine is merely asleep — exactly the window a
//! freeze-and-cold-boot RAM-dump attack targets.
//!
//! See the full mechanism, and the deliberate root-filesystem exclusion,
//! in the header comment of [`HOOK_SCRIPT`] below — that comment ships
//! verbatim as part of the installed hook, so anyone auditing the live
//! system sees the same reasoning this module was built from.

use nyx_core::NyxResult;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const HOOK_PATH: &str = "/usr/lib/systemd/system-sleep/nyx-coldboot-luks-suspend.sh";

pub const HOOK_SCRIPT: &str = r#"#!/bin/bash
#
# NyxOS cold-boot defense hook
# ============================
# Installed by `nyx-hardening install-coldboot-hook` into
# /usr/lib/systemd/system-sleep/ — systemd-sleep(8)'s real, documented
# extension point: every executable file here runs automatically around
# every suspend/hibernate, called as "<script> pre|post <mode>" (mode is
# one of suspend/hibernate/hybrid-sleep/suspend-then-hibernate). Every
# "pre" script must finish before the kernel is actually told to sleep;
# every "post" script runs once it's back, before anything else touches
# the resumed devices.
#
# Real mechanism (verified against cryptsetup(8)): `cryptsetup luksSuspend
# <name>` freezes all I/O to that dm-crypt mapping AND wipes its master
# key out of kernel memory; `cryptsetup luksResume <name>` re-derives the
# key from the on-disk LUKS header (passphrase/token/key file) and lets
# I/O through again. That is the actual, standard cold-boot-attack
# mitigation for a machine that gets suspended rather than powered off —
# without it, every LUKS key stays resident in RAM for as long as the
# machine is merely asleep, which is exactly the window a freeze/cold-boot
# RAM-dump attack targets.
#
# Deliberate exclusion: the mapper backing the ROOT filesystem.
# ---------------------------------------------------------------
# luksResume needs an interactive passphrase prompt (or a key file/token)
# to bring a device back. On resume this hook runs with no controlling
# terminal, so `cryptsetup luksResume` on a device that needs a passphrase
# fails closed immediately rather than hanging (no tty => no prompt, per
# cryptsetup(8)'s passphrase-processing notes). That's fine for a
# *secondary* volume — it just stays locked until someone runs
# `cryptsetup luksResume` on it by hand from a real terminal — but fatal
# if it's the root filesystem: the running system, including systemd
# itself, journald, and this very script's own shell, lives on that
# filesystem and cannot tolerate its I/O staying frozen indefinitely. The
# real tools that DO suspend the root LUKS volume (go-luks-suspend,
# arch-luks-suspend) solve this by chrooting into an initramfs — a tmpfs,
# unaffected by the root device being frozen — to run the suspend/resume
# dance and prompt for the passphrase there. That's a much larger
# undertaking than "install a system-sleep hook" and out of scope here.
# So: this hook protects every OTHER active LUKS mapping and deliberately
# leaves root alone rather than risk bricking resume.
#
# What this does NOT cover: key material belonging to the root
# filesystem's own LUKS mapping is untouched by this hook, by design, for
# the reason above. Any other mounted encrypted volume that fails to
# auto-resume (because no passphrase agent is reachable at that moment)
# will need a manual `cryptsetup luksResume <name>` from a real terminal
# after waking — inconvenient, but not system-bricking.

set -u

ACTION="${1:-}"
# "${2:-}" (the sleep mode) is intentionally unused — every mode gets the
# same treatment.

[ "$ACTION" = "pre" ] || [ "$ACTION" = "post" ] || exit 0

ROOT_SOURCE="$(findmnt -no SOURCE / 2>/dev/null || true)"
ROOT_MAPPER=""
case "$ROOT_SOURCE" in
    /dev/mapper/*) ROOT_MAPPER="${ROOT_SOURCE##*/}" ;;
esac

for name in $(dmsetup ls --target crypt 2>/dev/null | awk '{print $1}'); do
    [ "$name" = "$ROOT_MAPPER" ] && continue

    dev_type="$(cryptsetup status "$name" 2>/dev/null | awk '$1=="type:"{print $2}')"
    case "$dev_type" in
        LUKS1|LUKS2) ;;
        *) continue ;;
    esac

    case "$ACTION" in
        pre)  cryptsetup luksSuspend "$name" 2>/dev/null || true ;;
        post) cryptsetup luksResume  "$name" 2>/dev/null || true ;;
    esac
done

exit 0
"#;

pub fn install() -> NyxResult<()> {
    fs::write(HOOK_PATH, HOOK_SCRIPT)?;
    fs::set_permissions(HOOK_PATH, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

pub fn remove() -> NyxResult<bool> {
    let path = Path::new(HOOK_PATH);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

pub fn is_installed() -> bool {
    Path::new(HOOK_PATH).exists()
}
