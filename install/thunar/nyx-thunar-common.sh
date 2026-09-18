#!/usr/bin/env bash
# Shared helpers for NyxOS Thunar custom-action scripts. Sourced, not run
# directly.
set -u

# Escape a string for safe interpolation into GTK/Pango markup (as zenity's
# --text does). Filenames are attacker-controlled data handed to us by
# Thunar, not trusted text — skipping this can crash or hide the dialog.
nyx_esc() {
    local s=$1
    s=${s//&/&amp;}
    s=${s//</&lt;}
    s=${s//>/&gt;}
    printf '%s' "$s"
}

# Report failure through whatever's available and always exit non-zero —
# never fail silently.
nyx_die() {
    local msg=$1
    if command -v zenity &>/dev/null; then
        zenity --error --title="NyxOS" --text="$(nyx_esc "$msg")" 2>/dev/null
    elif command -v notify-send &>/dev/null; then
        notify-send "NyxOS" "$msg" 2>/dev/null
    fi
    echo "nyx-thunar: $msg" >&2
    exit 1
}

nyx_notify() {
    notify-send "NyxOS" "$1" 2>/dev/null || true
}

# Blocking yes/no confirmation. Returns Thunar-script-friendly exit status:
# 0 = confirmed, 1 = declined.
nyx_confirm() {
    local title=$1 text=$2
    zenity --question --title="$title" --text="$(nyx_esc "$text")" 2>/dev/null
}
