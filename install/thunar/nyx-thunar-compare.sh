#!/usr/bin/env bash
# NyxOS Thunar action: Compare Files. Unified diff between exactly two
# selected files, shown via zenity's scrollable --text-info rather than a
# plain --info dialog since diff output can run long.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -eq 2 ]] || nyx_die "select exactly 2 files to compare (got $#)"
command -v diff &>/dev/null || nyx_die "diff is not installed"

diff_out=$(diff -u -- "$1" "$2")
status=$?

if [[ $status -eq 0 ]]; then
    zenity --info --title="NyxOS Compare Files" \
        --text="$(nyx_esc "$(basename -- "$1") and $(basename -- "$2") are identical.")" 2>/dev/null
elif [[ $status -eq 1 ]]; then
    printf '%s\n' "$diff_out" | zenity --text-info \
        --title="NyxOS Compare Files: $(basename -- "$1") vs $(basename -- "$2")" \
        --width=800 --height=600 2>/dev/null
else
    nyx_die "diff failed (exit $status) — one of the selected files may be unreadable or a directory"
fi
