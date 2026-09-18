#!/usr/bin/env bash
# NyxOS Thunar action: Entropy Analysis. Runs ent(1) on the selected file
# and shows its report. Shannon entropy close to 8 bits/byte is what
# compressed or genuinely encrypted data reads as; a file that *claims* to
# be encrypted (by name or extension) but reads with low entropy is a real
# signal something is wrong — plaintext padding, a broken cipher mode, or
# it simply isn't encrypted at all.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no file selected"
target=$1
[[ -f "$target" ]] || nyx_die "not a regular file: $(nyx_esc "$(basename -- "$target")")"
command -v ent &>/dev/null || nyx_die "ent is not installed"

output=$(ent "$target" 2>&1) || nyx_die "ent failed: $(nyx_esc "$output")"

zenity --info --title="NyxOS Entropy Analysis: $(basename -- "$target")" \
    --text="$(nyx_esc "$output")" --no-wrap 2>/dev/null
