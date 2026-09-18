#!/usr/bin/env bash
# NyxOS Thunar action: Copy Path. Deliberately does NOT resolve symlinks
# (realpath -s) — the point is "the path I clicked", not its target.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no file selected"
path=$(realpath -s -- "$1")

if command -v xclip &>/dev/null; then
    printf '%s' "$path" | xclip -selection clipboard
elif command -v xsel &>/dev/null; then
    printf '%s' "$path" | xsel --clipboard --input
else
    nyx_die "no clipboard tool (xclip/xsel) installed"
fi
