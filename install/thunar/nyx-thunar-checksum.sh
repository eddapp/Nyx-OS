#!/usr/bin/env bash
# NyxOS Thunar action: SHA-256 Checksum. Read-only, no confirmation needed.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"
command -v sha256sum &>/dev/null || nyx_die "sha256sum is not installed"

out=""
for f in "$@"; do
    sum=$(sha256sum -- "$f" 2>/dev/null | awk '{print $1}')
    out+="$(nyx_esc "$(basename "$f")"): ${sum:-error reading file}"$'\n'
done

if command -v zenity &>/dev/null; then
    zenity --info --title="SHA-256" --text="$out" --no-wrap 2>/dev/null
else
    printf '%s' "$out"
fi
