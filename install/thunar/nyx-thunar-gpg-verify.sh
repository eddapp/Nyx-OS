#!/usr/bin/env bash
# NyxOS Thunar action: GPG Verify. Verifies a detached signature against
# its data file, inferring the data file by stripping the .sig/.asc
# extension when that file exists, prompting via a file picker otherwise.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no signature file selected"
command -v gpg &>/dev/null || nyx_die "gpg is not installed"

sigfile=$1
datafile=""
case "$sigfile" in
    *.sig) datafile="${sigfile%.sig}" ;;
    *.asc) datafile="${sigfile%.asc}" ;;
esac

if [[ -z "$datafile" || ! -f "$datafile" ]]; then
    datafile=$(zenity --file-selection \
        --title="NyxOS GPG Verify — select the signed file for $(basename -- "$sigfile")" 2>/dev/null)
    [[ -n "$datafile" ]] || exit 0
fi

[[ -f "$datafile" ]] || nyx_die "no such file: $(nyx_esc "$(basename -- "$datafile")")"

verify_output=$(gpg --verify -- "$sigfile" "$datafile" 2>&1)
status=$?

header="Signature check for $(basename -- "$datafile")"
body=$(nyx_esc "$verify_output")

if [[ $status -eq 0 ]]; then
    zenity --info --title="NyxOS GPG Verify" \
        --text="$(nyx_esc "$header — VALID.")"$'\n\n'"$body" 2>/dev/null
else
    zenity --error --title="NyxOS GPG Verify" \
        --text="$(nyx_esc "$header — FAILED.")"$'\n\n'"$body" 2>/dev/null
    exit 1
fi
