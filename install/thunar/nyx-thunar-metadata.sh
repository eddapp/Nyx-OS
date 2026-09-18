#!/usr/bin/env bash
# NyxOS Thunar action: Strip Metadata. Uses mat2 (deep, format-aware
# sanitizer) in place. Destructive — the original metadata is not
# recoverable afterwards, so this asks first.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"
command -v mat2 &>/dev/null || nyx_die "mat2 is not installed"

nyx_confirm "NyxOS Strip Metadata" \
    "Remove metadata (EXIF, GPS, author, timestamps, and more) from $# file(s) in place?\n\nThe original metadata cannot be recovered afterwards." \
    || exit 0

fail=0
for f in "$@"; do
    mat2 --inplace "$f" || fail=1
done

if [[ $fail -eq 0 ]]; then
    nyx_notify "Metadata stripped from $# file(s)."
else
    nyx_die "mat2 failed on one or more files — they may be a format it doesn't support"
fi
