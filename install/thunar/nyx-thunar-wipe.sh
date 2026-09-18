#!/usr/bin/env bash
# NyxOS Thunar action: Secure Wipe. All the actual safety logic (protected-
# path blocking, checked BEFORE any confirmation, and the SSD/NVMe honesty
# caveat) lives in nyx-wipe itself — this script is only UI glue.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"

names=""
for f in "$@"; do
    names+="$(nyx_esc "$(basename "$f")")"$'\n'
done

nyx_confirm "NyxOS Secure Wipe" \
    "Permanently destroy these $# file(s)?\n\n${names}\nThis cannot be undone. Protected system paths are refused unconditionally by nyx-wipe, before this confirmation and regardless of it." \
    || exit 0

args=()
for f in "$@"; do
    args+=(--path "$f")
done

if pkexec /usr/bin/nyx-wipe execute "${args[@]}" --yes; then
    nyx_notify "Secure wipe complete."
else
    nyx_die "nyx-wipe reported a failure — run 'nyx-wipe plan --path <file>' in a terminal for details"
fi
