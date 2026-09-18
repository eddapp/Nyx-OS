#!/usr/bin/env bash
# NyxOS Thunar action: GPG Encrypt. Symmetric AES256 encryption via gpg.
# The passphrase is piped straight into gpg's stdin (--passphrase-fd 0) and
# is NEVER written to a temp file, not even briefly — a shell pipe is an
# in-kernel buffer, not disk. Bash heredocs/herestrings are NOT used here
# for exactly that reason: bash implements them via an unlinked temp file
# under the hood, which is the mistake this script deliberately avoids.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"
command -v gpg &>/dev/null || nyx_die "gpg is not installed"

passphrase=$(zenity --password --title="NyxOS GPG Encrypt" 2>/dev/null) || exit 0
[[ -n "$passphrase" ]] || nyx_die "empty passphrase"

fail=0
for f in "$@"; do
    if [[ ! -f "$f" ]]; then
        fail=1
        continue
    fi

    out="${f}.gpg"
    if [[ -e "$out" ]]; then
        nyx_confirm "NyxOS GPG Encrypt" \
            "$(nyx_esc "$(basename -- "$out")") already exists. Overwrite it?" \
            || continue
    fi

    if ! printf '%s' "$passphrase" | gpg --batch --yes --pinentry-mode loopback \
            --passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$out" -- "$f"; then
        fail=1
        echo "nyx-thunar: gpg encrypt failed for $f" >&2
    fi
done
unset passphrase

if [[ $fail -eq 0 ]]; then
    nyx_notify "GPG encryption complete ($# file(s))."
else
    nyx_die "gpg failed to encrypt one or more files"
fi
