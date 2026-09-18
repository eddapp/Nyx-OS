#!/usr/bin/env bash
# NyxOS Thunar action: GPG Sign. Detached signatures (--detach-sign) rather
# than clearsign, since clearsign only round-trips text and this menu entry
# has to work for arbitrary file types. No passphrase handling here — the
# signing key's own passphrase prompt is left to gpg-agent's real pinentry
# (not --batch/--pinentry-mode loopback), which is the secure, standard
# path for unlocking a secret key.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"
command -v gpg &>/dev/null || nyx_die "gpg is not installed"

mapfile -t _sec_lines < <(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep '^sec')
[[ ${#_sec_lines[@]} -ge 1 ]] || nyx_die "no GPG secret keys found — generate one with 'gpg --full-generate-key' first"

keyid=""
if [[ ${#_sec_lines[@]} -eq 1 ]]; then
    keyid=$(grep -oE '[0-9A-F]{16}' <<<"${_sec_lines[0]}" | head -n1)
else
    mapfile -t _uid_lines < <(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep '^uid' | sed -E 's/^uid +[^ ]+ //')
    list_args=(--list --title="NyxOS GPG Sign" --text="Multiple secret keys found — choose one to sign with:" \
        --column="Key ID" --column="User ID")
    i=0
    for line in "${_sec_lines[@]}"; do
        kid=$(grep -oE '[0-9A-F]{16}' <<<"$line" | head -n1)
        uid=${_uid_lines[$i]:-"(unknown)"}
        list_args+=("$kid" "$(nyx_esc "$uid")")
        i=$((i + 1))
    done
    keyid=$(zenity "${list_args[@]}" 2>/dev/null)
    [[ -n "$keyid" ]] || exit 0
fi

fail=0
for f in "$@"; do
    if [[ ! -f "$f" ]]; then
        fail=1
        continue
    fi

    out="${f}.sig"
    if [[ -e "$out" ]]; then
        nyx_confirm "NyxOS GPG Sign" \
            "$(nyx_esc "$(basename -- "$out")") already exists. Overwrite it?" \
            || continue
    fi

    if ! gpg --yes --local-user "$keyid" --detach-sign -o "$out" -- "$f"; then
        fail=1
        echo "nyx-thunar: gpg sign failed for $f" >&2
    fi
done

if [[ $fail -eq 0 ]]; then
    nyx_notify "Detached signature(s) created ($# file(s))."
else
    nyx_die "gpg failed to sign one or more files"
fi
