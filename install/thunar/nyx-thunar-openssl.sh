#!/usr/bin/env bash
# NyxOS Thunar action: OpenSSL Encrypt/Decrypt. Invoked with a leading mode
# argument ("encrypt" or "decrypt") from two separate uca.xml entries that
# both point at this one script. Same passphrase-via-stdin discipline as
# the GPG actions — piped straight into openssl via -pass fd:0, never
# written to a temp file.
#
# -pbkdf2 is passed explicitly on encrypt: without it, current openssl
# falls back to a legacy, weaker key-derivation scheme for -aes-256-cbc and
# warns on stderr that it did so. -pbkdf2 must also be passed on decrypt so
# openssl knows to use the same KDF path when re-deriving the key.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 2 ]] || nyx_die "usage: nyx-thunar-openssl.sh <encrypt|decrypt> <file...>"
mode=$1
shift
command -v openssl &>/dev/null || nyx_die "openssl is not installed"

case "$mode" in
    encrypt|decrypt) ;;
    *) nyx_die "unknown mode: $(nyx_esc "$mode")" ;;
esac

passphrase=$(zenity --password --title="NyxOS OpenSSL $mode" 2>/dev/null) || exit 0
[[ -n "$passphrase" ]] || nyx_die "empty passphrase"

fail=0
for f in "$@"; do
    if [[ ! -f "$f" ]]; then
        fail=1
        continue
    fi

    if [[ "$mode" == encrypt ]]; then
        out="${f}.enc"
        op=(-e)
    else
        out="${f%.enc}"
        [[ "$out" != "$f" ]] || out="${f}.dec"
        op=(-d)
    fi

    if [[ -e "$out" ]]; then
        nyx_confirm "NyxOS OpenSSL $mode" \
            "$(nyx_esc "$(basename -- "$out")") already exists. Overwrite it?" \
            || continue
    fi

    err_out=$(printf '%s' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -salt "${op[@]}" \
        -pass fd:0 -in "$f" -out "$out" 2>&1)
    status=$?
    if [[ $status -ne 0 ]]; then
        fail=1
        echo "nyx-thunar: openssl $mode failed for $f (exit $status): $err_out" >&2
    fi
done
unset passphrase

if [[ $fail -eq 0 ]]; then
    nyx_notify "OpenSSL $mode complete ($# file(s))."
else
    nyx_die "openssl $mode failed on one or more files — wrong passphrase, or not a valid openssl-encrypted file. See the terminal/system log for the exact openssl error."
fi
