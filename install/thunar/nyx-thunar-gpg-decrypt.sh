#!/usr/bin/env bash
# NyxOS Thunar action: GPG Decrypt. Same passphrase-via-stdin discipline as
# GPG Encrypt — piped straight into gpg via --passphrase-fd 0, never
# written to a temp file. Works for both symmetric and public-key
# encrypted input: in batch+loopback mode gpg reads whatever passphrase it
# needs (symmetric passphrase, or the matching private key's passphrase)
# from this same fd.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no files selected"
command -v gpg &>/dev/null || nyx_die "gpg is not installed"

passphrase=$(zenity --password --title="NyxOS GPG Decrypt" 2>/dev/null) || exit 0
[[ -n "$passphrase" ]] || nyx_die "empty passphrase"

fail=0
for f in "$@"; do
    if [[ ! -f "$f" ]]; then
        fail=1
        continue
    fi

    out=$f
    case "$f" in
        *.gpg) out="${f%.gpg}" ;;
        *.asc) out="${f%.asc}" ;;
    esac
    [[ "$out" != "$f" ]] || out="${f}.decrypted"

    if [[ -e "$out" ]]; then
        nyx_confirm "NyxOS GPG Decrypt" \
            "$(nyx_esc "$(basename -- "$out")") already exists. Overwrite it with the decrypted output?" \
            || continue
    fi

    if ! printf '%s' "$passphrase" | gpg --batch --yes --pinentry-mode loopback \
            --passphrase-fd 0 --decrypt -o "$out" -- "$f"; then
        fail=1
        echo "nyx-thunar: gpg decrypt failed for $f" >&2
    fi
done
unset passphrase

if [[ $fail -eq 0 ]]; then
    nyx_notify "GPG decryption complete. The decrypted plaintext was written to disk unencrypted — wipe it (NyxOS Secure Wipe) once you're done with it."
else
    nyx_die "gpg failed to decrypt one or more files — wrong passphrase, or not a valid GPG-encrypted file"
fi
