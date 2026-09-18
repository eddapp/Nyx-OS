#!/usr/bin/env bash
# Generates (once) and uses a dedicated GnuPG signing key for NyxOS's own
# build output: a detached signature for every .pkg.tar.zst this build
# produces, a signed [nyxos] repo database, and a signed build manifest for
# the final ISO.
#
# The signing key lives in its own GNUPGHOME under the profile dir
# (NYX_GPG_HOME below) -- never the invoking developer's own ~/.gnupg. It is
# generated non-interactively the first time a build needs it and reused on
# every later build on the same machine. That directory holds private key
# material; it is listed in .gitignore and must never be committed.
#
# Wired into iso/build.sh as:
#
#   source "$PROFILE_DIR/sign-packages.sh"
#   ensure_nyx_signing_key                              # sets NYX_SIGN_KEY_FPR
#   trust_nyx_signing_key_on_host                        # pacman-key --add/--lsign-key
#   sign_nyx_packages "$LOCAL_REPO_DIR"                   # per-package .sig files
#   sign_nyx_repo_db "$LOCAL_REPO_DIR" "nyxos.db.tar.gz"  # signed repo database
#   write_and_sign_build_manifest "$iso_file" "$OUT_DIR"  # signed ISO manifest
#
# Same conventions as build.sh/build-aur-packages.sh: set -euo pipefail,
# refuses to run as root (gpg's keyring/homedir model is per-user, and this
# whole pipeline already runs as the invoking user for the same reason
# makepkg does), and idempotent -- safe to source and call repeatedly.

set -euo pipefail

# PROFILE_DIR and LOCAL_REPO_DIR come from the sourcing script (build.sh).
NYX_GPG_HOME="${NYX_GPG_HOME:-$PROFILE_DIR/nyx-signing-gpg}"
NYX_SIGN_KEY_NAME="NyxOS Build Signing Key"
NYX_SIGN_KEY_EMAIL="build@nyxos.local"
NYX_SIGN_KEY_COMMENT="automated NyxOS ISO/package signing key -- do not use for personal correspondence"

# Populated by ensure_nyx_signing_key; every other function here requires it.
NYX_SIGN_KEY_FPR=""

# ensure_nyx_signing_key
#
# Creates $NYX_GPG_HOME (mode 700, which gpg refuses to use a homedir
# without) and, if it doesn't already contain a NyxOS build-signing key,
# generates a passphrase-less RSA-4096 signing-only key in it using gpg's
# real unattended-generation batch-file format (`gpg --batch --gen-key
# <file>` -- distinct from `gpg --quick-gen-key`, which takes the same
# information as CLI arguments instead of a batch file). The key carries no
# passphrase (`%no-protection`) because it has to sign packages/databases
# unattended during an automated build; that is exactly why it must never be
# the developer's own personal key, and why it lives in an isolated
# GNUPGHOME instead of ~/.gnupg.
ensure_nyx_signing_key() {
    if [[ "$EUID" -eq 0 ]]; then
        echo "ensure_nyx_signing_key: do not run as root -- see iso/build.sh's header comment" >&2
        return 1
    fi

    command -v gpg &>/dev/null || {
        echo "ensure_nyx_signing_key: gpg not found on PATH (is the 'gnupg' package installed on the build host?)" >&2
        return 1
    }

    mkdir -p "$NYX_GPG_HOME"
    chmod 700 "$NYX_GPG_HOME"

    if ! GNUPGHOME="$NYX_GPG_HOME" gpg --batch --list-secret-keys "$NYX_SIGN_KEY_EMAIL" &>/dev/null; then
        echo "sign-packages: no existing NyxOS build-signing key in $NYX_GPG_HOME, generating one..."

        local batch_file
        batch_file="$(mktemp)"
        # shellcheck disable=SC2064  # intentional: capture batch_file's value now
        trap "rm -f '$batch_file'" RETURN

        cat > "$batch_file" <<EOF
%echo Generating NyxOS build-signing key
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: $NYX_SIGN_KEY_NAME
Name-Comment: $NYX_SIGN_KEY_COMMENT
Name-Email: $NYX_SIGN_KEY_EMAIL
Expire-Date: 2y
%no-protection
%commit
%echo NyxOS build-signing key generated
EOF
        GNUPGHOME="$NYX_GPG_HOME" gpg --batch --gen-key "$batch_file"
    fi

    NYX_SIGN_KEY_FPR="$(GNUPGHOME="$NYX_GPG_HOME" gpg --batch --list-secret-keys --with-colons --fingerprint "$NYX_SIGN_KEY_EMAIL" \
        | awk -F: '$1 == "fpr" { print $10; exit }')"

    [[ -n "$NYX_SIGN_KEY_FPR" ]] || {
        echo "ensure_nyx_signing_key: failed to determine the fingerprint of the NyxOS build-signing key" >&2
        return 1
    }

    echo "sign-packages: using NyxOS build-signing key $NYX_SIGN_KEY_FPR"
}

# trust_nyx_signing_key_on_host
#
# Exports the NyxOS build-signing public key and imports + locally signs it
# into the *build host's* system pacman keyring (/etc/pacman.d/gnupg -- the
# same keyring pacstrap/mkarchiso consult to verify repo packages during ISO
# assembly), mirroring exactly the BLACKARCH_KEY block in build.sh: a
# `pacman-key --list-keys` existence check, then `--add` + `--lsign-key`.
# Call this after ensure_nyx_signing_key has populated NYX_SIGN_KEY_FPR.
trust_nyx_signing_key_on_host() {
    [[ -n "$NYX_SIGN_KEY_FPR" ]] || {
        echo "trust_nyx_signing_key_on_host: NYX_SIGN_KEY_FPR is empty -- call ensure_nyx_signing_key first" >&2
        return 1
    }

    mkdir -p "$LOCAL_REPO_DIR"
    local pubkey_file="$LOCAL_REPO_DIR/nyxos-build-signing-key.asc"
    GNUPGHOME="$NYX_GPG_HOME" gpg --batch --yes --armor --export "$NYX_SIGN_KEY_FPR" > "$pubkey_file"

    if ! sudo pacman-key --list-keys "$NYX_SIGN_KEY_FPR" &>/dev/null; then
        sudo pacman-key --add "$pubkey_file"
        sudo pacman-key --lsign-key "$NYX_SIGN_KEY_FPR"
    fi
}

# sign_nyx_packages <local_repo_dir>
#
# Detached-signs (binary, unarmored -- the exact format pacman/repo-add
# expect for a package's companion `<pkgfile>.sig`, as opposed to the
# ASCII-armored .asc used for the human-facing build manifest below) every
# *.pkg.tar.zst currently sitting in <local_repo_dir>. This is a distinct
# mechanism from database signing (sign_nyx_repo_db): pacman checks a
# package's own .sig against "Package" SigLevel, and the repo database's
# .sig separately against "Database" SigLevel -- a repo can have one
# without the other, and both are wired here. Re-run-safe: --yes overwrites
# any stale .sig left over from a previous build.
sign_nyx_packages() {
    local local_repo_dir="${1:-}"
    [[ -n "$local_repo_dir" ]] || {
        echo "sign_nyx_packages: usage: sign_nyx_packages <local_repo_dir>" >&2
        return 1
    }
    [[ -n "$NYX_SIGN_KEY_FPR" ]] || {
        echo "sign_nyx_packages: NYX_SIGN_KEY_FPR is empty -- call ensure_nyx_signing_key first" >&2
        return 1
    }

    local pkg_file signed_any=0
    for pkg_file in "$local_repo_dir"/*.pkg.tar.zst; do
        [[ -e "$pkg_file" ]] || continue
        GNUPGHOME="$NYX_GPG_HOME" gpg --batch --yes --detach-sign --no-armor \
            -u "$NYX_SIGN_KEY_FPR" -o "${pkg_file}.sig" "$pkg_file"
        signed_any=1
    done

    if [[ "$signed_any" -eq 0 ]]; then
        echo "sign_nyx_packages: no *.pkg.tar.zst found in $local_repo_dir" >&2
        return 1
    fi
}

# sign_nyx_repo_db <local_repo_dir> <db_basename>
#
# Re-indexes <db_basename> (e.g. nyxos.db.tar.gz) over every package
# currently in <local_repo_dir> and signs the resulting database with the
# NyxOS build-signing key, via repo-add's own -s/--sign (sign after update)
# and -k/--key (which key to sign with) flags -- the documented, current
# repo-add mechanism for database-level signing (see `man repo-add`; this is
# a separate signature from the per-package ones sign_nyx_packages writes).
# Re-run-safe: repo-add itself is idempotent over an existing db, and this
# is intentionally called again after any AUR packages have been built and
# repo-add'ed by build_aur_packages, so the final signed database covers
# every package the [nyxos] repo will actually serve.
sign_nyx_repo_db() {
    local local_repo_dir="${1:-}" db_basename="${2:-}"
    [[ -n "$local_repo_dir" && -n "$db_basename" ]] || {
        echo "sign_nyx_repo_db: usage: sign_nyx_repo_db <local_repo_dir> <db_basename>" >&2
        return 1
    }
    [[ -n "$NYX_SIGN_KEY_FPR" ]] || {
        echo "sign_nyx_repo_db: NYX_SIGN_KEY_FPR is empty -- call ensure_nyx_signing_key first" >&2
        return 1
    }

    local -a pkg_files=("$local_repo_dir"/*.pkg.tar.zst)
    [[ -e "${pkg_files[0]}" ]] || {
        echo "sign_nyx_repo_db: no *.pkg.tar.zst found in $local_repo_dir" >&2
        return 1
    }

    GNUPGHOME="$NYX_GPG_HOME" repo-add -s -k "$NYX_SIGN_KEY_FPR" \
        "$local_repo_dir/$db_basename" "${pkg_files[@]}"
}

# write_and_sign_build_manifest <iso_file> <out_dir>
#
# Writes a plain-text manifest (filename, byte size, sha256, git commit of
# this repo at build time, build timestamp) for the just-built ISO into
# <out_dir>, then produces an ASCII-armored detached GPG signature of that
# manifest with the NyxOS build-signing key.
#
# Verification for someone downloading the ISO: import
# local-repo/nyxos-build-signing-key.asc (or a copy of it published
# alongside the ISO), check the manifest's signature against it
# (`gpg --verify <manifest>.asc <manifest>`), then confirm the ISO's own
# sha256 matches the sha256 line inside that now-verified manifest.
write_and_sign_build_manifest() {
    local iso_file="${1:-}" out_dir="${2:-}"
    [[ -n "$iso_file" && -f "$iso_file" && -n "$out_dir" ]] || {
        echo "write_and_sign_build_manifest: usage: write_and_sign_build_manifest <iso_file> <out_dir>" >&2
        return 1
    }
    [[ -n "$NYX_SIGN_KEY_FPR" ]] || {
        echo "write_and_sign_build_manifest: NYX_SIGN_KEY_FPR is empty -- call ensure_nyx_signing_key first" >&2
        return 1
    }
    command -v git &>/dev/null || {
        echo "write_and_sign_build_manifest: git not found on PATH" >&2
        return 1
    }

    local iso_basename iso_size iso_sha256 git_commit build_ts manifest_file epoch
    iso_basename="$(basename "$iso_file")"
    iso_size="$(stat -c '%s' "$iso_file")"
    iso_sha256="$(sha256sum "$iso_file" | awk '{print $1}')"
    git_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    epoch="${SOURCE_DATE_EPOCH:-$(date +%s)}"
    build_ts="$(date -u -d "@${epoch}" '+%Y-%m-%dT%H:%M:%SZ')"
    manifest_file="$out_dir/${iso_basename}.manifest"

    cat > "$manifest_file" <<EOF
filename=$iso_basename
size_bytes=$iso_size
sha256=$iso_sha256
git_commit=$git_commit
build_timestamp_utc=$build_ts
EOF

    GNUPGHOME="$NYX_GPG_HOME" gpg --batch --yes --armor --detach-sign \
        -u "$NYX_SIGN_KEY_FPR" -o "${manifest_file}.asc" "$manifest_file"

    echo "sign-packages: wrote signed build manifest $manifest_file (+ ${manifest_file}.asc)"
}
