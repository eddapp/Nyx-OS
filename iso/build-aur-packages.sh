#!/usr/bin/env bash
# Builds AUR-only packages and drops them into the same local file:// pacman
# repo that iso/build.sh's NYX_PACKAGES loop uses (PKGDEST="$LOCAL_REPO_DIR"),
# then indexes them with repo-add — the exact mechanism build.sh already
# uses for NyxOS's own packages, just pointed at aur.archlinux.org checkouts
# instead of install/pkgbuild/ dirs.
#
# Wired into iso/build.sh (see the NYX_PACKAGES build loop there). Original
# motivating case for this file was packaging LibreWolf: it turned out
# LibreWolf ships straight from Arch's own [extra] repo instead, so no AUR
# step was needed for it after all. The real, current need is
# `zen-browser-bin` — NyxOS's default browser as of this build — which has
# no official or BlackArch package at all; confirmed via
# `aur.archlinux.org/rpc/v5/info` that the AUR entry is real, current, and
# ships a prebuilt release tarball (not a from-source Firefox-scale build,
# which has no place in an ISO pipeline).
#
# Usage:
#
#   source "$PROFILE_DIR/build-aur-packages.sh"
#   build_aur_packages "$LOCAL_REPO_DIR"
#
# Same safety conventions as build.sh: refuses to run as root (makepkg
# refuses too, but this fails fast with a clearer message), set -euo
# pipefail, and idempotent — safe to re-run. A re-run reuses each AUR
# package's existing git checkout (fetch + hard-reset to origin's default
# branch instead of a fresh clone) and rebuilds with the same -f/--noconfirm
# convention build.sh's own NYX_PACKAGES loop uses, so re-running always
# converges on the same end state rather than erroring on "already exists".
# AUR_PACKAGES_CLEAN=1 in the environment wipes the scratch git checkouts
# first, mirroring build.sh's own --clean flag for its work/out/local-repo
# dirs (kept as an env var rather than a second positional arg so this
# script's only required input stays the one $LOCAL_REPO_DIR path).

set -euo pipefail

# One AUR package name per line (the AUR git repo name — usually, but not
# always, identical to the built package's pkgname).
AUR_PACKAGES=(
    zen-browser-bin
    amneziawg-tools
    amneziawg-dkms
    hysteria-bin
)

# build_aur_packages <local_repo_dir>
#
# Clones/updates every name in AUR_PACKAGES under a scratch dir next to this
# script, builds each with makepkg straight into <local_repo_dir>, and
# indexes the result with repo-add so mkarchiso's [nyxos] repo (built by
# iso/build.sh) can pull it in exactly like a NyxOS-native package.
build_aur_packages() {
    local local_repo_dir="${1:-}"

    if [[ -z "$local_repo_dir" ]]; then
        echo "build_aur_packages: usage: build_aur_packages <local_repo_dir>" >&2
        return 1
    fi

    if [[ "$EUID" -eq 0 ]]; then
        echo "build_aur_packages: do not run as root — makepkg refuses to build as root, see iso/build.sh's header comment" >&2
        return 1
    fi

    if [[ ${#AUR_PACKAGES[@]} -eq 0 ]]; then
        echo "build_aur_packages: AUR_PACKAGES is empty, nothing to build"
        return 0
    fi

    for bin in git makepkg repo-add; do
        command -v "$bin" &>/dev/null || {
            echo "build_aur_packages: required tool '$bin' not found on PATH" >&2
            return 1
        }
    done

    local script_dir aur_work_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    aur_work_dir="$script_dir/aur-work"

    if [[ "${AUR_PACKAGES_CLEAN:-0}" == "1" ]]; then
        rm -rf "$aur_work_dir"
    fi

    mkdir -p "$aur_work_dir" "$local_repo_dir"

    local pkg pkg_dir
    for pkg in "${AUR_PACKAGES[@]}"; do
        pkg_dir="$aur_work_dir/$pkg"

        if [[ -d "$pkg_dir/.git" ]]; then
            # Idempotent re-run: update the existing checkout in place rather
            # than re-cloning (or erroring because the dir already exists).
            git -C "$pkg_dir" fetch --quiet origin
            git -C "$pkg_dir" reset --quiet --hard origin/HEAD
            git -C "$pkg_dir" clean --quiet -fdx
        else
            rm -rf "$pkg_dir"
            git clone --quiet "https://aur.archlinux.org/${pkg}.git" "$pkg_dir"
        fi

        # -s/--syncdeps beyond build.sh's own "-f --noconfirm" convention:
        # NYX_PACKAGES' makedepends are all already covered by
        # packages.x86_64/the build host, but an AUR PKGBUILD's makedepends
        # are arbitrary and can't be assumed pre-installed, so this build
        # needs pacman's own dependency resolution turned on to be reliable.
        (cd "$pkg_dir" && PKGDEST="$local_repo_dir" makepkg -f -s --noconfirm)
    done

    repo-add "$local_repo_dir/nyxos.db.tar.gz" "$local_repo_dir"/*.pkg.tar.zst
}
