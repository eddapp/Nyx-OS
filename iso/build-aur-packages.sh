#!/usr/bin/env bash
# Builds AUR-only packages and drops them into the same local file:// pacman
# repo that iso/build.sh's NYX_PACKAGES loop uses (PKGDEST="$LOCAL_REPO_DIR"),
# then indexes them with repo-add — the exact mechanism build.sh already
# uses for NyxOS's own packages, just pointed at aur.archlinux.org checkouts
# instead of install/pkgbuild/ dirs.
#
# Not currently wired into iso/build.sh. Original motivating case for this
# file was packaging LibreWolf: it turned out LibreWolf now ships straight
# from Arch's own [extra] repo (`pacman -Si librewolf` on this build host
# resolves to Repository: extra, packaged by an official Arch dev) and the
# librewolf-bin/librewolf AUR packages have been removed from the AUR
# entirely (checked both `aur.archlinux.org/rpc/v5/info` and a name search —
# zero hits). So AUR_PACKAGES is intentionally empty below: there is no
# NyxOS-needed AUR-only package right now. This script is kept anyway as
# real, working, general infrastructure for the next one, rather than
# hard-coding a package name that would make every build fail on a 404
# git clone.
#
# Usage, once NyxOS actually needs an AUR-only package (add its name to
# AUR_PACKAGES below first), wired into iso/build.sh with:
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
# always, identical to the built package's pkgname). Empty right now — see
# the header comment above for why.
AUR_PACKAGES=(
    # librewolf-bin  # removed from the AUR; librewolf ships in [extra] now
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
