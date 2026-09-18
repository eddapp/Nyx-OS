#!/usr/bin/env bash
# Builds the NyxOS ISO from this profile.
#
# Run as your normal user (must have sudo) — NOT as root: makepkg refuses to
# build the nyx-health/nyx-dashboard packages as root, so this script uses
# `sudo` only for the individual steps that actually need it (pacman,
# pacman-key, mkarchiso) and builds packages as the invoking user.
set -euo pipefail

PROFILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PROFILE_DIR/.." && pwd)"
PKGBUILD_DIR="$REPO_ROOT/install/pkgbuild"
LOCAL_REPO_DIR="$PROFILE_DIR/local-repo"
WORK_DIR="$PROFILE_DIR/work"
OUT_DIR="$PROFILE_DIR/out"
BUILD_PACMAN_CONF="$PROFILE_DIR/pacman.conf.local"
BLACKARCH_KEY="4345771566D76038C7FEB43863EC0ADBEA87E4E3"
NYX_PACKAGES=(nyx-health nyx-dns nyx-integrity nyx-wipe nyx-isolation nyx-workflow nyx-thunar-integration nyx-dashboard)

[[ "$EUID" -ne 0 ]] || { echo "do not run as root — see the header comment" >&2; exit 1; }

for tool_pkg in archiso:mkarchiso pacman-contrib:repo-add; do
    pkg="${tool_pkg%%:*}"; bin="${tool_pkg##*:}"
    command -v "$bin" &>/dev/null || sudo pacman -S --needed --noconfirm "$pkg"
done

# Trust the BlackArch signing key on this build host so pacstrap can verify
# [blackarch] packages listed in pacman.conf during ISO assembly.
if ! sudo pacman-key --list-keys "$BLACKARCH_KEY" &>/dev/null; then
    sudo pacman-key --recv-keys "$BLACKARCH_KEY" --keyserver keyserver.ubuntu.com
    sudo pacman-key --lsign-key "$BLACKARCH_KEY"
fi

if [[ "${1:-}" == "--clean" ]]; then
    rm -rf "$WORK_DIR" "$OUT_DIR" "$LOCAL_REPO_DIR" "$BUILD_PACMAN_CONF"
fi

# --- Build NyxOS's own packages and index them into a local file:// repo ---
mkdir -p "$LOCAL_REPO_DIR"
for pkg in "${NYX_PACKAGES[@]}"; do
    (cd "$PKGBUILD_DIR/$pkg" && PKGDEST="$LOCAL_REPO_DIR" makepkg -f --noconfirm)
done
repo-add "$LOCAL_REPO_DIR/nyxos.db.tar.gz" "$LOCAL_REPO_DIR"/*.pkg.tar.zst

# pacman.conf.local = the checked-in pacman.conf + a [nyxos] repo pointing at
# the local-repo dir we just built. Regenerated every run since the absolute
# path is host-specific; never edits the checked-in pacman.conf.
cp "$PROFILE_DIR/pacman.conf" "$BUILD_PACMAN_CONF"
cat >> "$BUILD_PACMAN_CONF" <<EOF

[nyxos]
SigLevel = Optional TrustAll
Server = file://$LOCAL_REPO_DIR
EOF

mkdir -p "$OUT_DIR"
sudo mkarchiso -v -C "$BUILD_PACMAN_CONF" -w "$WORK_DIR" -o "$OUT_DIR" "$PROFILE_DIR"

echo "ISO written to $OUT_DIR"
