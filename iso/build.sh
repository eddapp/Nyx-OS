#!/usr/bin/env bash
# Builds the NyxOS ISO from this profile.
#
# Run as your normal user (must have sudo) — NOT as root: makepkg refuses to
# build the nyx-health/nyx-dashboard packages as root, so this script uses
# `sudo` only for the individual steps that actually need it (pacman,
# pacman-key, mkarchiso) and builds packages as the invoking user.
#
# Usage: build.sh [--profile desktop|server] [--clean]
#   --profile desktop   Full XFCE/LightDM desktop ISO (default, matches the
#                        historical no-flag invocation).
#   --profile server    Headless control-layer ISO: same base system,
#                        networking, privacy stack, Nyx daemons and security
#                        tooling, minus every GUI-only package.
set -euo pipefail

PROFILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PROFILE_DIR/.." && pwd)"
PKGBUILD_DIR="$REPO_ROOT/install/pkgbuild"
LOCAL_REPO_DIR="$PROFILE_DIR/local-repo"
WORK_DIR="$PROFILE_DIR/work"
OUT_DIR="$PROFILE_DIR/out"
BUILD_PACMAN_CONF="$PROFILE_DIR/pacman.conf.local"
BLACKARCH_KEY="4345771566D76038C7FEB43863EC0ADBEA87E4E3"
NYX_PACKAGES=(nyx-health nyx-vpn nyx-identity nyx-devices nyx-telemetry nyx-diagnostics nyx-dns nyx-integrity nyx-wipe nyx-isolation nyx-workflow nyx-hardening nyx-watch nyx-thunar-integration nyx-desktop-sessions nyx-dashboard)
# shellcheck source=build-aur-packages.sh
source "$PROFILE_DIR/build-aur-packages.sh"
# shellcheck source=sign-packages.sh
source "$PROFILE_DIR/sign-packages.sh"

PROFILE="desktop"
CLEAN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ $# -ge 2 ]] || { echo "--profile needs an argument (desktop|server)" >&2; exit 1; }
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#--profile=}"
            shift
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

case "$PROFILE" in
    desktop|server) ;;
    *) echo "--profile must be 'desktop' or 'server', got '$PROFILE'" >&2; exit 1 ;;
esac

[[ "$EUID" -ne 0 ]] || { echo "do not run as root — see the header comment" >&2; exit 1; }

# The server profile drops the three GUI-dependent Nyx packages from the
# build list entirely — no reason to compile a GTK dashboard or a
# Thunar/LightDM integration package when neither Thunar nor LightDM is
# going to be installed.
if [[ "$PROFILE" == "server" ]]; then
    FILTERED_NYX_PACKAGES=()
    for pkg in "${NYX_PACKAGES[@]}"; do
        case "$pkg" in
            nyx-dashboard|nyx-thunar-integration|nyx-desktop-sessions) continue ;;
        esac
        FILTERED_NYX_PACKAGES+=("$pkg")
    done
    NYX_PACKAGES=("${FILTERED_NYX_PACKAGES[@]}")
fi

# --- Profile-directory swap bookkeeping -------------------------------
#
# archiso/mkarchiso has no --packages-file flag: it always reads
# "$PROFILE_DIR/packages.x86_64" implicitly, and boots into whatever
# default.target/display-manager.service airootfs/etc/systemd/system
# points at. For --profile server we temporarily repoint both onto their
# headless equivalents for the duration of the mkarchiso call, and restore
# the checked-in desktop originals via a trap so a Ctrl-C or a failed build
# never leaves the working tree modified.
PACKAGES_FILE="$PROFILE_DIR/packages.x86_64"
PACKAGES_BACKUP="$PROFILE_DIR/.packages.x86_64.desktop-orig"
DEFAULT_TARGET_LINK="$PROFILE_DIR/airootfs/etc/systemd/system/default.target"
DISPLAY_MANAGER_LINK="$PROFILE_DIR/airootfs/etc/systemd/system/display-manager.service"
SWAPPED_PROFILE_FILES=0

restore_profile_files() {
    [[ "$SWAPPED_PROFILE_FILES" -eq 1 ]] || return 0

    if [[ -f "$PACKAGES_BACKUP" ]]; then
        mv -f "$PACKAGES_BACKUP" "$PACKAGES_FILE"
    fi

    # graphical.target is the checked-in desktop default; server builds
    # never touch this symlink target itself, only recreate it pointing at
    # multi-user.target for the duration of the build.
    ln -sfn /usr/lib/systemd/system/graphical.target "$DEFAULT_TARGET_LINK"
    ln -sfn /usr/lib/systemd/system/lightdm.service "$DISPLAY_MANAGER_LINK"

    SWAPPED_PROFILE_FILES=0
}
trap restore_profile_files EXIT

if [[ "$PROFILE" == "server" ]]; then
    cp -f "$PACKAGES_FILE" "$PACKAGES_BACKUP"
    # From this point on something has been mutated in the working tree, so
    # the EXIT trap must attempt a restore no matter what happens next
    # (including packages-server.x86_64 itself being missing).
    SWAPPED_PROFILE_FILES=1
    cp -f "$PROFILE_DIR/packages-server.x86_64" "$PACKAGES_FILE"

    # No display manager is installed on this profile, so booting into
    # graphical.target would try to start a lightdm.service unit file that
    # doesn't exist. Land on multi-user.target instead (a plain login/SSH
    # prompt) and drop display-manager.service entirely rather than leave
    # it dangling.
    ln -sfn /usr/lib/systemd/system/multi-user.target "$DEFAULT_TARGET_LINK"
    rm -f "$DISPLAY_MANAGER_LINK"
fi

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

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf "$WORK_DIR" "$OUT_DIR" "$LOCAL_REPO_DIR" "$BUILD_PACMAN_CONF"
fi

# --- NyxOS's own build-signing key: generate one (first run on this
# machine) or reuse the existing one (later runs), isolated in its own
# GNUPGHOME under this profile dir -- never the developer's own ~/.gnupg --
# then trust it on this build host exactly like the BlackArch key above, so
# pacstrap/mkarchiso can verify [nyxos] packages/database during ISO
# assembly.
ensure_nyx_signing_key
trust_nyx_signing_key_on_host

# --- Build NyxOS's own packages and index them into a local file:// repo ---
mkdir -p "$LOCAL_REPO_DIR"
for pkg in "${NYX_PACKAGES[@]}"; do
    (cd "$PKGBUILD_DIR/$pkg" && PKGDEST="$LOCAL_REPO_DIR" makepkg -f --noconfirm)
done
repo-add "$LOCAL_REPO_DIR/nyxos.db.tar.gz" "$LOCAL_REPO_DIR"/*.pkg.tar.zst

# --- Build any AUR-only packages (currently: zen-browser-bin) into the same
# local repo and re-index. build_aur_packages does its own repo-add over
# everything now in $LOCAL_REPO_DIR (NYX_PACKAGES output included), so this
# is a harmless re-index when AUR_PACKAGES is non-empty and a no-op ---
# (it returns early, before touching the repo at all) when it's empty. ---
build_aur_packages "$LOCAL_REPO_DIR"

# --- Sign every package this build produced (NyxOS-native + any AUR ones
# build_aur_packages just added) and re-index + sign the repo database.
# Runs only now, after build_aur_packages, so every *.pkg.tar.zst that will
# end up in the [nyxos] repo already exists in $LOCAL_REPO_DIR. The repo-add
# call inside sign_nyx_repo_db is a harmless re-index over the same files
# (see the note above build_aur_packages) except this time with -s/-k, so
# the resulting nyxos.db.tar.gz also carries a database-level signature,
# not just the per-package ones sign_nyx_packages just wrote. ---
sign_nyx_packages "$LOCAL_REPO_DIR"
sign_nyx_repo_db "$LOCAL_REPO_DIR" "nyxos.db.tar.gz"

# pacman.conf.local = the checked-in pacman.conf + a [nyxos] repo pointing at
# the local-repo dir we just built. Regenerated every run since the absolute
# path is host-specific; never edits the checked-in pacman.conf.
#
# SigLevel = Required TrustedOnly: both the repo database and every package
# in it must now carry a valid signature (Required, applies to both since
# neither is qualified with a Package/Database prefix), and that signature
# must chain to a key already in the trusted keyring -- TrustedOnly, which
# is also pacman's own default when no trust qualifier is given at all, but
# spelled out here so it's unmistakable that TrustAll's blanket "accept
# anything" has actually been replaced, not merely renamed. The NyxOS
# build-signing key was just locally signed into the build host's pacman
# keyring above via trust_nyx_signing_key_on_host, which is what makes it
# "trusted" for this check.
cp "$PROFILE_DIR/pacman.conf" "$BUILD_PACMAN_CONF"
cat >> "$BUILD_PACMAN_CONF" <<EOF

[nyxos]
SigLevel = Required TrustedOnly
Server = file://$LOCAL_REPO_DIR
EOF

# --- Reproducible-build groundwork: pin mkarchiso's own timestamp source
# (SOURCE_DATE_EPOCH) to this commit's own commit time instead of "now", so
# two builds from the same commit land closer to byte-identical output
# wherever the rest of the toolchain (squashfs mtimes, ISO9660/UDF/El Torito
# timestamps, the ext4 hash seed, etc.) already supports it. mkarchiso
# itself reads SOURCE_DATE_EPOCH from its environment when present and only
# falls back to the current wall-clock time otherwise (see
# `grep SOURCE_DATE_EPOCH /usr/bin/mkarchiso`) -- this is real, current
# archiso behavior, not something added here. sudo resets the environment
# by default, so --preserve-env is required or mkarchiso would never see it.
export SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"

mkdir -p "$OUT_DIR"
sudo --preserve-env=SOURCE_DATE_EPOCH mkarchiso -v -C "$BUILD_PACMAN_CONF" -w "$WORK_DIR" -o "$OUT_DIR" "$PROFILE_DIR"

# --- Locate the ISO mkarchiso just wrote. Its filename embeds
# iso_version=$(date +%Y.%m.%d) from profiledef.sh, evaluated at mkarchiso's
# own runtime, so it isn't hardcoded here -- just take the most recently
# modified *.iso in $OUT_DIR, which is reliably the one just built. ---
iso_file="$(find "$OUT_DIR" -maxdepth 1 -name '*.iso' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n1 | cut -d' ' -f2-)"
if [[ -n "$iso_file" ]]; then
    write_and_sign_build_manifest "$iso_file" "$OUT_DIR"
else
    echo "warning: no .iso found in $OUT_DIR, skipping build manifest" >&2
fi

echo "ISO written to $OUT_DIR (profile: $PROFILE)"
