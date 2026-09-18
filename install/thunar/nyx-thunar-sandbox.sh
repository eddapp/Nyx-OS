#!/usr/bin/env bash
# NyxOS Thunar action: Sandbox Shell Here. Opens a Firejail-sandboxed
# terminal rooted at the selected directory. The sandboxing decision itself
# (which profile, path validation) is nyx-isolation's job, not this script's.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

target=${1:-$HOME}
[[ -d "$target" ]] || target=$(dirname "$target")

# Refuse to sandbox $HOME itself — the whole point is containing untrusted
# content, and $HOME is everything the user has, not a scratch directory.
if [[ "$(realpath -- "$target")" == "$(realpath -- "$HOME")" ]]; then
    nyx_die "refusing to open a sandboxed shell rooted at your home directory — pick a subfolder"
fi

exec /usr/bin/nyx-isolation launch app:xfce4-terminal --runtime firejail -- --working-directory="$target"
