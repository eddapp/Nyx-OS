#!/usr/bin/env bash
# NyxOS Thunar action: Open As Root. Uses pkexec/polkit rather than a
# blanket NOPASSWD sudoers rule — every invocation goes through the polkit
# authentication agent and is logged, instead of silently escalating.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

target=${1:-$HOME}
command -v pkexec &>/dev/null || nyx_die "pkexec is not installed"

exec pkexec env DISPLAY="${DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    /usr/bin/thunar "$target"
