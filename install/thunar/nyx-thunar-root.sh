#!/usr/bin/env bash
# NyxOS Thunar action: Open As Root. Still goes through pkexec/polkit
# (every call is authorized and logged via pkexec's own audit trail, never
# a raw sudo/setuid escalation), but iso/airootfs/etc/polkit-1/rules.d/
# 90-nyx-dashboard.rules now authorizes this exact program for wheel-group
# members without an interactive password prompt, matching the same
# Kodachi-style live-session trust model applied to the dashboard's own
# pkexec calls.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

target=${1:-$HOME}
command -v pkexec &>/dev/null || nyx_die "pkexec is not installed"

exec pkexec env DISPLAY="${DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    /usr/bin/thunar "$target"
