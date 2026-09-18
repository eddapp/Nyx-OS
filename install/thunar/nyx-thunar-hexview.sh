#!/usr/bin/env bash
# NyxOS Thunar action: Hex View. Pipes xxd into less inside a terminal —
# less pages the output properly (and handles arbitrarily large files, no
# hardcoded truncation needed) far better than a bounded blocking pipe or a
# from-scratch GUI viewer would.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=nyx-thunar-common.sh
source "$SCRIPT_DIR/nyx-thunar-common.sh"

[[ $# -ge 1 ]] || nyx_die "no file selected"
target=$1
[[ -f "$target" ]] || nyx_die "not a regular file: $(nyx_esc "$(basename -- "$target")")"
command -v xxd &>/dev/null || nyx_die "xxd is not installed"
command -v xfce4-terminal &>/dev/null || nyx_die "xfce4-terminal is not installed"

title="Hex View: $(basename -- "$target")"

# -x passes an argv array to the child instead of a shell string, so the
# attacker-controlled path never goes through shell interpolation — it
# reaches the inner bash as a real positional parameter ($1).
exec xfce4-terminal --title="$title" -x bash -c 'xxd -- "$1" | less' bash "$target"
