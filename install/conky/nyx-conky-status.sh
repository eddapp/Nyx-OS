#!/usr/bin/env bash
#
# Called on a repeating ${execi N ...} timer from install/conky/conky.conf.
# Prints a small block of plain "Label: value" lines for Conky to render
# verbatim. Every value here is either a local-only read (ip route/ip addr,
# no packet ever leaves the machine) or comes from an existing Nyx daemon's
# own live status, read through nyx-diagnostics (the same unprivileged
# aggregator the dashboard is built on) — nothing here is invented or
# cached from a previous run.
#
# Deliberately excluded: this machine's PUBLIC IP. Checking it always
# reveals the real IP to an external service, so NyxOS only ever does that
# from one explicit, one-time user action (`nyx-diagnostics public-ip
# --yes`, and the dashboard's "Check Public IP" button — see
# core/crates/nyx-diagnostics/src/main.rs and dashboard/src/ui.rs). A
# widget that polled it on any timer, however slow, would be silently
# automatic where that design is deliberately never automatic. Do not add
# it here — if a manual, explicit refresh is ever wanted, it belongs as a
# real user action (e.g. a keybinding that runs `nyx-diagnostics public-ip
# --yes` once and writes the result somewhere Conky can read), never a
# poll.

NYX_DIAGNOSTICS=/usr/bin/nyx-diagnostics
IP_BIN=/usr/bin/ip

# --- Local network info: default route, active interface, local IP. ---
# Pure local reads of the kernel's own routing/interface tables — no
# packet is sent for any of this.
iface=""
gateway=""
local_ip=""
if [ -x "$IP_BIN" ]; then
    route_line=$("$IP_BIN" route show default 2>/dev/null | head -n1)
    iface=$(printf '%s' "$route_line" | grep -oP '(?<=dev )\S+' || true)
    gateway=$(printf '%s' "$route_line" | grep -oP '(?<=via )\S+' || true)
    if [ -n "$iface" ]; then
        local_ip=$("$IP_BIN" -4 -o addr show dev "$iface" 2>/dev/null \
            | grep -oP '(?<=inet )[0-9.]+' | head -n1 || true)
    fi
fi

# --- NyxOS daemon status, via nyx-diagnostics (unprivileged socket client
# to nyx-health/nyx-vpn/nyx-dns; each daemon's Unix socket is group
# "wheel", 0660 — readable without a password by the same admin user the
# dashboard already assumes, no pkexec/root prompt involved). ---
#
# Uses `summary` rather than `bundle`: `bundle` writes a gzipped tarball
# and shells out to journalctl per call, far too heavy for a repeating
# timer. `summary` is a one-shot in-memory aggregation of every daemon's
# live status, plus one interfaces/routes dump and one connectivity ping
# to 1.1.1.1 (2 packets). That ping is the one part of this script that
# is not a purely local read; it never reveals or displays this machine's
# IP to anyone (unlike the public-IP case above, it returns no identifying
# information at all, just packet loss/latency), and is the same kind of
# background connectivity probe NetworkManager itself already performs
# periodically on a stock desktop. Its output isn't shown here, and the
# refresh interval on this exec is intentionally on the slower end
# (15s, see conky.conf) partly to keep it infrequent.
summary_json=""
if [ -x "$NYX_DIAGNOSTICS" ]; then
    summary_json=$("$NYX_DIAGNOSTICS" summary 2>/dev/null || true)
fi

# Pull the one line belonging to a given daemon out of `summary`'s
# newline-delimited JSON output. Each daemon's own successful reply is
# passed through with its own "binary" field (e.g. "nyx-health"); an
# unreachable daemon instead gets a synthesized nyx-diagnostics error line
# tagged with "command":"<label>" — matching on either catches both cases.
daemon_line() {
    local label="$1" binary="$2"
    printf '%s\n' "$summary_json" \
        | grep -m1 -E "\"binary\":\"$binary\"|\"command\":\"$label\"" || true
}

# Extracts a bare (unquoted) JSON scalar for "field": value|"value"|null.
json_bool() {
    printf '%s' "$1" | grep -oP "\"$2\":(true|false)" | head -n1 | cut -d: -f2
}
json_str() {
    printf '%s' "$1" | grep -oP "\"$2\":\"[^\"]*\"" | head -n1 | sed -E 's/.*:"([^"]*)"/\1/'
}

health_line=$(daemon_line health nyx-health)
vpn_line=$(daemon_line vpn nyx-vpn)
dns_line=$(daemon_line dns nyx-dns)

tor_active=$(json_bool "$health_line" tor_active)
kill_switch_level=$(json_str "$health_line" kill_switch_level)
panic_mode=$(json_bool "$health_line" panic_mode)

vpn_connected=$(json_bool "$vpn_line" connected)
vpn_protocol=$(json_str "$vpn_line" protocol)
vpn_iface=$(json_str "$vpn_line" interface)

dns_local=$(json_bool "$dns_line" resolver_is_local)
dns_foreign_listener=$(json_bool "$dns_line" foreign_listener_on_53)

# --- Render. Plain text only — Conky renders this exec's output verbatim,
# it does not re-parse Conky markup out of it (that would need
# ${execp}/${execpi}, deliberately not used here since correctness of any
# embedded markup can't be display-tested in this environment). ---

fmt() { printf '%-13s%s\n' "$1" "$2"; }

case "$tor_active" in
    true) tor_disp="active" ;;
    false) tor_disp="inactive" ;;
    *) tor_disp="unknown (nyx-health unreachable)" ;;
esac
fmt "Tor:" "$tor_disp"

ks_disp="${kill_switch_level:-unknown}"
if [ "$panic_mode" = "true" ]; then
    ks_disp="$ks_disp (PANIC MODE)"
fi
fmt "Kill Switch:" "$ks_disp"

case "$vpn_connected" in
    true)
        vpn_disp="connected"
        [ -n "$vpn_protocol" ] && vpn_disp="$vpn_disp ($vpn_protocol"
        [ -n "$vpn_iface" ] && vpn_disp="$vpn_disp, $vpn_iface"
        [ -n "$vpn_protocol" ] && vpn_disp="$vpn_disp)"
        ;;
    false) vpn_disp="disconnected" ;;
    *) vpn_disp="unknown (nyx-vpn unreachable)" ;;
esac
fmt "VPN:" "$vpn_disp"

case "$dns_local" in
    true)
        if [ "$dns_foreign_listener" = "true" ]; then
            dns_disp="local resolver, but foreign listener on :53"
        else
            dns_disp="local resolver OK"
        fi
        ;;
    false) dns_disp="NOT local — possible leak" ;;
    *) dns_disp="unknown (nyx-dns unreachable)" ;;
esac
fmt "DNS:" "$dns_disp"

fmt "Interface:" "${iface:-none}"
fmt "Gateway:" "${gateway:-none}"
fmt "Local IP:" "${local_ip:-none}"
fmt "Public IP:" "not checked (by design — see Nyx Dashboard)"
