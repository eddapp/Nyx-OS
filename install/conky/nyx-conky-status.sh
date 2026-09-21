#!/usr/bin/env bash
#
# Called on a repeating ${execpi N ...} timer from install/conky/conky.conf,
# once per section: `network` (local-only reads of the kernel's routing
# and interface tables — no packet ever leaves the machine) and `security`
# (each Nyx daemon's own live status, read through nyx-diagnostics, the
# same unprivileged aggregator the dashboard is built on). Nothing here is
# invented or cached from a previous run.
#
# Output is Conky markup (${color}, ${goto}, ${downspeedgraph ...}), which
# is why conky.conf uses ${execpi} rather than ${execi}. Every value taken
# from outside this script (daemon JSON fields, interface names, addresses)
# goes through sanitize() first, which strips the characters Conky's parser
# treats specially, so a daemon-reported string can never inject markup.
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

# Palette (keep in sync with conky.conf): section/accent purple, muted
# labels, bright values, and the four status colours.
C_LABEL='${color 6E7386}'
C_VALUE='${color E6E8EF}'
C_OK='${color 63D98A}'
C_WARN='${color F0B451}'
C_BAD='${color FF5C7A}'
C_OFF='${color 6E7386}'
C_END='${color}'
GRAPH_LO=5B21B6
GRAPH_HI=C084FC

sanitize() { printf '%s' "$1" | tr -d '${}#\\'; }

# Label at column 0, value at a fixed x offset so the column lines up.
row() { printf '%s%s%s${goto 118}%s\n' "$C_LABEL" "$1" "$C_END" "$2"; }
# Status row: label, coloured dot, text.
srow() { printf '%s%s%s${goto 118}%s●%s %s\n' "$C_LABEL" "$1" "$C_END" "$2" "$C_END" "$3"; }

# --- Local network info: default route, active interface, local IP. ---
iface=""; gateway=""; local_ip=""
if [ -x "$IP_BIN" ]; then
    route_line=$("$IP_BIN" route show default 2>/dev/null | head -n1)
    iface=$(sanitize "$(printf '%s' "$route_line" | grep -oP '(?<=dev )\S+' || true)")
    gateway=$(sanitize "$(printf '%s' "$route_line" | grep -oP '(?<=via )\S+' || true)")
    if [ -n "$iface" ]; then
        local_ip=$(sanitize "$("$IP_BIN" -4 -o addr show dev "$iface" 2>/dev/null \
            | grep -oP '(?<=inet )[0-9.]+' | head -n1 || true)")
    fi
fi

section_network() {
    if [ -z "$iface" ]; then
        srow "Link" "$C_BAD" "no default route"
        return
    fi
    row "Iface" "${C_VALUE}${iface}${C_END}\${alignr}${C_LABEL}IP${C_END} ${local_ip:-none}"
    row "Gateway" "${gateway:-none}"
    printf '%sDown%s %s${downspeed %s}%s${goto 204}%sUp%s %s${upspeed %s}%s\n' \
        "$C_LABEL" "$C_END" "$C_VALUE" "$iface" "$C_END" "$C_LABEL" "$C_END" "$C_VALUE" "$iface" "$C_END"
    printf '${color 3A3550}${downspeedgraph %s 26,182 %s %s -t}${goto 204}${upspeedgraph %s 26,182 %s %s -t}${color}\n' \
        "$iface" "$GRAPH_LO" "$GRAPH_HI" "$iface" "$GRAPH_LO" "$GRAPH_HI"
    row "Session" "${C_VALUE}\${totaldown ${iface}}${C_END} down  ${C_VALUE}\${totalup ${iface}}${C_END} up"
}

# --- NyxOS daemon status, via nyx-diagnostics (unprivileged socket client
# to the Nyx daemons; each daemon's Unix socket is group "wheel", 0660 —
# readable without a password by the same admin user the dashboard already
# assumes, no pkexec/root prompt involved). ---
#
# Uses `summary --no-ping` rather than plain `summary`: plain `summary`
# also fires one outbound connectivity ping to 1.1.1.1 as a side effect,
# which — however low-stakes — is still automatic, unattended, repeating
# outbound network traffic this always-on widget has no business sending
# on its own. `--no-ping` gives the exact same daemon/interface status with
# zero packets of its own. Never `bundle`: that writes a gzipped tarball
# and shells to journalctl per call, far too heavy for a repeating timer.
section_security() {
    local summary_json=""
    if [ -x "$NYX_DIAGNOSTICS" ]; then
        summary_json=$("$NYX_DIAGNOSTICS" summary --no-ping 2>/dev/null || true)
    fi

    # Pull the one line belonging to a given daemon out of `summary`'s
    # newline-delimited JSON output. A daemon's own successful reply carries
    # its "binary" field; an unreachable daemon instead gets a synthesized
    # nyx-diagnostics error line tagged "command":"<label>".
    daemon_line() {
        printf '%s\n' "$summary_json" \
            | grep -m1 -E "\"binary\":\"$2\"|\"command\":\"$1\"" || true
    }
    json_bool() { printf '%s' "$1" | grep -oP "\"$2\":(true|false)" | head -n1 | cut -d: -f2; }
    json_str() { sanitize "$(printf '%s' "$1" | grep -oP "\"$2\":\"[^\"]*\"" | head -n1 | sed -E 's/.*:"([^"]*)"/\1/')"; }

    local health_line vpn_line dns_line identity_line
    health_line=$(daemon_line health nyx-health)
    vpn_line=$(daemon_line vpn nyx-vpn)
    dns_line=$(daemon_line dns nyx-dns)
    identity_line=$(daemon_line identity nyx-identity)

    local tor_active kill_switch_level panic_mode
    tor_active=$(json_bool "$health_line" tor_active)
    kill_switch_level=$(json_str "$health_line" kill_switch_level)
    panic_mode=$(json_bool "$health_line" panic_mode)

    case "$tor_active" in
        true)  srow "Tor" "$C_OK"   "active" ;;
        false) srow "Tor" "$C_OFF"  "inactive" ;;
        *)     srow "Tor" "$C_WARN" "unknown (nyx-health unreachable)" ;;
    esac

    if [ "$panic_mode" = "true" ]; then
        srow "Kill switch" "$C_BAD" "${kill_switch_level:-?} — PANIC MODE"
    else
        case "$kill_switch_level" in
            "")  srow "Kill switch" "$C_WARN" "unknown" ;;
            off) srow "Kill switch" "$C_OFF"  "off" ;;
            *)   srow "Kill switch" "$C_OK"   "$kill_switch_level" ;;
        esac
    fi

    local vpn_connected vpn_protocol vpn_iface vpn_disp
    vpn_connected=$(json_bool "$vpn_line" connected)
    vpn_protocol=$(json_str "$vpn_line" protocol)
    vpn_iface=$(json_str "$vpn_line" interface)
    case "$vpn_connected" in
        true)
            vpn_disp="connected"
            [ -n "$vpn_protocol" ] && vpn_disp="$vpn_disp ($vpn_protocol${vpn_iface:+, $vpn_iface})"
            srow "VPN" "$C_OK" "$vpn_disp" ;;
        false) srow "VPN" "$C_OFF"  "disconnected" ;;
        *)     srow "VPN" "$C_WARN" "unknown (nyx-vpn unreachable)" ;;
    esac

    local dns_local dns_foreign_listener
    dns_local=$(json_bool "$dns_line" resolver_is_local)
    dns_foreign_listener=$(json_bool "$dns_line" foreign_listener_on_53)
    case "$dns_local" in
        true)
            if [ "$dns_foreign_listener" = "true" ]; then
                srow "DNS" "$C_WARN" "local, but foreign listener on :53"
            else
                srow "DNS" "$C_OK" "local resolver OK"
            fi ;;
        false) srow "DNS" "$C_BAD"  "NOT local — possible leak" ;;
        *)     srow "DNS" "$C_WARN" "unknown (nyx-dns unreachable)" ;;
    esac

    local ipv6_enabled
    ipv6_enabled=$(json_bool "$identity_line" ipv6_enabled)
    case "$ipv6_enabled" in
        true)  srow "IPv6" "$C_WARN" "enabled" ;;
        false) srow "IPv6" "$C_OK"   "disabled" ;;
        *)     srow "IPv6" "$C_WARN" "unknown (nyx-identity unreachable)" ;;
    esac

    row "Public IP" "${C_LABEL}not checked (by design)${C_END}"
}

case "${1:-}" in
    network)  section_network ;;
    security) section_security ;;
    *)        section_network; echo; section_security ;;
esac
