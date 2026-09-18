#!/usr/bin/env bash
# Entrypoint for the NyxOS "workbench" sandbox image. This script runs as
# PID 1 inside the container (see the Containerfile's exec-form ENTRYPOINT),
# so it is the process directly responsible for reacting to signals — there
# is no wrapping shell to do it for us, and no wrapping shell to silently
# swallow them either.
#
# Two modes, chosen by the single argument nyx-isolation passes:
#
#   shell — an interactive login shell. Used both for the disposable
#           one-shot sandbox (`podman run --rm -it ... workbench shell`)
#           and to attach into the already-running persistent workbench
#           (`podman exec -it nyx-workbench nyx-workbench-entrypoint shell`).
#
#   idle  — the persistent workbench's own long-running main process.
#           Deliberately NOT `sleep infinity`: PID 1 inside a fresh PID
#           namespace does not get the normal default action for a signal
#           it hasn't explicitly handled — the kernel just ignores it. A
#           bare `sleep infinity` (or a shell that execs one without a
#           trap) as PID 1 never reacts to SIGTERM at all, so `podman stop`
#           sits out its full timeout and then falls back to SIGKILL every
#           single time. Trapping SIGTERM/SIGINT here and breaking out of
#           `wait` on receipt makes `podman stop nyx-workbench` return
#           immediately instead, exactly once, cleanly.
set -euo pipefail

mode="${1:-shell}"
shift || true

case "$mode" in
    shell)
        exec /bin/bash -l
        ;;
    idle)
        trap 'exit 0' SIGTERM SIGINT
        while true; do
            sleep 3600 &
            wait "$!"
        done
        ;;
    *)
        exec "$mode" "$@"
        ;;
esac
