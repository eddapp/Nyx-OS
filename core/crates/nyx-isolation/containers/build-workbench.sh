#!/usr/bin/env bash
# Builds the NyxOS "workbench" sandbox image and pins its digest into the
# sidecar metadata file nyx-isolation's Rust code (core/crates/nyx-isolation/
# src/containers.rs) re-verifies on every single container launch.
#
# Run this once, as root, on a machine with Podman and network access, after
# a known-good build or whenever the workbench image is deliberately
# rebuilt — never routinely, or it will happily re-pin a compromised image
# as "trusted". This is trust-on-first-use, the same shape as
# nyx-integrity's baseline step.
#
# This is *not* how nyx-isolation itself ever builds the image: the CLI is
# a one-shot, unprivileged tool that refuses to run as root at all (except
# for the equivalent `nyx-isolation container build-image` maintenance
# path, which exists purely so this same logic is reachable without a
# shell script if that's ever preferable — both write the exact same
# metadata file).
set -euo pipefail

IMAGE="localhost/nyx-workbench:latest"
METADATA_PATH="/etc/nyx/workbench-image.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINERFILE="$SCRIPT_DIR/workbench.Containerfile"

if [[ "${EUID}" -ne 0 ]]; then
    echo "build-workbench.sh: must run as root (writes $METADATA_PATH)" >&2
    exit 1
fi

if ! command -v podman >/dev/null 2>&1; then
    echo "build-workbench.sh: podman not found on PATH" >&2
    exit 1
fi

if [[ ! -f "$CONTAINERFILE" ]]; then
    echo "build-workbench.sh: $CONTAINERFILE not found" >&2
    exit 1
fi

echo "building $IMAGE from $CONTAINERFILE ..."
podman build \
    --pull=newer \
    --tag "$IMAGE" \
    --file "$CONTAINERFILE" \
    "$SCRIPT_DIR"

digest="$(podman image inspect --format '{{.Digest}}' "$IMAGE")"
if [[ -z "$digest" || "$digest" == "<none>" ]]; then
    echo "build-workbench.sh: podman reported no digest for $IMAGE after build" >&2
    exit 1
fi

built_at="$(date -u +%s)"

install -d -m 0755 "$(dirname "$METADATA_PATH")"
tmp="$(mktemp "${METADATA_PATH}.XXXXXX")"
cat > "$tmp" <<EOF
{
  "image": "$IMAGE",
  "digest": "$digest",
  "built_at": $built_at
}
EOF
chmod 0644 "$tmp"
mv -f "$tmp" "$METADATA_PATH"

echo "wrote $METADATA_PATH"
echo "image:  $IMAGE"
echo "digest: $digest"
