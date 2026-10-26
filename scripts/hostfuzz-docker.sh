#!/usr/bin/env bash
#
# Convenience wrapper around `docker run` that keeps output files owned by the
# invoking user instead of root.
#
#   ./scripts/hostfuzz-docker.sh list
#   ./scripts/hostfuzz-docker.sh run --case 01_btstack_sm_pairing_central --seconds 120
#   ./scripts/hostfuzz-docker.sh replay --case 01_btstack_sm_pairing_central \
#       --input /outputs/<run>/fuzz-<timestamp>/queue/<input>
#
# Set HOSTFUZZ_IMAGE=hostfuzz:full for Fuzzware cases.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${HOSTFUZZ_IMAGE:-hostfuzz}"
mkdir -p "$ROOT/outputs"

exec docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -v "$ROOT/outputs:/outputs" \
    -v "$ROOT:/repo:ro" \
    "$IMAGE" "$@"
