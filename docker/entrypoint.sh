#!/usr/bin/env bash
set -euo pipefail

# Allow "hostfuzz bash" for debugging without going through the Python runner.
if [[ $# -gt 0 && ( "$1" == "bash" || "$1" == "sh" ) ]]; then
    exec "$@"
fi

exec python3 /opt/hostfuzz/scripts/hostfuzz.py "$@"
