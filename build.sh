#!/usr/bin/env bash
# Select existing project Python; tools/ owns build, generation, and test behavior.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf '%s\n' 'Execute this script; do not source it.' >&2
    return 1
fi
set -euo pipefail
astra_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
astra_python="${ASTRA_CACHE_ROOT:-$astra_root/build}/tools/python-build/bin/python"
if [[ ! -x "$astra_python" ]]; then astra_python=python3; fi
exec "$astra_python" -B "$astra_root/tools/build.py" "$@"
