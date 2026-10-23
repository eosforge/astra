#!/usr/bin/env bash
# Generate protocol sources explicitly; --check only compares. Normal service builds do not invoke this entry point.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf '%s\n' 'Execute this script; do not source it.' >&2
    return 1
fi
set -euo pipefail
astra_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then astra_root="$(cygpath -m "$astra_root")"; fi
exec env CARGO_HOME="${ASTRA_CACHE_ROOT:-$astra_root/build}/deps/cargo" CARGO_TARGET_DIR="$astra_root/build/proto/target" CARGO_NET_OFFLINE=true \
    cargo run --manifest-path "$astra_root/tools/protocol/Cargo.toml" --locked --offline --jobs 2 -- "$@"
