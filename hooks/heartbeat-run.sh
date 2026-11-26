#!/usr/bin/env bash
set -euo pipefail

REAL_SCRIPT="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
PAOS_BIN="$(cd "$(dirname "$REAL_SCRIPT")/.." && pwd)/bin/paos"
exec "$PAOS_BIN" cron run-now heartbeat "$@"
