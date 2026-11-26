#!/usr/bin/env python3
"""SessionStart dynamic memory hook launcher delegating to `paos.gate`."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from paos.gate import (  # noqa: E402
    MAX_SESSION_START_CHARS as MAX_OUTPUT_CHARS,
    build_memory_snapshot as build_snapshot,
    run_session_start_main as main,
)

if __name__ == "__main__":
    sys.exit(main())
