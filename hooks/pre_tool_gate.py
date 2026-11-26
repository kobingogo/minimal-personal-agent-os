#!/usr/bin/env python3
"""PreToolUse hook launcher delegating to `paos.gate` (single source of truth)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from paos.gate import run_pre_tool_gate_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_pre_tool_gate_main())
