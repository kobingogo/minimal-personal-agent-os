#!/usr/bin/env python3
"""Stop verification hook launcher delegating to `paos.gate`."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from paos.gate import run_stop_verify_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_stop_verify_main())
