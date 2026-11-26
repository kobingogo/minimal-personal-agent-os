"""Allow `python3 -m paos` execution across git checkouts and wheel installs."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
