"""Module execution entry point for `python -m cyberguard_verify`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
