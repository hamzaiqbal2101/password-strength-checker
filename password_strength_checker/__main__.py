"""Entry point for ``python -m password_strength_checker``."""

from __future__ import annotations

import sys

from password_strength_checker.cli import main

if __name__ == "__main__":
    sys.exit(main())
