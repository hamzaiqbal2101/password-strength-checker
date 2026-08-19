#!/usr/bin/env python3
"""Download a common-passwords wordlist for offline breach checks.

Fetches the SecLists "10 million passwords -- top 10000" list and writes it
(lowercased and deduplicated) to ``wordlists/common-passwords.txt``. The list
is not bundled in the repository because of its size.

Usage:
    python scripts/download_wordlists.py [--dest PATH]

The destination is created if it does not exist.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import requests

_SOURCE_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
)
_DEFAULT_DEST = Path(__file__).resolve().parent.parent / "wordlists" / "common-passwords.txt"


def download_wordlist(dest: Path, url: str = _SOURCE_URL) -> int:
    """Fetch and normalize a wordlist to ``dest``.

    Args:
        dest: Destination file path.
        url: Source URL of the raw wordlist.

    Returns:
        The number of unique passwords written.

    Raises:
        requests.HTTPError: If the source cannot be fetched.
    """
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    unique = sorted(
        {line.strip().lower() for line in response.text.splitlines() if line.strip()}
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(unique) + "\n", encoding="utf-8")
    return len(unique)


def main(argv: list[str] | None = None) -> int:
    """Script entry point."""
    parser = argparse.ArgumentParser(
        description="Download the SecLists top-10k common passwords wordlist."
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=_DEFAULT_DEST,
        help=f"Output file (default: {_DEFAULT_DEST})",
    )
    args = parser.parse_args(argv)
    count = download_wordlist(args.dest)
    print(f"Wrote {count} unique passwords to {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())