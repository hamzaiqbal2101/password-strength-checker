"""Command-line interface for the password strength checker.

Security properties:

* Interactive input uses :func:`getpass.getpass` so the password is not
  echoed to the terminal and never enters shell history.
* In ``--file`` mode each password is read line-by-line and only derived
  metrics (length, entropy, score, ...) are printed -- never the value.
* Passwords are explicitly deleted (``del``) from memory after processing.
  Python strings are immutable, so a ``del`` releases the reference for
  garbage collection rather than scrubbing the buffer; see the README.
* HIBP queries are opt-out only when ``--no-network`` is passed; failures
  degrade gracefully to an "unknown" breach status.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from password_strength_checker import __version__
from password_strength_checker.breach import HibpClient, HibpError, load_wordlist
from password_strength_checker.patterns import PatternReport
from password_strength_checker.scoring import Assessment, assess

# Default location for a downloaded common-passwords list, relative to the
# project root (two levels up from this package directory).
DEFAULT_WORDLIST = (
    Path(__file__).resolve().parent.parent / "wordlists" / "common-passwords.txt"
)

_PROG = "password-strength-checker"

# Exit codes used by the CLI.
_EXIT_OK = 0
_EXIT_BAD_INPUT = 1  # empty password, unreadable file, etc.
_EXIT_FILE_ERROR = 2  # --file path does not exist


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command-line parser.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Assess password strength using entropy, breach data, and "
            "structural pattern detection. Passwords are never printed, "
            "stored, or transmitted (HIBP queries use k-anonymity)."
        ),
        epilog=(
            "Examples:\n"
            f"  {_PROG}                         # interactive check\n"
            f"  {_PROG} --file list.txt         # batch check a wordlist\n"
            f"  {_PROG} --no-network            # skip online HIBP check\n"
            f"  python scripts/download_wordlists.py   # fetch SecLists top 10k"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Batch-check passwords from a file (one per line). Values are never echoed.",
    )
    parser.add_argument(
        "--wordlist",
        metavar="PATH",
        help=(
            "Common-passwords wordlist to match against. Defaults to "
            f"{DEFAULT_WORDLIST} if present."
        ),
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip the online Have I Been Pwned check (offline mode).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HIBP request timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _load_wordlist(path_arg: str | None) -> frozenset[str] | None:
    """Resolve and load the common-passwords wordlist.

    Args:
        path_arg: Explicit ``--wordlist`` path, or None.

    Returns:
        A frozenset of words, or None when no wordlist is available (the
        caller decides how to handle that case).
    """
    if path_arg:
        path = Path(path_arg)
        if not path.is_file():
            print(f"[!] Wordlist not found: {path}", file=sys.stderr)
            return None
    elif DEFAULT_WORDLIST.is_file():
        path = DEFAULT_WORDLIST
    else:
        print(
            f"[!] No common-passwords wordlist found at {DEFAULT_WORDLIST}.\n"
            "    Run: python scripts/download_wordlists.py  (or use --wordlist PATH)",
            file=sys.stderr,
        )
        return None
    return load_wordlist(path)


def _hibp_lookup(
    client: HibpClient | None, password: str
) -> tuple[int | None, bool]:
    """Query HIBP for a password; never propagate errors to the caller.

    Args:
        client: The HIBP client, or None when network is disabled.
        password: The password to look up.

    Returns:
        A tuple ``(count, checked)`` where ``count`` is the breach count (or
        None on failure) and ``checked`` records whether the query ran.
    """
    if client is None:
        return None, False
    try:
        return client.check(password), True
    except HibpError as exc:
        print(f"[!] HIBP check skipped: {exc}", file=sys.stderr)
        return None, False


def _pattern_summary(report: PatternReport) -> str:
    """Return a compact, comma-separated list of detected patterns."""
    names = {
        "keyboard_walk": "keyboard-walk",
        "repeated_characters": "repeated-characters",
        "sequential_characters": "sequential-characters",
        "dictionary_word": "dictionary-word",
        "leet_substitution": "leetspeak",
    }
    return ", ".join(name for key, name in names.items() if getattr(report, key)) or "none"


def _print_interactive(assessment: Assessment) -> None:
    """Pretty-print a single interactive assessment."""
    patterns = _pattern_summary(assessment.patterns)
    pwned = (
        f"pwned ({assessment.pwn_count:,} times)"
        if assessment.pwn_count
        else assessment.breach_status.label
    )
    print()
    print(f"Score:      {assessment.score}/100 ({assessment.strength_label})")
    print(f"Length:     {assessment.password_length} characters")
    print(
        f"Entropy:    {assessment.entropy_bits:.2f} bits "
        f"({assessment.entropy_class})"
    )
    print(f"Breach:     {pwned}")
    print(f"Patterns:   {patterns}")
    print("Feedback:")
    for message in assessment.feedback:
        print(f"  - {message}")


def _print_batch_row(index: int, assessment: Assessment) -> None:
    """Print one row of the batch table (indexed, never the raw password)."""
    pwned = (
        f"{assessment.breach_status.label}({assessment.pwn_count:,})"
        if assessment.pwn_count
        else assessment.breach_status.label
    )
    print(
        f"{index:>4} | {assessment.password_length:>3} | "
        f"{assessment.entropy_bits:>7.2f} | {assessment.entropy_class:<10} | "
        f"{pwned:<12} | {assessment.score:>3} | {assessment.strength_label}"
    )


def _run_interactive(args: argparse.Namespace, wordlist: frozenset[str] | None) -> int:
    """Run a single interactive assessment using getpass.

    Args:
        args: Parsed CLI arguments.
        wordlist: Loaded wordlist (or None).

    Returns:
        Process exit code.
    """
    client = None if args.no_network else HibpClient(timeout=args.timeout)
    try:
        password = getpass.getpass("Enter password to check: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return _EXIT_BAD_INPUT

    if not password:
        print("Empty password rejected.", file=sys.stderr)
        return _EXIT_BAD_INPUT

    try:
        hibp_count, hibp_checked = _hibp_lookup(client, password)
        hit = bool(wordlist and password.lower() in wordlist)
        assessment = assess(
            password,
            wordlist_hit=hit,
            hibp_count=hibp_count,
            hibp_checked=hibp_checked,
            dictionary=wordlist,
        )
        _print_interactive(assessment)
    finally:
        del password
    return _EXIT_OK


def _run_file(args: argparse.Namespace, wordlist: frozenset[str] | None) -> int:
    """Batch-check every non-empty line of ``--file``.

    Args:
        args: Parsed CLI arguments.
        wordlist: Loaded wordlist (or None).

    Returns:
        Process exit code.
    """
    path = Path(args.file)
    if not path.is_file():
        print(f"[!] File not found: {path}", file=sys.stderr)
        return _EXIT_FILE_ERROR

    client = None if args.no_network else HibpClient(timeout=args.timeout)
    if wordlist is not None:
        print(f"Common-passwords wordlist loaded: {len(wordlist)} entries")
    print(
        "Row | Len | Entropy | Class      | Breach      | Score | Label\n"
        "----+-----+---------+------------+-------------+-------+------------"
    )

    checked_count = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, raw in enumerate(handle, start=1):
                password = raw.rstrip("\r\n")
                if not password:
                    continue
                try:
                    hibp_count, hibp_checked = _hibp_lookup(client, password)
                    hit = bool(wordlist and password.lower() in wordlist)
                    assessment = assess(
                        password,
                        wordlist_hit=hit,
                        hibp_count=hibp_count,
                        hibp_checked=hibp_checked,
                        dictionary=wordlist,
                    )
                    _print_batch_row(index, assessment)
                    checked_count += 1
                finally:
                    del password
    except OSError as exc:
        print(f"[!] Could not read {path}: {exc}", file=sys.stderr)
        return _EXIT_FILE_ERROR

    print(f"\nChecked {checked_count} passwords.")
    return _EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    wordlist = _load_wordlist(args.wordlist)
    if args.file:
        return _run_file(args, wordlist)
    return _run_interactive(args, wordlist)