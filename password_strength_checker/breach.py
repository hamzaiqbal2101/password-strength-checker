"""Common-password and data-breach checks.

Two independent checks are provided:

1. **Local wordlist** -- an exact (case-insensitive) match against a
   common-passwords list such as SecLists' top 10k or a rockyou subset.
   No network access is required.

2. **Have I Been Pwned range API** -- a k-anonymity query. Only the first
   five characters of the password's SHA-1 hash are sent to HIBP; the API
   returns the list of matching hash suffixes and their breach counts.
   The full password and the full hash never leave the machine.

Security properties worth noting for the HIBP integration:

* We never transmit the password, only ``sha1(password)[:5]``.
* Requests use a descriptive User-Agent (HIBP policy requirement) and a
  bounded timeout so a slow/unreachable API degrades gracefully to an
  "unknown" breach status instead of hanging or crashing the tool.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection
from pathlib import Path

import requests

# HIBP range API endpoint. The prefix is appended at query time.
_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# HIBP asks clients to identify themselves with a descriptive User-Agent.
_USER_AGENT = "password-strength-checker/1.0 (educational security portfolio project; contact: local)"

_SHA1_PREFIX_LENGTH = 5


class HibpError(Exception):
    """Raised when the Have I Been Pwned API cannot be queried.

    The message is safe to surface to users (it never contains password or
    hash material).
    """


def load_wordlist(path: str | Path) -> frozenset[str]:
    """Load a common-passwords wordlist into memory.

    Words are lowercased, stripped of surrounding whitespace, and deduplicated
    so lookups are consistent with the case-insensitive matching performed
    during a check.

    Args:
        path: Path to the wordlist file (one word per line).

    Returns:
        A frozenset of normalized words.

    Raises:
        FileNotFoundError: If ``path`` does not exist or is not a file.
    """
    word_path = Path(path)
    if not word_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {word_path}")
    words: set[str] = set()
    with word_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            word = raw.strip().lower()
            if word:
                words.add(word)
    return frozenset(words)


def check_wordlist(
    password: str, wordlist: Collection[str] | frozenset[str] | set[str]
) -> bool:
    """Check a password against a set of known-bad passwords.

    Args:
        password: The password to check.
        wordlist: Collection of known passwords (already normalized by
            :func:`load_wordlist`, or a plain iterable of strings).

    Returns:
        True when the password matches a known-bad password
        (case-insensitively).
    """
    words = wordlist if isinstance(wordlist, (set, frozenset)) else set(wordlist)
    return password.lower() in words


class HibpClient:
    """Client for the Have I Been Pwned range API (k-anonymity).

    Args:
        timeout: Request timeout in seconds.
        session: Optional ``requests.Session``; primarily used for tests.
    """

    def __init__(self, timeout: float = 5.0, session: requests.Session | None = None) -> None:
        self.timeout = timeout
        self._session = session if session is not None else requests.Session()
        if getattr(self._session, "headers", None) is None:
            self._session.headers = {}
        self._session.headers["User-Agent"] = _USER_AGENT

    def check(self, password: str) -> int:
        """Return how many times a password appears in known breaches.

        Only the first five characters of the SHA-1 hash are sent to the
        remote service (``hash = sha1(password)``, transmit ``hash[:5]``).
        The response is searched for the matching suffix locally.

        Args:
            password: The password to look up. It is only used to derive the
                SHA-1 hash and is not transmitted.

        Returns:
            The number of times the password was seen in breaches; 0 if it
            was not found.

        Raises:
            HibpError: If the API is unreachable, times out, or returns an
                unexpected status code. The message never contains password
                material.
        """
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:_SHA1_PREFIX_LENGTH], digest[_SHA1_PREFIX_LENGTH:]

        try:
            response = self._session.get(
                _HIBP_RANGE_URL.format(prefix=prefix), timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise HibpError(f"HIBP request failed: {exc}") from exc

        if response.status_code != 200:
            raise HibpError(f"HIBP returned HTTP {response.status_code}")

        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            response_suffix, count_raw = line.split(":", 1)
            if response_suffix.upper() == suffix:
                try:
                    return int(count_raw)
                except ValueError:
                    return 0
        return 0
