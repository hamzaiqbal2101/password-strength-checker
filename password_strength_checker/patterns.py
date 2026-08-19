"""Structural password-pattern detection.

Detects the weaknesses that defeat a naive entropy estimate:

* Keyboard walks (``qwerty``, ``asdf``, ``12345``, ``zxcvbnm``)
* Repeated characters (``aaaa``, ``1111``)
* Sequential characters (``abcd``, ``1234``, ``9876``)
* Leetspeak substitutions (``p@ssw0rd`` -> ``password``)
* Dictionary words, with or without digit/symbol padding

All detection is case-insensitive. Detection happens on the lowercase
password so mixed-case does not hide a pattern.
"""

from __future__ import annotations

import re
import string
from collections.abc import Collection, Iterable
from dataclasses import dataclass

# Rows of a standard QWERTY keyboard. Each row is checked both forward and
# in reverse so that walks like "poiuyt" are caught too.
_KEYBOARD_ROWS: tuple[str, ...] = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "!@#$%^&*()",
)

# Sequences that are trivially guessable in order (forward or reverse).
_SEQUENCES: tuple[str, ...] = (
    string.ascii_lowercase,
    string.digits,
)

# A small built-in dictionary of very common base words so that dictionary
# detection still works when no external wordlist has been downloaded.
_COMMON_BASE_WORDS: frozenset[str] = frozenset(
    {
        "admin", "administrator", "baseball", "batman", "cheese", "dragon",
        "football", "freedom", "hello", "hunter", "iloveyou", "jordan",
        "letmein", "login", "master", "michael", "monkey", "mustang",
        "ninja", "password", "princess", "qwerty", "secret", "shadow",
        "starwars", "sunshine", "superman", "trustno1", "welcome", "whatever",
    }
)

# Minimum run length considered meaningful for keyboard / sequence checks.
_MIN_RUN = 3

# Maps leetspeak characters back to their plaintext equivalents. Because
# several symbols map to the same letter (e.g. "1" and "!" both to "i"),
# the mapping is keyed by unicode ordinal and passed to str.translate().
_L33T_TRANSLATION: dict[int, str] = {
    ord("0"): "o",
    ord("1"): "i",
    ord("2"): "z",
    ord("3"): "e",
    ord("4"): "a",
    ord("5"): "s",
    ord("6"): "g",
    ord("7"): "t",
    ord("8"): "b",
    ord("9"): "g",
    ord("@"): "a",
    ord("!"): "i",
    ord("$"): "s",
    ord("("): "c",
    ord(")"): "c",
    ord("+"): "t",
}

# Matches three or more of the same character in a row.
_REPEAT_PATTERN = re.compile(r"(.)\1{2,}")

# Minimum length of a contiguous keyboard run that counts as a walk.
_MIN_WALK = 4

# The maximum length of a dictionary word we hunt for as a substring. Longer
# substrings are unlikely to be real words and bounding this keeps detection
# linear-ish in password length even against 100k-entry wordlists.
_MAX_SUBSTRING_WORD = 12


@dataclass(frozen=True)
class PatternReport:
    """Immutable summary of the structural weaknesses found in a password.

    Attributes:
        keyboard_walk: Password is a run over one or more keyboard rows.
        repeated_characters: Password contains 3+ identical consecutive
            characters (e.g. ``aaaa``, ``1111``).
        sequential_characters: Password contains a contiguous run such as
            ``abcd`` or ``1234`` (forward or reverse).
        dictionary_word: Password is or contains a known dictionary word.
        leet_substitution: Leetspeak was used AND it decodes to a dictionary
            word (e.g. ``p@ssw0rd``). This is the truly dangerous case.
        has_leet_characters: Password contains leetspeak characters,
            regardless of whether they decode to a known word.
    """

    keyboard_walk: bool
    repeated_characters: bool
    sequential_characters: bool
    dictionary_word: bool
    leet_substitution: bool
    has_leet_characters: bool

    @property
    def any_weakness(self) -> bool:
        """True when any structural weakness was detected."""
        return any(
            (
                self.keyboard_walk,
                self.repeated_characters,
                self.sequential_characters,
                self.dictionary_word,
                self.leet_substitution,
            )
        )


def _build_sequential_substrings() -> frozenset[str]:
    """Precompute every contiguous run of length >= 3 in each sequence."""
    substrings: set[str] = set()
    for sequence in _SEQUENCES:
        for direction in (sequence, sequence[::-1]):
            for start in range(len(direction)):
                for end in range(start + _MIN_RUN, len(direction) + 1):
                    substrings.add(direction[start:end])
    return frozenset(substrings)


_SEQUENTIAL_SUBSTRINGS = _build_sequential_substrings()


def _build_keyboard_walk_substrings() -> frozenset[str]:
    """Precompute every contiguous run (length >= _MIN_WALK) of each row.

    Both forward and reversed rows are included so walks like ``poiuyt`` are
    caught. A password counts as a keyboard walk if it *contains* any of
    these runs; this deliberately handles composite passwords such as
    ``qwerty123`` (contains ``qwerty``) and ``asdf1234``.
    """
    walks: set[str] = set()
    for row in _KEYBOARD_ROWS:
        for direction in (row, row[::-1]):
            for start in range(len(direction)):
                for end in range(start + _MIN_WALK, len(direction) + 1):
                    walks.add(direction[start:end])
    return frozenset(walks)


_KEYBOARD_WALK_SUBSTRINGS = _build_keyboard_walk_substrings()


def normalize_l33t(password: str) -> str:
    """Decode common leetspeak substitutions back to plaintext.

    Args:
        password: The password to normalize.

    Returns:
        The password with leetspeak characters mapped to their plaintext
        equivalents (e.g. ``p@ssw0rd`` -> ``password``).
    """
    return password.translate(_L33T_TRANSLATION)


def detect_keyboard_walk(password: str) -> bool:
    """Detect a QWERTY keyboard walk within a password.

    The password counts as a keyboard walk when it contains any contiguous
    run of at least ``_MIN_WALK`` (4) characters from a keyboard row, forward
    or reversed (``qwerty``, ``asdf``, ``12345``, ``poiuyt``). Substring
    matching also catches composite passwords like ``qwerty123`` or
    ``asdf1234``.

    Args:
        password: The password to check.

    Returns:
        True if a keyboard walk is present.
    """
    if len(password) < _MIN_WALK:
        return False
    lowered = password.lower()
    return any(walk in lowered for walk in _KEYBOARD_WALK_SUBSTRINGS)


def detect_repeated_characters(password: str) -> bool:
    """Detect runs of three or more identical consecutive characters.

    Args:
        password: The password to check.

    Returns:
        True if a run such as ``aaaa`` or ``1111`` is present.
    """
    return _REPEAT_PATTERN.search(password) is not None


def detect_sequential_characters(password: str) -> bool:
    """Detect contiguous character runs such as ``abcd`` or ``1234``.

    Runs are matched case-insensitively and in both directions, so ``zyx``
    and ``9876`` are caught as well.

    Args:
        password: The password to check.

    Returns:
        True if any run of at least three ordered characters is present.
    """
    if len(password) < _MIN_RUN:
        return False
    lowered = password.lower()
    return any(substring in lowered for substring in _SEQUENTIAL_SUBSTRINGS)


def _dictionary_hit(normalized: str, dictionary: Collection[str]) -> bool:
    """Return True when ``normalized`` matches or contains a dictionary word.

    Performs an exact match, a match after stripping digit/symbol padding,
    and a bounded substring scan (words of 4-12 characters). Substring scans
    against a large wordlist are kept fast by iterating over the *password's*
    substrings (bounded count) and doing set lookups instead of iterating the
    whole wordlist per password.

    Args:
        normalized: Lowercased (and leetspeak-decoded) password.
        dictionary: Iterable of candidate words.

    Returns:
        True if a dictionary word is present.
    """
    words = set(dictionary)
    if normalized in words:
        return True

    padded = normalized.strip(string.digits + string.punctuation)
    if len(padded) >= 3 and padded in words:
        return True

    for start in range(len(normalized)):
        limit = min(start + _MAX_SUBSTRING_WORD, len(normalized))
        for end in range(start + 4, limit + 1):
            if normalized[start:end] in words:
                return True
    return False


def detect_dictionary_word(
    password: str, dictionary: Collection[str] | None = None
) -> bool:
    """Detect dictionary words in a password.

    Args:
        password: The password to check.
        dictionary: Optional word list; defaults to a small built-in list of
            common base words.

    Returns:
        True when the password is, or contains, a dictionary word.
    """
    if not password:
        return False
    words = dictionary if dictionary is not None else _COMMON_BASE_WORDS
    return _dictionary_hit(normalize_l33t(password.lower()), words)


def detect_leet_substitution(
    password: str, dictionary: Collection[str] | None = None
) -> bool:
    """Detect leetspeak that decodes to a dictionary word.

    Args:
        password: The password to check.
        dictionary: Optional word list; defaults to the built-in base words.

    Returns:
        True when leetspeak is present and it decodes to a known word (the
        ``p@ssw0rd`` case).
    """
    if not password:
        return False
    lowered = password.lower()
    normalized = normalize_l33t(lowered)
    if normalized == lowered:
        return False
    words = dictionary if dictionary is not None else _COMMON_BASE_WORDS
    return _dictionary_hit(normalized, words)


def is_common_base_word(password: str) -> bool:
    """Return True when a password is exactly a well-known common base word.

    This powers the offline "known-bad" hard cap: even without a downloaded
    wordlist or network access, exact matches against the built-in list of
    extremely common passwords are treated as inherently weak.

    Args:
        password: The password to check.

    Returns:
        True for exact (case-insensitive) matches against
        :data:`_COMMON_BASE_WORDS`.
    """
    return bool(password) and password.lower() in _COMMON_BASE_WORDS


def _iter_words(wordlist: Iterable[str]) -> set[str]:
    """Normalize an iterable of words into a lowercase, whitespace-free set.

    Args:
        wordlist: Raw word list (e.g. lines from a file).

    Returns:
        A set of normalized words.
    """
    words: set[str] = set()
    for raw in wordlist:
        word = raw.strip().lower()
        if word:
            words.add(word)
    return words


def analyze_patterns(
    password: str, dictionary: Collection[str] | None = None
) -> PatternReport:
    """Run every structural pattern detector and summarize the results.

    Args:
        password: The password to analyze.
        dictionary: Optional external word list used for dictionary and
            leetspeak checks. When ``None``, a built-in list of common base
            words is used.

    Returns:
        A :class:`PatternReport` describing all detected weaknesses.
    """
    lowered = password.lower()
    normalized = normalize_l33t(lowered)
    words = (
        _iter_words(dictionary)
        if dictionary is not None
        else _COMMON_BASE_WORDS
    )
    has_leet = normalized != lowered
    dict_hit = _dictionary_hit(normalized, words)
    return PatternReport(
        keyboard_walk=detect_keyboard_walk(lowered),
        repeated_characters=detect_repeated_characters(password),
        sequential_characters=detect_sequential_characters(lowered),
        dictionary_word=dict_hit,
        leet_substitution=has_leet and dict_hit,
        has_leet_characters=has_leet,
    )
