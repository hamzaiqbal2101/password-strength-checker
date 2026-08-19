"""Entropy estimation for passwords.

This module implements the estimate specified for this project:

    entropy = length * log2(pool_size)

where ``pool_size`` is the number of characters an attacker would have to
guess from, assuming they know exactly which character *classes* (lowercase,
uppercase, digits, symbols) are present in the password.

Security note: this is an *upper-bound estimate*, not the true Shannon
entropy of the password's byte stream. A password built from a predictable
pattern (dictionary word, keyboard walk, repetition) has far less real
strength than this formula suggests. Structural weaknesses are handled
separately by ``patterns.py`` and folded into the final score by
``scoring.py``.
"""

from __future__ import annotations

import math
import string

_LOWERCASE_POOL = len(string.ascii_lowercase)  # 26
_UPPERCASE_POOL = len(string.ascii_uppercase)  # 26
_DIGITS_POOL = len(string.digits)  # 10
_SYMBOLS_POOL = len(string.punctuation)  # 32

# Classification thresholds in bits, highest first. Per project spec:
#   Very Strong >= 128, Strong 60-127, Good 36-59, Fair 28-35, Weak < 28.
_CLASSIFICATION_BANDS: tuple[tuple[str, float], ...] = (
    ("Very Strong", 128.0),
    ("Strong", 60.0),
    ("Good", 36.0),
    ("Fair", 28.0),
    ("Weak", 0.0),
)


def character_classes(password: str) -> frozenset[str]:
    """Return the set of character classes present in a password.

    Args:
        password: The password to inspect.

    Returns:
        A frozenset with any subset of ``{"lowercase", "uppercase",
        "digits", "symbols"}``.
    """
    classes: set[str] = set()
    for char in password:
        if char.islower():
            classes.add("lowercase")
        elif char.isupper():
            classes.add("uppercase")
        elif char.isdigit():
            classes.add("digits")
        else:
            classes.add("symbols")
    return frozenset(classes)


def character_pool_size(password: str) -> int:
    """Estimate the attacker's character pool for a given password.

    Args:
        password: The password to analyze.

    Returns:
        The size of the search space per position, computed by summing the
        standard class sizes (26, 26, 10, 32) for every class present. An
        empty password returns 0.
    """
    classes = character_classes(password)
    if not classes:
        return 0
    pool = 0
    if "lowercase" in classes:
        pool += _LOWERCASE_POOL
    if "uppercase" in classes:
        pool += _UPPERCASE_POOL
    if "digits" in classes:
        pool += _DIGITS_POOL
    if "symbols" in classes:
        pool += _SYMBOLS_POOL
    return pool


def shannon_entropy_bits(password: str) -> float:
    """Compute the estimated entropy of a password in bits.

    Uses the formula ``entropy = length * log2(pool_size)``.

    Args:
        password: The password to analyze.

    Returns:
        The estimated entropy in bits, rounded to two decimals. An empty
        password returns 0.0.
    """
    if not password:
        return 0.0
    return round(len(password) * math.log2(character_pool_size(password)), 2)


def classify_entropy(entropy_bits: float) -> str:
    """Map an entropy value (in bits) to a human-readable classification.

    Bands: Weak <28, Fair 28-35, Good 36-59, Strong 60-127,
    Very Strong 128+.

    Args:
        entropy_bits: The entropy value in bits.

    Returns:
        One of ``"Weak"``, ``"Fair"``, ``"Good"``, ``"Strong"`` or
        ``"Very Strong"``.
    """
    for label, threshold in _CLASSIFICATION_BANDS:
        if entropy_bits >= threshold:
            return label
    return "Weak"
