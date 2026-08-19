"""Weighted scoring model that combines all signals into one 0-100 score.

The score blends three independent signals:

================  =====  =====================================================
Component         Weight  Rationale
================  =====  =====================================================
Entropy           0.40   Raw search-space size. A strong prior but useless on
                        its own: a long keyboard walk has high entropy yet is
                        trivially guessable.
Breach status     0.30   Empirical evidence. If the password (or something
                        like it) has already leaked, attackers will hit it
                        first regardless of how clever it looks.
Patterns          0.30   Structural weaknesses (dictionary words, keyboard
                        walks, sequences, repetition). These collapse the
                        effective entropy far below the estimate.
================  =====  =====================================================

Weights are deliberately close to equal because each signal is necessary:
entropy rewards size, breach status rewards novelty, and pattern detection
penalizes structure. A password is only strong when it is big, fresh, and
unstructured -- exactly what this mix rewards.

The final score is ``round(100 * (0.40*E + 0.30*B + 0.30*P))`` clamped to
[0, 100], where E, B and P are component scores in [0, 1] described below.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum

from password_strength_checker.entropy import (
    character_classes,
    classify_entropy,
    shannon_entropy_bits,
)
from password_strength_checker.patterns import (
    PatternReport,
    analyze_patterns,
    is_common_base_word,
)

# Component weights (see module docstring for rationale).
_WEIGHT_ENTROPY = 0.40
_WEIGHT_BREACH = 0.30
_WEIGHT_PATTERNS = 0.30

# Breach component score per status. A wordlist hit means the password is a
# known-bad first guess -> 0. A confirmed breach hit is almost as bad. An
# "unknown" (offline / API failure) is mildly penalized because we simply
# cannot vouch for it. A clean HIBP result is best.
_BREACH_COMPONENT = {
    "COMMON_WORDLIST": 0.0,
    "HIBP_PWNED": 0.15,
    "UNKNOWN": 0.70,
    "HIBP_CLEAN": 1.0,
}

# Anchors for the piecewise-linear entropy->component curve. Interpolating
# between the classification band edges keeps the curve smooth instead of
# snapping at band boundaries.
_ENTROPY_CURVE: tuple[tuple[float, float], ...] = (
    (0.0, 0.00),
    (28.0, 0.30),   # Weak   < 28 bits
    (36.0, 0.55),   # Fair   28-35
    (60.0, 0.80),   # Good   36-59
    (128.0, 1.00),  # Strong / Very Strong 60+
)

# Pattern penalties. Each is subtracted from a 1.0 baseline. The floor keeps
# a heavily patterned password from scoring zero purely on structure.
_PATTERN_PENALTIES: tuple[tuple[str, float], ...] = (
    ("keyboard_walk", 0.35),
    ("dictionary_word", 0.35),
    ("sequential_characters", 0.20),
    ("leet_substitution", 0.20),
    ("repeated_characters", 0.15),
)
_PATTERN_FLOOR = 0.05


class BreachStatus(Enum):
    """Outcome of the breach checks for a single password."""

    COMMON_WORDLIST = "common-wordlist"  # Found in local common-passwords list
    HIBP_PWNED = "hibp-pwned"  # Found in the HIBP breach corpus
    HIBP_CLEAN = "clean"  # Checked against HIBP, no matches
    UNKNOWN = "unknown"  # Wordlist absent and/or HIBP unreachable

    @property
    def label(self) -> str:
        """Short human-readable label for CLI output."""
        return {
            BreachStatus.COMMON_WORDLIST: "wordlist",
            BreachStatus.HIBP_PWNED: "pwned",
            BreachStatus.HIBP_CLEAN: "clean",
            BreachStatus.UNKNOWN: "unknown",
        }[self]


@dataclass(frozen=True)
class Assessment:
    """Immutable result of a full password assessment.

    The raw password is intentionally NOT stored here; only derived metrics.
    """

    password_length: int
    entropy_bits: float
    entropy_class: str
    breach_status: BreachStatus
    pwn_count: int
    patterns: PatternReport
    score: int  # 0-100
    strength_label: str
    feedback: tuple[str, ...]


def strength_label_from_score(score: int) -> str:
    """Map a 0-100 score to a human-readable strength label.

    Args:
        score: The final score (0-100).

    Returns:
        ``"Very Weak"`` (<25), ``"Weak"`` (<50), ``"Fair"`` (<70),
        ``"Strong"`` (<90) or ``"Very Strong"`` (>=90).
    """
    if score < 25:
        return "Very Weak"
    if score < 50:
        return "Weak"
    if score < 70:
        return "Fair"
    if score < 90:
        return "Strong"
    return "Very Strong"


def _entropy_component(entropy_bits: float) -> float:
    """Map entropy (bits) to a [0, 1] component via linear interpolation."""
    for (x0, y0), (x1, y1) in zip(_ENTROPY_CURVE, _ENTROPY_CURVE[1:]):
        if entropy_bits <= x1:
            return y0 + (y1 - y0) * (entropy_bits - x0) / (x1 - x0)
    return 1.0


def _breach_component(status: BreachStatus) -> float:
    """Map a breach status to its [0, 1] component score."""
    return _BREACH_COMPONENT[status.name]


def _pattern_component(report: PatternReport) -> float:
    """Map a pattern report to a [0, 1] component score.

    Starts at a clean 1.0 and subtracts a fixed penalty per detected
    weakness, floored so heavily patterned passwords keep a small residual.
    """
    score = 1.0
    for field, penalty in _PATTERN_PENALTIES:
        if getattr(report, field):
            score -= penalty
    return max(_PATTERN_FLOOR, score)


def _resolve_breach_status(
    wordlist_hit: bool,
    hibp_count: int | None,
    hibp_checked: bool,
) -> BreachStatus:
    """Derive a single breach status from the available signals."""
    if wordlist_hit:
        return BreachStatus.COMMON_WORDLIST
    if hibp_checked:
        if hibp_count is None:
            return BreachStatus.UNKNOWN
        return BreachStatus.HIBP_PWNED if hibp_count > 0 else BreachStatus.HIBP_CLEAN
    return BreachStatus.UNKNOWN


def _build_feedback(
    length: int,
    entropy_class: str,
    status: BreachStatus,
    pwn_count: int,
    report: PatternReport,
    score: int,
    classes: frozenset[str],
) -> list[str]:
    """Generate actionable, ordered feedback messages.

    Breach findings come first (most important), then length guidance, then
    structural weaknesses, then class/character guidance.
    """
    messages: list[str] = []

    if status is BreachStatus.COMMON_WORDLIST:
        messages.append(
            "This is a well-known common password - attackers try it first."
        )
    elif status is BreachStatus.HIBP_PWNED:
        messages.append(
            f"Found in a known data breach ({pwn_count:,} times). "
            "Do not reuse this password anywhere."
        )

    if length < 8:
        messages.append("Use at least 8 characters - 12+ is strongly recommended.")
    elif entropy_class in {"Weak", "Fair"}:
        messages.append(
            "Increase length and character variety to raise entropy above 36 bits."
        )

    if report.keyboard_walk:
        messages.append("Avoid sequential keyboard patterns such as 'qwerty' or '12345'.")
    if report.sequential_characters:
        messages.append("Avoid sequential runs like 'abcd' or '1234'.")
    if report.repeated_characters:
        messages.append("Avoid repeated characters such as 'aaaa' or '1111'.")
    if report.leet_substitution:
        messages.append(
            "Leetspeak substitutions ('p@ssw0rd') are trivially reversed - "
            "avoid dictionary words entirely."
        )
    elif report.dictionary_word:
        messages.append("Avoid dictionary words - these are cracked in seconds.")

    if length >= 8 and "symbols" not in classes:
        messages.append("Add symbols (!@#$%&*) to widen the character pool.")

    if score >= 80 and not report.any_weakness:
        messages.append("Strong password - no common patterns detected.")
    if not messages:
        messages.append(
            "No major weaknesses detected, but length and uniqueness matter most."
        )
    return messages


def assess(
    password: str,
    *,
    wordlist_hit: bool = False,
    hibp_count: int | None = None,
    hibp_checked: bool = False,
    dictionary: Collection[str] | None = None,
) -> Assessment:
    """Assess a password and produce a full, scored report.

    Args:
        password: The password to assess. It is never stored on the returned
            :class:`Assessment`; callers should ``del`` it after use.
        wordlist_hit: True if the password matched a common-passwords list.
            Exact matches against a built-in list of common base words count
            automatically, even when run fully offline.
        hibp_count: Number of HIBP breach hits, or None when not queried.
        hibp_checked: True if an HIBP query was actually attempted.
        dictionary: Optional external word list for pattern detection.
            Defaults to the built-in base words.

    Returns:
        An :class:`Assessment` with entropy, breach status, pattern report,
        final 0-100 score, strength label, and actionable feedback.

    Raises:
        ValueError: If ``password`` is empty.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    # A password that exactly equals a well-known common base word counts as
    # a wordlist hit even when no external wordlist is loaded or the tool is
    # run fully offline.
    effective_wordlist_hit = wordlist_hit or is_common_base_word(password)

    entropy_bits = shannon_entropy_bits(password)
    entropy_class = classify_entropy(entropy_bits)
    report = analyze_patterns(password, dictionary)
    status = _resolve_breach_status(
        effective_wordlist_hit, hibp_count, hibp_checked
    )

    entropy_score = _entropy_component(entropy_bits)
    breach_score = _breach_component(status)
    pattern_score = _pattern_component(report)

    raw_score = (
        _WEIGHT_ENTROPY * entropy_score
        + _WEIGHT_BREACH * breach_score
        + _WEIGHT_PATTERNS * pattern_score
    )
    score = max(0, min(100, round(raw_score * 100)))

    # Hard cap: a password found in a common-passwords wordlist (or exactly
    # equal to a well-known base word) is inherently weak regardless of its
    # entropy, because attackers exhaust the whole list before trying
    # anything else. Cap it at the top of the "Very Weak" band.
    if status is BreachStatus.COMMON_WORDLIST:
        score = min(score, 24)

    label = strength_label_from_score(score)
    classes = character_classes(password)
    feedback = tuple(
        _build_feedback(
            len(password), entropy_class, status, hibp_count or 0, report, score, classes
        )
    )

    return Assessment(
        password_length=len(password),
        entropy_bits=entropy_bits,
        entropy_class=entropy_class,
        breach_status=status,
        pwn_count=hibp_count if status is BreachStatus.HIBP_PWNED else 0,
        patterns=report,
        score=score,
        strength_label=label,
        feedback=feedback,
    )
