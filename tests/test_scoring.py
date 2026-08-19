"""Unit tests for the weighted scoring model."""

from __future__ import annotations

import pytest

from password_strength_checker.scoring import (
    BreachStatus,
    assess,
    strength_label_from_score,
)


def test_empty_password_rejected() -> None:
    with pytest.raises(ValueError):
        assess("")


def test_trivial_password_scores_very_low() -> None:
    result = assess("password", wordlist_hit=True)
    assert result.score < 30
    assert result.strength_label in {"Very Weak", "Weak"}
    assert result.breach_status is BreachStatus.COMMON_WORDLIST


def test_offline_common_base_word_is_hard_capped() -> None:
    result = assess("password")  # no wordlist, no network
    assert result.breach_status is BreachStatus.COMMON_WORDLIST
    assert result.score <= 25
    assert result.strength_label == "Very Weak"


def test_keyboard_walk_is_penalized() -> None:
    walk = assess("qwertyuiop")
    random_like = assess("q7#Km2x!9vL")
    assert walk.score < random_like.score


def test_pwned_password_is_penalized_vs_clean() -> None:
    password = "Tr0ub4dour&3"
    clean = assess(password, hibp_checked=True, hibp_count=0)
    pwned = assess(password, hibp_checked=True, hibp_count=42)
    assert pwned.score < clean.score
    assert pwned.breach_status is BreachStatus.HIBP_PWNED
    assert pwned.pwn_count == 42
    assert clean.breach_status is BreachStatus.HIBP_CLEAN


def test_strong_password_scores_high() -> None:
    result = assess(
        "X7#kQp!2vLm9$wR", hibp_checked=True, hibp_count=0
    )
    assert result.score >= 80
    assert result.strength_label == "Very Strong"
    assert result.entropy_class in {"Strong", "Very Strong"}


def test_unchecked_status_is_unknown() -> None:
    result = assess("somepassword")
    assert result.breach_status is BreachStatus.UNKNOWN


def test_failed_hibp_treated_as_unknown() -> None:
    result = assess("somepassword", hibp_checked=True, hibp_count=None)
    assert result.breach_status is BreachStatus.UNKNOWN


def test_score_clamped_to_range() -> None:
    very_weak = assess("a")
    assert 0 <= very_weak.score <= 100
    strong = assess("CorrectHorseBatteryStaple!x9#Q", hibp_checked=True, hibp_count=0)
    assert 0 <= strong.score <= 100


def test_feedback_is_actionable_and_nonempty() -> None:
    result = assess("password", wordlist_hit=True)
    assert result.feedback
    joined = " ".join(result.feedback).lower()
    assert "common password" in joined


def test_assessment_never_contains_raw_password() -> None:
    password = "Hunter2Secret!"
    result = assess(password)
    assert password not in str(result.feedback)
    assert password not in str(result)


def test_feedback_missing_symbol_hint() -> None:
    result = assess("abcdefghijk", hibp_checked=True, hibp_count=0)
    assert any("symbol" in m for m in result.feedback)


def test_feedback_length_hint() -> None:
    result = assess("abc")
    assert any("8 characters" in m for m in result.feedback)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Very Weak"),
        (24, "Very Weak"),
        (25, "Weak"),
        (49, "Weak"),
        (50, "Fair"),
        (69, "Fair"),
        (70, "Strong"),
        (89, "Strong"),
        (90, "Very Strong"),
        (100, "Very Strong"),
    ],
)
def test_strength_label_boundaries(score: int, expected: str) -> None:
    assert strength_label_from_score(score) == expected