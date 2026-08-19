"""Unit tests for entropy estimation and classification."""

from __future__ import annotations

import math

import pytest

from password_strength_checker.entropy import (
    character_classes,
    character_pool_size,
    classify_entropy,
    shannon_entropy_bits,
)


def test_empty_password_entropy_is_zero() -> None:
    assert shannon_entropy_bits("") == 0.0


def test_empty_password_pool_is_zero() -> None:
    assert character_pool_size("") == 0


def test_empty_password_has_no_classes() -> None:
    assert character_classes("") == frozenset()


@pytest.mark.parametrize(
    ("password", "expected_pool"),
    [
        ("aaaa", 26),  # lowercase only
        ("Aaaa", 52),  # lower + upper
        ("Aaa1", 62),  # + digits
        ("Aa1!", 94),  # + symbols (string.punctuation == 32)
    ],
)
def test_pool_size_for_character_classes(
    password: str, expected_pool: int
) -> None:
    assert character_pool_size(password) == expected_pool


def test_character_classes_detected() -> None:
    assert character_classes("aA1!") == frozenset(
        {"lowercase", "uppercase", "digits", "symbols"}
    )


def test_entropy_follows_formula() -> None:
    # 4 chars drawn from a pool of 94 -> 4 * log2(94) bits.
    expected = 4 * math.log2(94)
    assert shannon_entropy_bits("Aa1!") == pytest.approx(expected, abs=0.01)


def test_entropy_is_additive_in_length() -> None:
    # Doubling length (same pool) doubles entropy.
    single = shannon_entropy_bits("a")
    double = shannon_entropy_bits("aa")
    assert double == pytest.approx(2 * single, abs=0.01)


@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        (0.0, "Weak"),
        (27.9, "Weak"),
        (28.0, "Fair"),
        (35.9, "Fair"),
        (36.0, "Good"),
        (59.9, "Good"),
        (60.0, "Strong"),
        (127.9, "Strong"),
        (128.0, "Very Strong"),
        (200.0, "Very Strong"),
    ],
)
def test_classification_bands(bits: float, expected: str) -> None:
    assert classify_entropy(bits) == expected