"""Unit tests for structural pattern detection."""

from __future__ import annotations

import pytest

from password_strength_checker.patterns import (
    analyze_patterns,
    detect_dictionary_word,
    detect_keyboard_walk,
    detect_leet_substitution,
    detect_repeated_characters,
    detect_sequential_characters,
    normalize_l33t,
)


class TestKeyboardWalks:
    @pytest.mark.parametrize(
        "password",
        ["qwerty", "asdf", "12345", "67890", "zxcvbnm", "poiuyt", "mnbvcxz"],
    )
    def test_common_walks_detected(self, password: str) -> None:
        assert detect_keyboard_walk(password)

    def test_walk_split_across_rows(self) -> None:
        assert detect_keyboard_walk("qwerty123")
        assert detect_keyboard_walk("asdf1234")

    def test_non_walk_passes(self) -> None:
        assert not detect_keyboard_walk("correcthorse")
        assert not detect_keyboard_walk("randomstringx9")

    def test_too_short_to_be_a_walk(self) -> None:
        assert not detect_keyboard_walk("qw")


class TestRepeatedCharacters:
    @pytest.mark.parametrize("password", ["aaaa", "1111", "Pass1111", "aabbbbcc"])
    def test_repeated_runs_detected(self, password: str) -> None:
        assert detect_repeated_characters(password)

    def test_no_repetition(self) -> None:
        assert not detect_repeated_characters("abcdef")


class TestSequentialCharacters:
    @pytest.mark.parametrize(
        "password", ["abcd", "ABCD", "1234", "xyz", "987", "zyx", "nopqrs"]
    )
    def test_sequential_runs_detected(self, password: str) -> None:
        assert detect_sequential_characters(password)

    def test_no_sequence(self) -> None:
        assert not detect_sequential_characters("a1b2c3")
        assert not detect_sequential_characters("x9f2j8k1")


class TestLeetspeak:
    def test_normalize_decodes_substitutions(self) -> None:
        assert normalize_l33t("p@ssw0rd") == "password"
        assert normalize_l33t("l33t") == "leet"
        assert normalize_l33t("plain") == "plain"

    def test_leet_dictionary_word_flagged(self) -> None:
        assert detect_leet_substitution("p@ssw0rd")
        assert detect_leet_substitution("s3cur3pa$$w0rd")

    def test_plain_password_not_flagged(self) -> None:
        assert not detect_leet_substitution("password")
        assert not detect_leet_substitution("Tr0ub4dour&3")

    def test_report_exposes_leet_flags(self) -> None:
        report = analyze_patterns("p@ssw0rd")
        assert report.has_leet_characters is True
        assert report.leet_substitution is True
        assert report.dictionary_word is True


class TestDictionaryWords:
    def test_exact_word_detected(self) -> None:
        assert detect_dictionary_word("monkey")
        assert detect_dictionary_word("Dragon")

    def test_word_with_padding_detected(self) -> None:
        assert detect_dictionary_word("iloveyou2024")
        assert detect_dictionary_word("password123")
        assert detect_dictionary_word("123monkey")

    def test_leet_word_detected(self) -> None:
        assert detect_dictionary_word("p@ssw0rd")

    def test_random_string_passes(self) -> None:
        assert not detect_dictionary_word("x9f2j8k1qm")
        assert not detect_dictionary_word("kLq7#mX2!pV")


class TestAnalyzePatterns:
    def test_strong_random_password_has_no_weakness(self) -> None:
        report = analyze_patterns("X7#kQp!2vLm9$wR")
        assert report.any_weakness is False

    def test_every_weakness_reported(self) -> None:
        report = analyze_patterns("qwerty1111")
        assert report.keyboard_walk is True
        assert report.repeated_characters is True

    def test_empty_password_is_benign(self) -> None:
        report = analyze_patterns("")
        assert report.any_weakness is False