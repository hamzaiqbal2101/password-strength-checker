"""CLI integration tests: verify passwords are never echoed or logged."""

from __future__ import annotations

import pytest

from password_strength_checker.cli import main


def test_file_mode_never_echoes_passwords(tmp_path, capsys) -> None:
    batch = tmp_path / "batch.txt"
    batch.write_text(
        "hunter2\npassword123\nIloveyou2024!\n", encoding="utf-8"
    )
    exit_code = main(["--file", str(batch), "--no-network"])
    out, err = capsys.readouterr()

    assert exit_code == 0
    for secret in ("hunter2", "password123", "Iloveyou2024!"):
        assert secret not in out
        assert secret not in err
    assert "Score" in out


def test_interactive_uses_getpass_and_hides_password(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "password_strength_checker.cli.getpass.getpass",
        lambda prompt="": "secretpw123",
    )
    exit_code = main(["--no-network"])
    out, _ = capsys.readouterr()

    assert exit_code == 0
    assert "secretpw123" not in out
    assert "Score" in out


def test_empty_password_rejected(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "password_strength_checker.cli.getpass.getpass",
        lambda prompt="": "",
    )
    exit_code = main(["--no-network"])
    assert exit_code == 1


def test_missing_file_returns_error_code(tmp_path, capsys) -> None:
    exit_code = main(["--file", str(tmp_path / "missing.txt"), "--no-network"])
    assert exit_code == 2


def test_batch_mode_respects_wordlist(tmp_path, capsys) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n123456\n", encoding="utf-8")
    batch = tmp_path / "batch.txt"
    batch.write_text("password\n", encoding="utf-8")

    exit_code = main(
        ["--file", str(batch), "--wordlist", str(wordlist), "--no-network"]
    )
    out, _ = capsys.readouterr()

    assert exit_code == 0
    assert "wordlist" in out.lower()


def test_version_flag(tmp_path, capsys) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    out, _ = capsys.readouterr()
    assert "password-strength-checker" in out