"""Unit tests for wordlist and Have I Been Pwned (k-anonymity) checks."""

from __future__ import annotations

import hashlib

import pytest
import requests

from password_strength_checker.breach import (
    HibpClient,
    HibpError,
    check_wordlist,
    load_wordlist,
)


class _FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class _FakeSession:
    """Minimal requests.Session stand-in that records the request and can
    simulate either a response or a transport-level failure."""

    def __init__(
        self,
        response: _FakeResponse | None = None,
        exc: Exception | None = None,
    ) -> None:
        self.response = response
        self.exc = exc
        self.url: str | None = None
        self.headers: dict | None = None
        self.timeout: float | None = None

    def get(self, url: str, headers: dict | None = None, timeout: float | None = None) -> _FakeResponse:
        self.url = url
        self.headers = headers
        self.timeout = timeout
        if self.exc is not None:
            raise self.exc
        assert self.response is not None
        return self.response


class TestWordlist:
    def test_load_wordlist_normalizes_entries(self, tmp_path) -> None:
        path = tmp_path / "list.txt"
        path.write_text("password\n  Password \nMONKEY\n\n", encoding="utf-8")
        words = load_wordlist(path)
        assert words == frozenset({"password", "monkey"})

    def test_load_wordlist_missing_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            load_wordlist(tmp_path / "does-not-exist.txt")

    def test_check_wordlist_case_insensitive(self) -> None:
        assert check_wordlist("password", {"password"}) is True
        assert check_wordlist("Password123", {"password123"}) is True
        assert check_wordlist("P@SSWORD", {"p@ssword"}) is True
        assert check_wordlist("x9f2kq", {"password"}) is False


class TestHibpKAnonymity:
    def test_only_hash_prefix_transmitted(self) -> None:
        password = "CorrectHorseBatteryStaple!"
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        suffix = digest[5:]
        session = _FakeSession(_FakeResponse(200, f"{suffix}:8675309\n"))
        client = HibpClient(timeout=3.0, session=session)

        assert client.check(password) == 8675309

        # The request URL contains exactly the 5-char prefix and nothing more.
        assert session.url is not None
        assert session.url.startswith("https://api.pwnedpasswords.com/range/")
        prefix = session.url.rsplit("/", 1)[1]
        assert prefix == digest[:5]
        assert len(prefix) == 5
        assert digest[5:] not in session.url
        assert password not in session.url

    def test_password_not_found_returns_zero(self) -> None:
        session = _FakeSession(_FakeResponse(200, "AAAAA:5\nBBBBB:2\n"))
        client = HibpClient(session=session)
        assert client.check("totally-not-present") == 0

    def test_non_http_response_raises(self) -> None:
        session = _FakeSession(_FakeResponse(500, "boom"))
        client = HibpClient(session=session)
        with pytest.raises(HibpError):
            client.check("password")

    def test_network_failure_raises_hibp_error(self) -> None:
        session = _FakeSession(exc=requests.ConnectionError("offline"))
        client = HibpClient(session=session)
        with pytest.raises(HibpError):
            client.check("password")

    def test_timeout_used_from_constructor(self) -> None:
        session = _FakeSession(_FakeResponse(200, ""))
        client = HibpClient(timeout=1.25, session=session)
        client.check("password")
        assert session.timeout == 1.25

    def test_error_messages_do_not_leak_password(self) -> None:
        password = "SuperSecretValue1!"
        session = _FakeSession(_FakeResponse(500, "err"))
        client = HibpClient(session=session)
        with pytest.raises(HibpError) as excinfo:
            client.check(password)
        assert password not in str(excinfo.value)