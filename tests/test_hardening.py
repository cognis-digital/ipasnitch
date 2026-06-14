"""Hardening tests: error paths, edge cases, and input validation.

These tests cover the guardrails added during production hardening and must
never be weakened or deleted.
"""
from __future__ import annotations

import io
import json
import plistlib

import pytest

from ipasnitch.core import (
    Finding,
    ScanResult,
    parse_plist,
    scan_file,
    scan_plist,
)
from ipasnitch.cli import main


# ---------------------------------------------------------------------------
# parse_plist edge cases
# ---------------------------------------------------------------------------

def test_parse_plist_rejects_empty_bytes():
    """Empty bytes must raise ValueError with a clear message, not an
    opaque plistlib exception."""
    with pytest.raises(ValueError, match="empty"):
        parse_plist(b"")


def test_parse_plist_rejects_garbage():
    """Garbage bytes must raise ValueError, not leak a raw plistlib exception."""
    with pytest.raises(ValueError, match="could not parse plist"):
        parse_plist(b"\x00\x01\x02\x03 not a plist at all")


def test_parse_plist_rejects_truncated_xml():
    with pytest.raises(ValueError, match="could not parse plist"):
        parse_plist(b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Foo")


# ---------------------------------------------------------------------------
# scan_file edge cases
# ---------------------------------------------------------------------------

def test_scan_file_empty_path_returns_error():
    """An empty string path must return a ScanResult with an error, not crash."""
    result = scan_file("")
    assert result.error is not None
    assert "empty" in result.error.lower()


def test_scan_file_missing_file_returns_error():
    """A non-existent file must return ScanResult.error, not raise."""
    result = scan_file("/no/such/file/Info.plist")
    assert result.error is not None
    assert result.findings == []


def test_scan_file_empty_plist_on_disk(tmp_path):
    """A zero-byte file must return a clean error, not crash."""
    p = tmp_path / "empty.plist"
    p.write_bytes(b"")
    result = scan_file(str(p))
    assert result.error is not None
    assert result.findings == []


def test_scan_file_accepts_pathlib_path(tmp_path):
    """scan_file should accept a pathlib.Path (coerced to str internally)."""
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.test"}))
    result = scan_file(p)  # Pass Path object, not str.
    assert result.error is None


# ---------------------------------------------------------------------------
# scan_plist edge cases
# ---------------------------------------------------------------------------

def test_scan_plist_empty_dict():
    """An empty dict is a valid (if minimal) plist — should not crash."""
    result = scan_plist({})
    assert result.error is None
    # Only the info-level "ats-not-configured" finding is expected.
    assert all(f.severity == "info" for f in result.findings)


def test_scan_plist_deeply_nested_dict(tmp_path):
    """Deeply nested dicts must not overflow the stack."""
    obj: dict = {"leaf": "value"}
    for _ in range(50):
        obj = {"nested": obj}
    result = scan_plist(obj)
    assert result.error is None


def test_scan_plist_large_string_value():
    """A very large string value must not cause a hang or crash."""
    big = "A" * 200_000
    result = scan_plist({"LargeKey": big})
    assert result.error is None


def test_scan_plist_array_of_strings():
    """Arrays of strings in plist values must be walked without error."""
    result = scan_plist({"SomeList": ["http://example.com", "https://safe.example.com"]})
    ids = {f.id for f in result.findings}
    assert "transport-cleartext-http" in ids


def test_counts_unknown_severity_does_not_crash():
    """ScanResult.counts() must not KeyError on an unrecognised severity."""
    r = ScanResult(
        source="test",
        findings=[
            Finding(
                id="test-id",
                title="Test",
                severity="unknown_level",  # Not in SEVERITY_ORDER.
                path="root",
                detail="detail",
                recommendation="fix",
            )
        ],
    )
    counts = r.counts()  # Must not raise.
    # Unknown severity is bucketed under "info".
    assert counts["info"] == 1


# ---------------------------------------------------------------------------
# CLI edge cases
# ---------------------------------------------------------------------------

def test_cli_no_command_returns_2():
    """Calling main() with no sub-command returns exit code 2."""
    rc = main([])
    assert rc == 2


def test_cli_empty_path_returns_2():
    """Passing an empty string as a plist path must exit 2, not traceback."""
    rc = main(["scan", ""])
    assert rc == 2


def test_cli_multiple_files_one_missing(tmp_path, capsys):
    """When one file is missing, had_error is set and exit code is 2.
    Valid files in the same batch are still scanned."""
    good = tmp_path / "good.plist"
    good.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.good"}))
    rc = main(["scan", str(good), "/no/such/file.plist"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "ERROR" in out  # table output should show the error


def test_cli_json_output_multiple_files(tmp_path, capsys):
    """JSON output with multiple files must produce a valid list in results."""
    p1 = tmp_path / "a.plist"
    p2 = tmp_path / "b.plist"
    p1.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.a"}))
    p2.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.b"}))
    rc = main(["scan", str(p1), str(p2), "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert len(payload["results"]) == 2
    assert rc == 0  # Only info-level findings, default fail-on is low.


def test_cli_malformed_plist_returns_2(tmp_path):
    """A file that contains garbage (not a valid plist) must return exit 2."""
    p = tmp_path / "bad.plist"
    p.write_bytes(b"this is not a plist at all !!!")
    rc = main(["scan", str(p)])
    assert rc == 2


# ---------------------------------------------------------------------------
# webhook.py edge cases
# ---------------------------------------------------------------------------

def _run_webhook_main(argv: list, stdin_bytes: bytes) -> int:
    """Run integrations/webhook.py main() with controlled argv and stdin bytes.

    We replace sys.stdin wholesale with a TextIOWrapper whose underlying buffer
    we control — avoiding the readonly-attribute issue with sys.stdin.buffer on
    Python 3.14.
    """
    import unittest.mock as mock
    import integrations.webhook as wh

    fake_stdin = io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding="utf-8")
    with mock.patch("sys.argv", ["webhook.py"] + argv), \
         mock.patch("sys.stdin", fake_stdin):
        return wh.main()


def test_webhook_empty_stdin_exits_1():
    """Empty stdin must return exit code 1 with a clear message."""
    rc = _run_webhook_main(["--url", "https://example.com/hook"], b"")
    assert rc == 1


def test_webhook_bad_url_scheme_exits_1():
    """A non-http/https URL scheme must be rejected with exit code 1."""
    rc = _run_webhook_main(["--url", "ftp://example.com/hook"], b'{"key": "value"}')
    assert rc == 1


def test_webhook_malformed_header_exits_1():
    """A --header value with no colon must return exit code 1."""
    rc = _run_webhook_main(
        ["--url", "https://example.com/hook", "--header", "   "],
        b'{"key": "value"}',
    )
    assert rc == 1
