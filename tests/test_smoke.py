"""Smoke tests for IPASNITCH. No network. Runs against the bundled demo."""
import os
import plistlib

import pytest

from ipasnitch import (
    TOOL_NAME,
    TOOL_VERSION,
    parse_plist,
    scan_file,
    scan_plist,
)
from ipasnitch.cli import main

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "Info.plist",
)


def test_metadata():
    assert TOOL_NAME == "ipasnitch"
    assert TOOL_VERSION


def test_demo_file_exists():
    assert os.path.isfile(DEMO)


def test_scan_demo_finds_issues():
    result = scan_file(DEMO)
    assert result.error is None
    ids = {f.id for f in result.findings}
    # ATS globally disabled
    assert "ats-arbitrary-loads" in ids
    # Per-domain insecure HTTP
    assert "ats-domain-insecure-http" in ids
    # Weak TLS pin
    assert "ats-weak-tls" in ids
    # No forward secrecy
    assert "ats-no-forward-secrecy" in ids
    # Cleartext URL string
    assert "transport-cleartext-http" in ids
    # Embedded AWS key
    assert "secret-aws-access-key" in ids
    # Highest severity is critical (the AWS key)
    assert result.max_severity == "critical"


def test_findings_sorted_worst_first():
    result = scan_file(DEMO)
    from ipasnitch.core import SEVERITY_ORDER

    sevs = [SEVERITY_ORDER[f.severity] for f in result.findings]
    assert sevs == sorted(sevs, reverse=True)


def test_clean_plist_has_no_security_findings():
    clean = {
        "CFBundleIdentifier": "com.example.clean",
        "ApiBaseURL": "https://api.example.com/v1",
    }
    result = scan_plist(clean, source="clean")
    # Only the informational "ats-not-configured" should appear.
    non_info = [f for f in result.findings if f.severity != "info"]
    assert non_info == []
    assert result.max_severity == "info"


def test_parse_rejects_non_dict():
    data = plistlib.dumps([1, 2, 3])
    with pytest.raises(ValueError):
        parse_plist(data)


def test_parse_binary_plist():
    data = plistlib.dumps(
        {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
        fmt=plistlib.FMT_BINARY,
    )
    plist = parse_plist(data)
    result = scan_plist(plist)
    assert any(f.id == "ats-arbitrary-loads" for f in result.findings)


def test_cli_json_exit_code(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1  # findings exceed default --fail-on low
    import json

    payload = json.loads(out)
    assert payload["tool"] == "ipasnitch"
    assert payload["results"][0]["counts"]["critical"] >= 1


def test_cli_fail_on_threshold_gate(tmp_path):
    # A plist whose worst finding is medium should pass a high gate (rc 0).
    p = tmp_path / "Info.plist"
    p.write_bytes(
        plistlib.dumps({"ApiBaseURL": "http://only-cleartext.example.com"})
    )
    assert main(["scan", str(p), "--fail-on", "high"]) == 0
    assert main(["scan", str(p), "--fail-on", "medium"]) == 1


def test_cli_missing_file_returns_2():
    assert main(["scan", "/no/such/Info.plist"]) == 2
