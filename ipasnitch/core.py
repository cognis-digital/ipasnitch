"""Core engine for IPASNITCH.

Parses an iOS Info.plist (XML plist) into native Python structures and runs a
set of static security checks against it:

  * App Transport Security (ATS) exceptions and weak transport settings.
  * Insecure URL schemes / cleartext endpoints in any string value.
  * Embedded secrets (API keys, tokens, private keys) anywhere in the plist.

The parser is a small, dependency-free reader for the subset of Apple's plist
format that real Info.plist files use (dict/array/string/bool/int/real/data).
"""
from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# Severity ordering for sorting / gating (higher number == worse).
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """A single security finding."""

    id: str
    title: str
    severity: str  # one of SEVERITY_ORDER keys
    path: str  # dotted key path inside the plist where it was found
    detail: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Result of scanning a single plist."""

    source: str
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def counts(self) -> dict:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "error": self.error,
            "max_severity": self.max_severity,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_plist(data: bytes) -> dict:
    """Parse plist bytes (XML or binary) into a Python dict.

    Uses the stdlib plistlib, which handles both Apple XML and binary (bplist)
    formats. Raises ValueError on malformed input or a non-dict root.
    """
    try:
        obj = plistlib.loads(data)
    except Exception as exc:  # plistlib raises a variety of errors
        raise ValueError(f"could not parse plist: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("plist root is not a dictionary (not a valid Info.plist)")
    return obj


def _walk(obj: Any, prefix: str = ""):
    """Yield (dotted_path, value) for every leaf and container in the tree."""
    yield prefix or "<root>", obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _walk(v, child)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            child = f"{prefix}[{i}]"
            yield from _walk(v, child)


# --------------------------------------------------------------------------- #
# Secret detection
# --------------------------------------------------------------------------- #
# (id, label, compiled regex, severity)
_SECRET_PATTERNS = [
    ("aws-access-key", "AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("google-api-key", "Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("slack-token", "Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high"),
    ("stripe-key", "Stripe Secret Key", re.compile(r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b"), "critical"),
    ("github-token", "GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "critical"),
    ("private-key", "Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium"),
    ("bearer", "Hardcoded Bearer Token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}"), "medium"),
]

# Key names that look like they hold credentials, paired with a value that
# looks non-trivial (long, high-entropy-ish).
_SUSPICIOUS_KEY = re.compile(
    r"(?i)(api[_-]?key|secret|passwd|password|token|client[_-]?secret|access[_-]?key|private[_-]?key|auth)"
)
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9+/=_\-]{20,}$")


def _detect_secrets(path: str, value: str) -> list[Finding]:
    out: list[Finding] = []
    for sid, label, rx, sev in _SECRET_PATTERNS:
        if rx.search(value):
            out.append(
                Finding(
                    id=f"secret-{sid}",
                    title=f"Embedded secret: {label}",
                    severity=sev,
                    path=path,
                    detail=f"A value matching {label} was found embedded in the plist.",
                    recommendation="Remove credentials from Info.plist; fetch secrets at runtime from a secure store.",
                )
            )
    return out


def _detect_suspicious_key(path: str, key: str, value: str) -> Optional[Finding]:
    if _SUSPICIOUS_KEY.search(key) and isinstance(value, str) and _HIGH_ENTROPY.match(value.strip()):
        return Finding(
            id="secret-suspicious-key",
            title="Credential-like key holds a high-entropy value",
            severity="high",
            path=path,
            detail=f"Key '{key}' holds a long opaque value that resembles a credential.",
            recommendation="Do not ship credentials in Info.plist; load them securely at runtime.",
        )
    return None


# --------------------------------------------------------------------------- #
# Transport / URL detection
# --------------------------------------------------------------------------- #
_HTTP_URL = re.compile(r"(?i)\bhttp://[^\s\"'<>]+")
_WS_URL = re.compile(r"(?i)\bws://[^\s\"'<>]+")


def _detect_cleartext_url(path: str, value: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _HTTP_URL.finditer(value):
        out.append(
            Finding(
                id="transport-cleartext-http",
                title="Cleartext HTTP URL in plist",
                severity="medium",
                path=path,
                detail=f"Cleartext endpoint found: {m.group(0)}",
                recommendation="Use https:// endpoints; cleartext traffic exposes data to interception.",
            )
        )
    for m in _WS_URL.finditer(value):
        out.append(
            Finding(
                id="transport-cleartext-ws",
                title="Cleartext WebSocket URL in plist",
                severity="medium",
                path=path,
                detail=f"Cleartext WebSocket endpoint found: {m.group(0)}",
                recommendation="Use wss:// for WebSocket traffic.",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# ATS analysis
# --------------------------------------------------------------------------- #
def _analyze_ats(plist: dict) -> list[Finding]:
    out: list[Finding] = []
    ats = plist.get("NSAppTransportSecurity")
    base = "NSAppTransportSecurity"
    if not isinstance(ats, dict):
        # No ATS dict at all -> defaults apply (secure). Informational only.
        out.append(
            Finding(
                id="ats-not-configured",
                title="No NSAppTransportSecurity dictionary",
                severity="info",
                path="<root>",
                detail="Default ATS applies (TLS required). No explicit exceptions present.",
                recommendation="No action required unless you intentionally need exceptions.",
            )
        )
        return out

    if ats.get("NSAllowsArbitraryLoads") is True:
        out.append(
            Finding(
                id="ats-arbitrary-loads",
                title="NSAllowsArbitraryLoads enabled (ATS globally disabled)",
                severity="high",
                path=f"{base}.NSAllowsArbitraryLoads",
                detail="App Transport Security is disabled globally; all cleartext traffic is allowed.",
                recommendation="Set NSAllowsArbitraryLoads to false and scope exceptions per-domain only if required.",
            )
        )
    for legacy in ("NSAllowsArbitraryLoadsForMedia", "NSAllowsArbitraryLoadsInWebContent"):
        if ats.get(legacy) is True:
            out.append(
                Finding(
                    id=f"ats-{legacy.lower()}",
                    title=f"{legacy} enabled",
                    severity="medium",
                    path=f"{base}.{legacy}",
                    detail=f"{legacy} permits cleartext traffic for a content class.",
                    recommendation="Disable broad exceptions; prefer per-domain exception dictionaries.",
                )
            )
    if ats.get("NSAllowsLocalNetworking") is True:
        out.append(
            Finding(
                id="ats-local-networking",
                title="NSAllowsLocalNetworking enabled",
                severity="low",
                path=f"{base}.NSAllowsLocalNetworking",
                detail="Cleartext traffic to local/private hosts is allowed.",
                recommendation="Acceptable for local dev/IoT, but confirm it is intentional.",
            )
        )

    domains = ats.get("NSExceptionDomains")
    if isinstance(domains, dict):
        for domain, cfg in domains.items():
            dpath = f"{base}.NSExceptionDomains.{domain}"
            if not isinstance(cfg, dict):
                continue
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                out.append(
                    Finding(
                        id="ats-domain-insecure-http",
                        title=f"Insecure HTTP allowed for domain '{domain}'",
                        severity="high",
                        path=f"{dpath}.NSExceptionAllowsInsecureHTTPLoads",
                        detail=f"Cleartext HTTP is explicitly permitted for {domain}.",
                        recommendation="Serve the domain over HTTPS and remove the exception.",
                    )
                )
            min_tls = cfg.get("NSExceptionMinimumTLSVersion") or cfg.get("NSThirdPartyExceptionMinimumTLSVersion")
            if isinstance(min_tls, str) and min_tls in ("TLSv1.0", "TLSv1.1"):
                out.append(
                    Finding(
                        id="ats-weak-tls",
                        title=f"Weak minimum TLS version for domain '{domain}'",
                        severity="medium",
                        path=dpath,
                        detail=f"Minimum TLS version is set to {min_tls}, which is deprecated.",
                        recommendation="Require TLSv1.2 or TLSv1.3.",
                    )
                )
            if cfg.get("NSExceptionRequiresForwardSecrecy") is False:
                out.append(
                    Finding(
                        id="ats-no-forward-secrecy",
                        title=f"Forward secrecy disabled for domain '{domain}'",
                        severity="medium",
                        path=f"{dpath}.NSExceptionRequiresForwardSecrecy",
                        detail=f"Forward secrecy requirement is disabled for {domain}.",
                        recommendation="Keep forward secrecy enabled (remove the key or set it to true).",
                    )
                )
            if cfg.get("NSIncludesSubdomains") is True and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                out.append(
                    Finding(
                        id="ats-insecure-subdomains",
                        title=f"Insecure HTTP exception applies to all subdomains of '{domain}'",
                        severity="high",
                        path=dpath,
                        detail="NSIncludesSubdomains widens the cleartext exception to every subdomain.",
                        recommendation="Scope exceptions as narrowly as possible; avoid wildcarding subdomains.",
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def scan_plist(plist: dict, source: str = "<memory>") -> ScanResult:
    """Run all checks against an already-parsed plist dict."""
    result = ScanResult(source=source)
    result.findings.extend(_analyze_ats(plist))

    # Walk the whole tree for secrets + cleartext URLs in any string value.
    for path, value in _walk(plist):
        if isinstance(value, str):
            result.findings.extend(_detect_secrets(path, value))
            result.findings.extend(_detect_cleartext_url(path, value))
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, str):
                    f = _detect_suspicious_key(f"{path}.{k}" if path != "<root>" else k, k, v)
                    if f:
                        result.findings.append(f)

    # De-duplicate identical findings (same id+path+detail).
    seen = set()
    deduped = []
    for f in result.findings:
        key = (f.id, f.path, f.detail)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.id))
    result.findings = deduped
    return result


def scan_file(path: str) -> ScanResult:
    """Read and scan a plist file from disk."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return ScanResult(source=path, error=f"cannot read file: {exc}")
    try:
        plist = parse_plist(data)
    except ValueError as exc:
        return ScanResult(source=path, error=str(exc))
    return scan_plist(plist, source=path)
