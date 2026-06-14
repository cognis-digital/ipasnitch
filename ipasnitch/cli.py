"""Command-line interface for IPASNITCH.

Examples:
  # Scan an Info.plist and print a table
  ipasnitch scan demos/01-basic/Info.plist

  # JSON output for CI piping
  ipasnitch scan Info.plist --format json | jq '.findings'

  # Fail the build only on medium-or-worse findings
  ipasnitch scan Info.plist --fail-on medium

Exit codes:
  0  no findings at/above the --fail-on threshold
  1  findings at/above threshold (CI gate)
  2  usage / read / parse error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, ScanResult, scan_file


def _render_table(result: ScanResult) -> str:
    lines = []
    lines.append(f"IPASNITCH scan: {result.source}")
    if result.error:
        lines.append(f"  ERROR: {result.error}")
        return "\n".join(lines)
    counts = result.counts()
    summary = "  ".join(f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info"))
    lines.append(f"  findings: {len(result.findings)}   [{summary}]")
    if not result.findings:
        lines.append("  (clean)")
        return "\n".join(lines)
    lines.append("")
    lines.append(f"  {'SEVERITY':<9} {'ID':<28} {'PATH'}")
    lines.append(f"  {'-'*8:<9} {'-'*27:<28} {'-'*20}")
    for f in result.findings:
        lines.append(f"  {f.severity.upper():<9} {f.id:<28} {f.path}")
        lines.append(f"      {f.title}")
        lines.append(f"      {f.detail}")
        lines.append(f"      fix: {f.recommendation}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static scanner for iOS Info.plist: ATS exceptions, weak transport, embedded secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ipasnitch scan Info.plist\n"
            "  ipasnitch scan Info.plist --format json | jq .\n"
            "  ipasnitch scan Info.plist --fail-on high\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan one or more Info.plist files")
    scan.add_argument("plists", nargs="+", help="path(s) to Info.plist file(s)")
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER.keys()),
        default="low",
        help="exit non-zero if any finding is at/above this severity (default: low)",
    )
    return p


def _run(argv: Optional[list] = None) -> int:
    """Parse args and execute the scan. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    # Validate: reject empty path list (argparse nargs="+" prevents this, but
    # an explicit guard catches any hypothetical bypass).
    if not args.plists:
        print("error: at least one plist path is required", file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.fail_on]
    results = [scan_file(path) for path in args.plists]

    gate_tripped = False
    had_error = False
    for r in results:
        if r.error:
            had_error = True
        for f in r.findings:
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold:
                gate_tripped = True

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "fail_on": args.fail_on,
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        print("\n\n".join(_render_table(r) for r in results))

    if had_error:
        return 2
    return 1 if gate_tripped else 0


def main(argv: Optional[list] = None) -> int:
    """Entry point — wraps _run() so unexpected errors print a clean message."""
    try:
        return _run(argv)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover
        print(f"ipasnitch: unexpected error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
