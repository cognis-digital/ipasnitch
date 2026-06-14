"""IPASNITCH MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from ipasnitch.core import scan_file


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ipasnitch[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ipasnitch[mcp]'")
        return 1
    app = FastMCP("ipasnitch")

    @app.tool()
    def ipasnitch_scan(target: str) -> str:
        """Static scanner for iOS .ipa bundles that flags ATS exceptions,
        missing entitlements hardening, embedded URLs/secrets, and weak
        Info.plist transport settings. Returns JSON findings."""
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        result = scan_file(target.strip())
        return json.dumps(result.to_dict(), indent=2)

    app.run()
    return 0
