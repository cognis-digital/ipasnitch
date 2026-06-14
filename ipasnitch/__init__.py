"""ipasnitch — part of the Cognis Neural Suite."""
# Identity constants live here; core.py does not define them.
TOOL_NAME = "ipasnitch"
TOOL_VERSION = "0.7.8"
__version__ = TOOL_VERSION

# Re-export the public scanning API so callers can do `from ipasnitch import scan_file`.
from ipasnitch.core import (  # noqa: E402,F401
    SEVERITY_ORDER,
    Finding,
    ScanResult,
    parse_plist,
    scan_file,
    scan_plist,
)
