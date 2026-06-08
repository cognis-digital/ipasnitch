"""ipasnitch — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from ipasnitch.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from ipasnitch.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "ipasnitch"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
