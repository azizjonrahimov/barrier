"""Script-friendly MCP entry point.

Harness configs commonly register servers as plain script paths:

    claude mcp add --transport stdio barrier-brain -- python /path/to/barrier/mcp_server.py
    codex  mcp add barrier-brain -- python /path/to/barrier/mcp_server.py

Run as a script, relative imports are unavailable - this shim fixes sys.path
and delegates to barrier.mcp_proxy, which is the actual server.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from barrier.mcp_proxy import serve  # noqa: E402

if __name__ == "__main__":
    serve()
