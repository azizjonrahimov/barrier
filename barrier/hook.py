"""Fallback gate: a Claude Code PreToolUse hook.

If the MCP route is unavailable - a harness that will not add a server, or a
brain already wired directly - this screens memory writes at the harness level
instead. It protects only the harness it is installed in, which is why the MCP
server is the primary path, but the demo works either way.

Install in .claude/settings.json:

    {"hooks": {"PreToolUse": [{
        "matcher": "mcp__(brain|gbrain|barrier)__(remember|write|save).*",
        "hooks": [{"type": "command",
                   "command": "python D:/ClaudeProject/barrier/barrier/hook.py"}]}]}}

Contract: the tool call arrives as JSON on stdin. Exit 0 allows it; exit 2
blocks it and the text on stderr is what the agent sees.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from barrier.models import Gate, ScreenRequest, Trust, Verdict  # noqa: E402
from barrier.screen import Screener  # noqa: E402

CONTENT_KEYS = ("content", "text", "memory", "fact", "value", "body")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # unreadable payload: do not wedge the harness

    tool_input = payload.get("tool_input") or payload.get("input") or {}
    content = next((str(tool_input[k]) for k in CONTENT_KEYS if tool_input.get(k)), "")
    if not content.strip():
        return 0

    screener = Screener()
    request = ScreenRequest(
        gate=Gate.MEMORY,
        content=content,
        source_id=str(tool_input.get("source") or "agent/hook"),
        source_label=str(tool_input.get("source") or "agent write via hook"),
        source_kind=str(tool_input.get("source_kind") or "agent"),
        trust=Trust(str(tool_input.get("trust") or "external")),
        agent_id=str(payload.get("session_id") or "claude-code"),
        writer=str(payload.get("tool_name") or "unknown-tool"),
        entity=tool_input.get("entity"),
        operation="remember",
    )
    result = screener.screen(request)

    if result.verdict is Verdict.ALLOW:
        return 0

    policies = f" (policy {', '.join(result.policy_ids)})" if result.policy_ids else ""
    print(f"Barrier {result.verdict.value}: {result.reason}{policies}. "
          f"Risk {result.risk:.0%}, category {result.category}, decision {result.decision_id}. "
          f"This write was not stored. Do not rephrase and retry - if you believe it is "
          f"legitimate, ask a human to release it from the Barrier quarantine queue.",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
