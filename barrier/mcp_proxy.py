"""Barrier as an MCP server: agents connect here instead of to the brain.

This is the memory gate in its real form. A harness - Claude Code, Codex, a QM
agent - registers Barrier as its memory server. Reads pass straight through.
`remember` and `forget` are screened first, and a refused write comes back as a
tool error carrying the reason, so the agent sees why rather than silently
losing the memory.

The client's own name arrives in the MCP `initialize` handshake, which is how a
decision gets tagged with the harness that made it - "Claude Code wrote this,
Codex read it" is the whole multi-agent story.

Wire it up in .mcp.json:

    {"mcpServers": {"barrier": {
        "command": "python", "args": ["-m", "barrier.mcp_proxy"],
        "cwd": "D:\\\\ClaudeProject\\\\barrier"}}}

Protocol: JSON-RPC 2.0 over newline-delimited stdio. No dependencies.
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .ledger import Ledger
from .models import Gate, ScreenRequest, Trust, Verdict
from .screen import Screener
from .store import LocalStore, get_store

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "barrier", "version": "0.1.0"}

WRITE_VERBS = {"remember", "forget"}

TRUST_VALUES = [t.value for t in Trust]

TOOLS: list[dict[str, Any]] = [
    {
        "name": "remember",
        "description": ("Write a memory into the organization's shared brain. Screened by Barrier: "
                        "poisoned or policy-violating writes are refused or held for review."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "The fact to remember"},
                "entity": {"type": "string", "description": "Who or what this is about"},
                "source": {"type": "string", "description": "Where this came from, e.g. email/vendor-184"},
                "source_kind": {"type": "string",
                                "description": "email | slack | web | document | api | agent | human"},
                "trust": {"type": "string", "enum": TRUST_VALUES,
                          "description": "Standing of the source inside this organization"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "recall",
        "description": "Retrieve memories matching a query. Withdrawn and quarantined memories never appear.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "default": 10}},
            "required": ["query"],
        },
    },
    {
        "name": "forget",
        "description": "Retract a memory by id. Logged and attributed.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "entity",
        "description": "Everything the brain believes about one entity.",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}},
                        "required": ["name"]},
    },
    {
        "name": "synthesize",
        "description": "A short synthesis of what the brain knows about a subject.",
        "inputSchema": {"type": "object",
                        "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "default": 10}},
                        "required": ["query"]},
    },
    {
        "name": "context_pack",
        "description": "A budgeted bundle of relevant memories for a task.",
        "inputSchema": {"type": "object",
                        "properties": {"query": {"type": "string"}, "budget": {"type": "integer", "default": 5}},
                        "required": ["query"]},
    },
    {
        "name": "delta",
        "description": "What changed in the brain since a timestamp.",
        "inputSchema": {"type": "object", "properties": {"since": {"type": "number"}},
                        "required": ["since"]},
    },
    {
        "name": "screen_procedure",
        "description": ("Screen a reusable procedure (a tool-call trace) before it is stored or "
                        "shared with other agents."),
        "inputSchema": {
            "type": "object",
            "properties": {"steps": {"type": "array", "items": {"type": "string"}},
                           "source": {"type": "string"}},
            "required": ["steps"],
        },
    },
]


class BarrierMCP:
    def __init__(self) -> None:
        self.screener = Screener(ledger=Ledger(), store=get_store())
        self.client_name = "unknown-agent"

    # ------------------------------------------------------------ dispatch

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            info = params.get("clientInfo") or {}
            self.client_name = info.get("name") or "unknown-agent"
            return self._ok(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
                "instructions": ("Memory writes through this server are screened by Barrier. "
                                 "A refused write returns an error explaining why; do not retry "
                                 "it verbatim or attempt to rephrase around the refusal."),
            })

        if method in ("notifications/initialized", "notifications/cancelled"):
            return None

        if method == "ping":
            return self._ok(msg_id, {})

        if method == "tools/list":
            return self._ok(msg_id, {"tools": TOOLS})

        if method == "tools/call":
            return self._call(msg_id, params.get("name", ""), params.get("arguments") or {})

        if msg_id is None:
            return None
        return self._err(msg_id, -32601, f"method not found: {method}")

    def _call(self, msg_id: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            if name == "remember":
                return self._remember(msg_id, args)
            if name == "screen_procedure":
                return self._procedure(msg_id, args)
            if name == "forget":
                store = self.screener.store
                ok = store.forget(args.get("id", ""), args.get("reason", f"forget via {self.client_name}"))
                return self._text(msg_id, f"{'Retracted' if ok else 'No live memory with id'} "
                                          f"{args.get('id', '')}")
            if name == "recall":
                hits = self.screener.store.recall(args.get("query", ""), int(args.get("limit", 10)))
                if not hits:
                    return self._text(msg_id, "No memories matched.")
                body = "\n".join(f"- [{h['id']}] {h['content']}  (source: {h['source_label']})"
                                 for h in hits)
                return self._text(msg_id, body)
            if name == "entity":
                return self._json(msg_id, self.screener.store.entity(args.get("name", "")))
            if name == "synthesize":
                return self._text(msg_id, self.screener.store.synthesize(
                    args.get("query", ""), int(args.get("limit", 10))))
            if name == "context_pack":
                return self._json(msg_id, self.screener.store.context_pack(
                    args.get("query", ""), int(args.get("budget", 5))))
            if name == "delta":
                return self._json(msg_id, self.screener.store.delta(float(args.get("since", 0))))
            return self._err(msg_id, -32602, f"unknown tool: {name}")
        except Exception as exc:  # a crashed gate must not look like an allow
            return self._tool_error(msg_id, f"Barrier internal error, write not stored: {exc}")

    # --------------------------------------------------------------- gates

    def _remember(self, msg_id: Any, args: dict[str, Any]) -> dict[str, Any]:
        content = (args.get("content") or "").strip()
        if not content:
            return self._tool_error(msg_id, "content is required")
        source = args.get("source") or "agent/unspecified"
        trust_raw = str(args.get("trust") or "").lower()
        trust = Trust(trust_raw) if trust_raw in TRUST_VALUES else Trust.EXTERNAL
        req = ScreenRequest(
            gate=Gate.MEMORY,
            content=content,
            source_id=source,
            source_label=args.get("source_label") or source,
            source_kind=args.get("source_kind") or (source.split("/")[0] if "/" in source else "agent"),
            trust=trust,
            agent_id=self.client_name,
            writer=self.client_name,
            entity=args.get("entity"),
            operation="remember",
            existing=[m["content"] for m in self.screener.store.recall(
                args.get("entity") or content, limit=5)],
        )
        result = self.screener.screen(req)

        if result.verdict is Verdict.ALLOW:
            return self._text(msg_id, f"Remembered [{result.memory_id}]. "
                                      f"Screened by {result.model_version}.")
        pols = f" (policy {', '.join(result.policy_ids)})" if result.policy_ids else ""
        return self._tool_error(
            msg_id,
            f"Barrier {result.verdict.value}: {result.reason}{pols}. "
            f"Risk {result.risk:.0%}, category {result.category}. "
            f"Decision {result.decision_id}. "
            + ("Held for human review in the Barrier quarantine queue."
               if result.verdict is Verdict.QUARANTINE
               else "This write was refused and is not in memory."))

    def _procedure(self, msg_id: Any, args: dict[str, Any]) -> dict[str, Any]:
        steps = args.get("steps") or []
        result = self.screener.screen_procedure(
            list(steps), source_id=args.get("source") or "memorable/procedure",
            source_label=args.get("source") or "Memorable procedure",
            source_kind="agent", trust=Trust.UNKNOWN,
            agent_id=self.client_name, writer=self.client_name)
        if result.verdict is Verdict.ALLOW:
            return self._text(msg_id, f"Procedure cleared for reuse. Risk {result.risk:.0%}.")
        return self._tool_error(msg_id, f"Barrier {result.verdict.value}: {result.reason}. "
                                        f"Risk {result.risk:.0%}, category {result.category}.")

    # ------------------------------------------------------------ plumbing

    @staticmethod
    def _ok(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def _text(self, msg_id: Any, text: str) -> dict[str, Any]:
        return self._ok(msg_id, {"content": [{"type": "text", "text": text}]})

    def _json(self, msg_id: Any, payload: Any) -> dict[str, Any]:
        return self._text(msg_id, json.dumps(payload, indent=2, default=str))

    def _tool_error(self, msg_id: Any, text: str) -> dict[str, Any]:
        return self._ok(msg_id, {"content": [{"type": "text", "text": text}], "isError": True})


def serve(stdin=None, stdout=None) -> None:
    server = BarrierMCP()
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        try:
            response = server.handle(message)
        except Exception:
            print(traceback.format_exc(), file=sys.stderr, flush=True)
            response = server._err(message.get("id"), -32603, "internal error")
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
