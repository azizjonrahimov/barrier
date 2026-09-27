"""The protected memory store.

Barrier speaks GBrain's memory protocol - remember, recall, forget, entity,
synthesize, context_pack, delta - so that swapping this local store for a live
GBrain is a backend change, not a rewrite. Reads pass straight through. Writes
are the interesting half: `remember` is only ever reached by content that has
already cleared a gate, and every stored memory carries the Barrier fields
(source, decision, risk, model version) that make source withdrawal possible.

`LocalStore` is the default and is what the demo runs against. `GBrainBackend`
is the adapter for a live GBrain; it is written against the documented verb
names but has NOT been verified against a running GBrain instance - see
README.md before claiming it works.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from .ledger import connect
from .models import new_id, now

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "for", "is", "are", "was", "were", "be", "in", "on",
    "at", "by", "with", "from", "that", "this", "it", "as", "we", "our", "you", "your", "should",
    "new", "all", "any", "has", "have", "will", "can", "do", "does", "not", "but", "if", "then",
}


def _terms(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\-']+", text.lower()) if t not in STOPWORDS]


class MemoryBackend(Protocol):
    """The seven GBrain verbs, plus the withdrawal primitive Barrier adds."""

    def remember(self, content: str, **fields: Any) -> str: ...
    def recall(self, query: str, limit: int = 10) -> list[dict[str, Any]]: ...
    def forget(self, memory_id: str, reason: str = "") -> bool: ...
    def entity(self, name: str) -> dict[str, Any]: ...
    def synthesize(self, query: str, limit: int = 10) -> str: ...
    def context_pack(self, query: str, budget: int = 5) -> dict[str, Any]: ...
    def delta(self, since: float) -> dict[str, Any]: ...


class LocalStore:
    """A GBrain-shaped store backed by the same SQLite file as the ledger."""

    name = "local"

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = db_path

    # --------------------------------------------------------------- writes

    def remember(
        self,
        content: str,
        *,
        entity: str | None = None,
        source_id: str = "unknown",
        source_label: str = "unknown source",
        agent_id: str = "unknown-agent",
        provenance: str = "",
        decision_id: str | None = None,
        risk_score: float = 0.0,
        model_version: str = "",
        visibility: str = "brain",
    ) -> str:
        memory_id = new_id("mem")
        with connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO memories (id, ts, content, entity, source_id, source_label, agent_id,
                                      provenance, decision_id, risk_score, model_version, visibility)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (memory_id, now(), content, entity, source_id, source_label, agent_id,
                  provenance or source_label, decision_id, risk_score, model_version, visibility))
        return memory_id

    def forget(self, memory_id: str, reason: str = "") -> bool:
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE memories SET withdrawn = 1, withdrawn_ts = ?, withdraw_reason = ? "
                "WHERE id = ? AND withdrawn = 0",
                (now(), reason, memory_id))
            return cur.rowcount > 0

    # ---------------------------------------------------------------- reads

    def _live(self, conn) -> list[dict[str, Any]]:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM memories WHERE withdrawn = 0 ORDER BY ts DESC").fetchall()]

    def recall(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        q = set(_terms(query))
        with connect(self.db_path) as conn:
            rows = self._live(conn)
        scored = []
        for row in rows:
            hay = set(_terms(row["content"] + " " + (row["entity"] or "")))
            overlap = len(q & hay)
            if overlap:
                scored.append((overlap / max(len(q), 1), row))
        scored.sort(key=lambda p: (-p[0], -p[1]["ts"]))
        out = []
        for score, row in scored[:limit]:
            row = dict(row)
            row["score"] = round(score, 3)
            out.append(row)
        return out

    def entity(self, name: str) -> dict[str, Any]:
        key = name.lower()
        with connect(self.db_path) as conn:
            rows = self._live(conn)
        facts = [r for r in rows
                 if (r["entity"] or "").lower() == key or key in r["content"].lower()]
        return {
            "entity": name,
            "facts": facts,
            "sources": sorted({r["source_label"] for r in facts}),
            "count": len(facts),
        }

    def synthesize(self, query: str, limit: int = 10) -> str:
        hits = self.recall(query, limit=limit)
        if not hits:
            return f"Nothing in memory about {query!r}."
        lines = [f"What the brain believes about {query!r}:"]
        for h in hits:
            lines.append(f"  - {h['content']}  [source: {h['source_label']}]")
        return "\n".join(lines)

    def context_pack(self, query: str, budget: int = 5) -> dict[str, Any]:
        hits = self.recall(query, limit=budget)
        return {
            "query": query,
            "budget": budget,
            "memories": hits,
            "sources": sorted({h["source_label"] for h in hits}),
        }

    def delta(self, since: float) -> dict[str, Any]:
        with connect(self.db_path) as conn:
            added = [dict(r) for r in conn.execute(
                "SELECT * FROM memories WHERE ts > ? ORDER BY ts", (since,)).fetchall()]
            removed = [dict(r) for r in conn.execute(
                "SELECT * FROM memories WHERE withdrawn = 1 AND withdrawn_ts > ? ORDER BY withdrawn_ts",
                (since,)).fetchall()]
        return {"since": since, "added": added, "withdrawn": removed}

    # ------------------------------------------------------- source lineage

    def memories_from_source(self, source_id: str, include_withdrawn: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM memories WHERE source_id = ?"
        if not include_withdrawn:
            sql += " AND withdrawn = 0"
        sql += " ORDER BY ts DESC"
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute(sql, (source_id,)).fetchall()]

    def withdraw_source(self, source_id: str, reason: str = "source marked compromised") -> list[str]:
        """Retract every memory a single source ever created. The blast-radius button."""
        withdrawn = []
        for mem in self.memories_from_source(source_id):
            if self.forget(mem["id"], reason=reason):
                withdrawn.append(mem["id"])
        return withdrawn

    def all_memories(self, include_withdrawn: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM memories"
        if not include_withdrawn:
            sql += " WHERE withdrawn = 0"
        sql += " ORDER BY ts DESC"
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute(sql).fetchall()]


class GBrainBackend:
    """Adapter for a live GBrain over its HTTP surface.

    UNVERIFIED: written from the documented verb list, not yet run against a
    real GBrain. Configure with GBRAIN_URL (and GBRAIN_TOKEN if the deployment
    requires one). Until it has been exercised against a running instance, do
    not claim on stage that Barrier protects a real GBrain.
    """

    name = "gbrain"

    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or os.environ.get("GBRAIN_URL", "")).rstrip("/")
        self.token = token or os.environ.get("GBRAIN_TOKEN", "")
        if not self.base_url:
            raise RuntimeError("GBRAIN_URL is not set; use LocalStore or configure a GBrain endpoint.")

    def _call(self, verb: str, payload: dict[str, Any]) -> Any:
        req = urllib.request.Request(
            f"{self.base_url}/{verb}",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json",
                     **({"authorization": f"Bearer {self.token}"} if self.token else {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GBrain {verb} failed: {exc}") from exc

    def remember(self, content: str, **fields: Any) -> str:
        res = self._call("remember", {"content": content, **fields})
        return res.get("id", "")

    def recall(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        return self._call("recall", {"query": query, "limit": limit}).get("memories", [])

    def forget(self, memory_id: str, reason: str = "") -> bool:
        return bool(self._call("forget", {"id": memory_id, "reason": reason}).get("ok"))

    def entity(self, name: str) -> dict[str, Any]:
        return self._call("entity", {"name": name})

    def synthesize(self, query: str, limit: int = 10) -> str:
        return self._call("synthesize", {"query": query, "limit": limit}).get("text", "")

    def context_pack(self, query: str, budget: int = 5) -> dict[str, Any]:
        return self._call("context_pack", {"query": query, "budget": budget})

    def delta(self, since: float) -> dict[str, Any]:
        return self._call("delta", {"since": since})


def get_store(db_path: Path | str | None = None) -> Any:
    """LocalStore unless GBRAIN_URL is configured."""
    if os.environ.get("GBRAIN_URL"):
        try:
            return GBrainBackend()
        except RuntimeError:
            pass
    return LocalStore(db_path)
