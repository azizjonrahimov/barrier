"""The Barrier ledger: every decision, every source, every human ruling.

This is the "decision memory" and "trust memory" half of the Barrier Brain. It
is deliberately boring SQLite - the interesting part is that nothing is thrown
away, so a human ruling on a quarantined item becomes a training example and a
compromised source can be traced to every memory it ever created.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .models import Evidence, ScreenRequest, ScreenResult, Verdict, new_id, now

BUILTIN_DB = Path(__file__).resolve().parent.parent / "data" / "barrier.db"


def default_db() -> Path:
    """Resolved per call, not at import, so BARRIER_DB set later still takes effect."""
    return Path(os.environ.get("BARRIER_DB") or BUILTIN_DB)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    trust       TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    compromised INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decisions (
    id            TEXT PRIMARY KEY,
    ts            REAL NOT NULL,
    gate          TEXT NOT NULL,
    content       TEXT NOT NULL,
    source_id     TEXT NOT NULL,
    source_label  TEXT NOT NULL,
    source_kind   TEXT NOT NULL,
    trust         TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    writer        TEXT NOT NULL,
    entity        TEXT,
    operation     TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    risk          REAL NOT NULL,
    category      TEXT NOT NULL,
    reason        TEXT NOT NULL,
    tier          TEXT NOT NULL,
    model_version TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    policy_ids    TEXT NOT NULL,
    latency_ms    REAL NOT NULL,
    memory_id     TEXT,
    resolved      INTEGER NOT NULL DEFAULT 0,
    human_verdict TEXT,
    analyst       TEXT,
    resolved_ts   REAL
);

CREATE INDEX IF NOT EXISTS decisions_ts      ON decisions (ts DESC);
CREATE INDEX IF NOT EXISTS decisions_source  ON decisions (source_id);
CREATE INDEX IF NOT EXISTS decisions_verdict ON decisions (verdict, resolved);

CREATE TABLE IF NOT EXISTS memories (
    id            TEXT PRIMARY KEY,
    ts            REAL NOT NULL,
    content       TEXT NOT NULL,
    entity        TEXT,
    source_id     TEXT NOT NULL,
    source_label  TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    provenance    TEXT NOT NULL,
    decision_id   TEXT,
    risk_score    REAL NOT NULL DEFAULT 0,
    model_version TEXT NOT NULL DEFAULT '',
    visibility    TEXT NOT NULL DEFAULT 'brain',
    withdrawn     INTEGER NOT NULL DEFAULT 0,
    withdrawn_ts  REAL,
    withdraw_reason TEXT
);

CREATE INDEX IF NOT EXISTS memories_source ON memories (source_id);
CREATE INDEX IF NOT EXISTS memories_entity ON memories (entity);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The immune system: every attack a human confirms becomes an antibody.
-- Future writes are compared against these, so a paraphrase of a known
-- attack is caught even when no rule matches it.
CREATE TABLE IF NOT EXISTS threat_memory (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    decision_id TEXT NOT NULL,
    content     TEXT NOT NULL,
    category    TEXT NOT NULL,
    source_id   TEXT NOT NULL,
    entity      TEXT,
    analyst     TEXT NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0
);
"""

# Columns added after the first release; applied best-effort on connect.
MIGRATIONS = [
    "ALTER TABLE decisions ADD COLUMN posture TEXT NOT NULL DEFAULT 'enforce'",
    "ALTER TABLE decisions ADD COLUMN enforced_verdict TEXT",
    "ALTER TABLE threat_memory ADD COLUMN entity TEXT",
]


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path or default_db())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path | str | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        for migration in MIGRATIONS:
            try:
                conn.execute(migration)
            except sqlite3.OperationalError:
                pass  # column already exists


def reset_db(db_path: Path | str | None = None) -> None:
    """Empty every table, keeping the file.

    Deleting the file would fail on Windows whenever the API server has it
    open - which is exactly the situation the demo is replayed in. Truncating
    instead also means a running dashboard clears live as the demo restarts.
    """
    init_db(db_path)
    with connect(db_path) as conn:
        for table in ("decisions", "memories", "sources", "threat_memory"):
            conn.execute(f"DELETE FROM {table}")


class Ledger:
    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path or default_db())
        init_db(self.db_path)

    # ---------------------------------------------------------------- sources

    def touch_source(self, req: ScreenRequest) -> None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT id FROM sources WHERE id = ?", (req.source_id,)).fetchone()
            if row:
                conn.execute("UPDATE sources SET last_seen = ?, label = ?, trust = ? WHERE id = ?",
                             (now(), req.source_label, req.trust.value, req.source_id))
            else:
                conn.execute(
                    "INSERT INTO sources (id, label, kind, trust, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                    (req.source_id, req.source_label, req.source_kind, req.trust.value, now(), now()))

    def sources(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT s.*,
                       (SELECT COUNT(*) FROM decisions d WHERE d.source_id = s.id) AS decisions,
                       (SELECT COUNT(*) FROM memories m WHERE m.source_id = s.id AND m.withdrawn = 0) AS live_memories,
                       (SELECT COUNT(*) FROM memories m WHERE m.source_id = s.id AND m.withdrawn = 1) AS withdrawn_memories,
                       (SELECT MAX(d.risk) FROM decisions d WHERE d.source_id = s.id) AS max_risk
                FROM sources s ORDER BY last_seen DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def source(self, source_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
            if not row:
                return None
            src = dict(row)
            src["decisions"] = [dict(r) for r in conn.execute(
                "SELECT * FROM decisions WHERE source_id = ? ORDER BY ts DESC", (source_id,)).fetchall()]
            src["memories"] = [dict(r) for r in conn.execute(
                "SELECT * FROM memories WHERE source_id = ? ORDER BY ts DESC", (source_id,)).fetchall()]
        return src

    def mark_compromised(self, source_id: str, compromised: bool = True) -> None:
        with connect(self.db_path) as conn:
            conn.execute("UPDATE sources SET compromised = ? WHERE id = ?", (1 if compromised else 0, source_id))

    # --------------------------------------------------------------- settings

    def get_setting(self, key: str, default: str = "") -> str:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # ---------------------------------------------------------- threat memory

    def learn_threat(self, decision_id: str, content: str, category: str,
                     source_id: str, analyst: str, entity: str | None = None) -> str:
        """A confirmed attack becomes an antibody. See immune.ImmuneSystem."""
        threat_id = new_id("thr")
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO threat_memory (id, ts, decision_id, content, category, source_id, entity, analyst) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (threat_id, now(), decision_id, content, category, source_id, entity, analyst))
        return threat_id

    def threats(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM threat_memory ORDER BY ts DESC").fetchall()]

    def record_threat_hit(self, threat_id: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("UPDATE threat_memory SET hits = hits + 1 WHERE id = ?", (threat_id,))

    # -------------------------------------------------------------- decisions

    def record(self, req: ScreenRequest, result: ScreenResult) -> str:
        self.touch_source(req)
        decision_id = result.decision_id or new_id("dec")
        result.decision_id = decision_id
        with connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO decisions (id, ts, gate, content, source_id, source_label, source_kind, trust,
                                       agent_id, writer, entity, operation, verdict, risk, category, reason,
                                       tier, model_version, evidence, policy_ids, latency_ms, memory_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                decision_id, now(), req.gate.value, req.content, req.source_id, req.source_label,
                req.source_kind, req.trust.value, req.agent_id, req.writer, req.entity, req.operation,
                result.verdict.value, result.risk, result.category, result.reason, result.tier,
                result.model_version,
                json.dumps([e.__dict__ for e in result.evidence]),
                json.dumps(result.policy_ids), result.latency_ms, result.memory_id,
            ))
        return decision_id

    def attach_memory(self, decision_id: str, memory_id: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("UPDATE decisions SET memory_id = ? WHERE id = ?", (memory_id, decision_id))

    def set_decision_posture(self, decision_id: str, posture: str, enforced_verdict: str) -> None:
        """Record the posture a decision ran under and what enforce would have done."""
        with connect(self.db_path) as conn:
            conn.execute("UPDATE decisions SET posture = ?, enforced_verdict = ? WHERE id = ?",
                         (posture, enforced_verdict, decision_id))

    def decisions(self, limit: int = 50, verdict: str | None = None, gate: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM decisions"
        clauses, params = [], []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        if gate:
            clauses.append("gate = ?")
            params.append(gate)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with connect(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._decision_dict(r) for r in rows]

    def decision(self, decision_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        return self._decision_dict(row) if row else None

    def quarantine(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM decisions WHERE verdict = 'QUARANTINE' AND resolved = 0 ORDER BY risk DESC, ts DESC"
            ).fetchall()
        return [self._decision_dict(r) for r in rows]

    def resolve(self, decision_id: str, human_verdict: str, analyst: str = "analyst") -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE decisions SET resolved = 1, human_verdict = ?, analyst = ?, resolved_ts = ? WHERE id = ?",
                (human_verdict, analyst, now(), decision_id))
        return self.decision(decision_id)

    @staticmethod
    def _decision_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["evidence"] = json.loads(d.get("evidence") or "[]")
        d["policy_ids"] = json.loads(d.get("policy_ids") or "[]")
        return d

    # ------------------------------------------------------------- statistics

    def stats(self) -> dict[str, Any]:
        with connect(self.db_path) as conn:
            def scalar(sql: str, params: tuple = ()) -> int:
                return conn.execute(sql, params).fetchone()[0] or 0

            return {
                "protected_agents": scalar("SELECT COUNT(DISTINCT agent_id) FROM decisions"),
                "protected_memories": scalar("SELECT COUNT(*) FROM memories WHERE withdrawn = 0"),
                "withdrawn_memories": scalar("SELECT COUNT(*) FROM memories WHERE withdrawn = 1"),
                "screened": scalar("SELECT COUNT(*) FROM decisions"),
                "allowed": scalar("SELECT COUNT(*) FROM decisions WHERE verdict = 'ALLOW'"),
                "blocked": scalar("SELECT COUNT(*) FROM decisions WHERE verdict = 'BLOCK'"),
                "quarantined_open": scalar(
                    "SELECT COUNT(*) FROM decisions WHERE verdict = 'QUARANTINE' AND resolved = 0"),
                "quarantined_total": scalar("SELECT COUNT(*) FROM decisions WHERE verdict = 'QUARANTINE'"),
                "decisions_learned": scalar("SELECT COUNT(*) FROM decisions WHERE resolved = 1"),
                "sources_seen": scalar("SELECT COUNT(*) FROM sources"),
                "sources_compromised": scalar("SELECT COUNT(*) FROM sources WHERE compromised = 1"),
            }

    def training_rows(self) -> list[dict[str, Any]]:
        """Human-resolved decisions, in the shape the guard is trained on.

        This is the feedback loop the spec calls for: an analyst ruling becomes
        a labelled example for the next version of the owned model.
        """
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM decisions WHERE resolved = 1 ORDER BY resolved_ts ASC").fetchall()
        out = []
        for r in rows:
            human = (r["human_verdict"] or "").upper()
            if human not in {v.value for v in Verdict}:
                continue
            out.append({
                "content": r["content"],
                "source": r["source_label"],
                "source_kind": r["source_kind"],
                "trust": r["trust"],
                "writer": r["writer"],
                "entity": r["entity"],
                "operation": r["operation"],
                "label": human,
                "category": r["category"],
                "reason": r["reason"],
                "origin": "human_feedback",
                "decision_id": r["id"],
            })
        return out
