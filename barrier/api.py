"""The Barrier API and dashboard host.

Endpoints follow the spec: three screening gates, QM's security-proxy contract,
the quarantine queue, source lineage with withdrawal, human feedback, and the
intelligence stats the dashboard reads.

Run:  python -m barrier.api      (or run-barrier.bat)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__
from .events import bus
from .guard import guard_status
from .ledger import Ledger
from .models import ESCALATE_AT, QUARANTINE_AT, Gate, ScreenRequest, Trust, Verdict
from .policy import POLICIES
from .screen import Screener
from .selftrain import SelfTrainer
from .store import LocalStore

STATIC = Path(__file__).resolve().parent / "static"
EVAL_FILE = Path(__file__).resolve().parent.parent / "data" / "eval.json"

app = FastAPI(title="Barrier", version=__version__,
              description="Owned security intelligence for AI agents")

screener = Screener()
ledger: Ledger = screener.ledger
trainer = SelfTrainer(ledger, screener=screener)


# ----------------------------------------------------------------- schemas

class ScreenBody(BaseModel):
    content: str = Field(..., description="What the agent wants to remember, reuse or do")
    source_id: str = "unknown"
    source_label: str = "unknown source"
    source_kind: str = "external"
    trust: Literal["internal", "trusted", "unknown", "external"] = "external"
    agent_id: str = "unknown-agent"
    writer: str = "agent"
    entity: str | None = None
    operation: str = "remember"
    existing: list[str] | None = None
    commit: bool = True


class ProcedureBody(BaseModel):
    steps: list[str] = Field(default_factory=list)
    content: str | None = None
    source_id: str = "memorable"
    source_label: str = "Memorable procedure"
    source_kind: str = "agent"
    trust: Literal["internal", "trusted", "unknown", "external"] = "unknown"
    agent_id: str = "unknown-agent"
    writer: str = "agent"
    commit: bool = True


class QMScreenBody(BaseModel):
    """QM's documented security-screen proxy payload."""

    text: str
    hook: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeedbackBody(BaseModel):
    decision_id: str
    verdict: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    analyst: str = "analyst"


class WithdrawBody(BaseModel):
    source_id: str | None = None
    reason: str = "source confirmed compromised"


def _request_from(body: ScreenBody, gate: Gate) -> ScreenRequest:
    return ScreenRequest(
        gate=gate,
        content=body.content,
        source_id=body.source_id,
        source_label=body.source_label,
        source_kind=body.source_kind,
        trust=Trust(body.trust),
        agent_id=body.agent_id,
        writer=body.writer,
        entity=body.entity,
        operation=body.operation,
        existing=body.existing or [],
    )


# ------------------------------------------------------------------ gates

class BenchBody(BaseModel):
    """The live test bench: type any content, pick a source, watch Barrier decide.

    This is deliberately the SAME path a real agent hits through the MCP server -
    no shortcut, no canned answer. `commit` defaults true so the write really
    lands (or is really stopped) and shows up in the feed, the queue and memory.
    """
    content: str
    source_id: str = "bench/manual"
    source_label: str = "Live test bench"
    source_kind: str = "email"
    trust: Literal["internal", "trusted", "unknown", "external"] = "external"
    agent_id: str = "test-bench"
    entity: str | None = None
    gate: Literal["memory", "procedure", "action"] = "memory"
    commit: bool = True


@app.post("/v1/bench")
def bench(body: BenchBody) -> dict[str, Any]:
    gate = Gate(body.gate)
    if gate is Gate.PROCEDURE:
        result = screener.screen_procedure(
            body.content, source_id=body.source_id, source_label=body.source_label,
            source_kind=body.source_kind, trust=Trust(body.trust), agent_id=body.agent_id,
            writer=body.agent_id)
    elif gate is Gate.ACTION:
        result = screener.screen_action(
            body.content, source_id=body.source_id, source_label=body.source_label,
            source_kind=body.source_kind, trust=Trust(body.trust), agent_id=body.agent_id,
            writer=body.agent_id)
    else:
        req = ScreenRequest(
            gate=Gate.MEMORY, content=body.content, source_id=body.source_id,
            source_label=body.source_label, source_kind=body.source_kind,
            trust=Trust(body.trust), agent_id=body.agent_id, writer=body.agent_id,
            entity=body.entity, operation="remember")
        req.existing = [m["content"] for m in screener.store.recall(
            body.entity or body.content, limit=5)]
        req.existing_refs = [(m.get("id", ""), m["content"])
                             for m in screener.store.recall(body.entity or body.content, limit=5)]
        result = screener.screen(req, commit=body.commit)
    return result.to_dict()


@app.post("/v1/screen/memory")
def screen_memory(body: ScreenBody) -> dict[str, Any]:
    req = _request_from(body, Gate.MEMORY)
    if body.existing is None:
        try:
            req.existing = [m["content"] for m in screener.store.recall(body.entity or body.content, limit=5)]
        except Exception:
            req.existing = []
    return screener.screen(req, commit=body.commit).to_dict()


@app.post("/v1/screen/procedure")
def screen_procedure(body: ProcedureBody) -> dict[str, Any]:
    content = body.content or "\n".join(f"{i+1}. {s}" for i, s in enumerate(body.steps))
    if not content.strip():
        raise HTTPException(400, "provide either steps[] or content")
    req = ScreenRequest(
        gate=Gate.PROCEDURE, content=content, source_id=body.source_id,
        source_label=body.source_label, source_kind=body.source_kind,
        trust=Trust(body.trust), agent_id=body.agent_id, writer=body.writer,
        operation="extract_procedure")
    return screener.screen(req, commit=body.commit).to_dict()


@app.post("/v1/screen/action")
def screen_action(body: ScreenBody) -> dict[str, Any]:
    body.operation = body.operation if body.operation != "remember" else "act"
    return screener.screen(_request_from(body, Gate.ACTION), commit=body.commit).to_dict()


@app.post("/v1/qm/screen")
def qm_screen(body: QMScreenBody,
              authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """QM security-screen proxy contract: takes text/hook/metadata, returns score/threshold/outcome.

    UNVERIFIED against a live QM deployment - the field names follow QM's
    documented proxy contract, but nothing here has been exercised end to end
    with QM. Do not claim "works with QM" until it has.
    """
    expected = os.environ.get("SECURITY_SCREEN_PROXY_TOKEN", "")
    if expected:
        presented = (authorization or "").removeprefix("Bearer ").strip()
        if presented != expected:
            raise HTTPException(401, "bad proxy token")

    meta = body.metadata or {}
    req = ScreenRequest(
        gate=Gate.QM,
        content=body.text,
        source_id=str(meta.get("source_id", body.hook or "qm")),
        source_label=str(meta.get("source", f"QM {body.hook or 'screen'}")),
        source_kind=str(meta.get("source_kind", "external")),
        trust=Trust(str(meta.get("trust", "external"))),
        agent_id=str(meta.get("agent_id", "qm-agent")),
        writer=str(meta.get("writer", "qm")),
        operation=body.hook or "screen",
    )
    result = screener.screen(req)
    outcome = {Verdict.ALLOW: "allow", Verdict.QUARANTINE: "review", Verdict.BLOCK: "block"}[result.verdict]
    return {
        "score": round(result.risk, 4),
        "threshold": QUARANTINE_AT,
        "primary_outcome": outcome,
        "category": result.category,
        "reason": result.reason,
        "decision_id": result.decision_id,
        "model_version": result.model_version,
    }


# -------------------------------------------------------------- quarantine

@app.get("/v1/quarantine")
def quarantine() -> dict[str, Any]:
    return {"items": ledger.quarantine()}


@app.post("/v1/quarantine/{decision_id}/approve")
def approve(decision_id: str, analyst: str = "analyst") -> dict[str, Any]:
    result = screener.approve(decision_id, analyst)
    if not result:
        raise HTTPException(404, "no such decision")
    return result


@app.post("/v1/quarantine/{decision_id}/reject")
def reject(decision_id: str, analyst: str = "analyst") -> dict[str, Any]:
    result = screener.reject(decision_id, analyst)
    if not result:
        raise HTTPException(404, "no such decision")
    return result


@app.post("/v1/feedback")
def feedback(body: FeedbackBody) -> dict[str, Any]:
    if body.verdict == "ALLOW":
        result = screener.approve(body.decision_id, body.analyst)
    else:
        result = screener.reject(body.decision_id, body.analyst)
    if not result:
        raise HTTPException(404, "no such decision")
    return {"recorded": True, "decision": result, "training_rows": len(ledger.training_rows())}


# ------------------------------------------------------------ source lineage

@app.get("/v1/sources")
def sources() -> dict[str, Any]:
    return {"sources": ledger.sources()}


@app.post("/v1/sources/withdraw")
def withdraw_by_body(body: WithdrawBody) -> dict[str, Any]:
    """Primary withdrawal route.

    Source ids carry slashes ("email/vendor-update-184"), which a path
    parameter would swallow along with any suffix, so the id travels in the
    body. The spec-shaped /v1/sources/{id}/withdraw alias below still works for
    ids without slashes.
    """
    if not body.source_id:
        raise HTTPException(400, "source_id is required")
    if not ledger.source(body.source_id):
        raise HTTPException(404, "no such source")
    return screener.withdraw_source(body.source_id, body.reason)


@app.post("/v1/sources/{source_id}/withdraw")
def withdraw(source_id: str, body: WithdrawBody | None = None) -> dict[str, Any]:
    if not ledger.source(source_id):
        raise HTTPException(404, "no such source")
    reason = body.reason if body else "source confirmed compromised"
    return screener.withdraw_source(source_id, reason)


@app.get("/v1/sources/{source_id:path}")
def source(source_id: str) -> dict[str, Any]:
    found = ledger.source(source_id)
    if not found:
        raise HTTPException(404, "no such source")
    return found


# ------------------------------------------------------------- observability

@app.get("/v1/activity")
def activity(limit: int = 50, verdict: str | None = None, gate: str | None = None) -> dict[str, Any]:
    return {"decisions": ledger.decisions(limit=limit, verdict=verdict, gate=gate)}


@app.get("/v1/memories")
def memories(include_withdrawn: bool = True) -> dict[str, Any]:
    store = screener.store
    if isinstance(store, LocalStore):
        return {"memories": store.all_memories(include_withdrawn=include_withdrawn)}
    return {"memories": [], "note": "remote GBrain backend - read memories from GBrain directly"}


@app.get("/v1/recall")
def recall(q: str, limit: int = 10) -> dict[str, Any]:
    """What an agent would get back. Withdrawn memories are gone from here."""
    return {"query": q, "memories": screener.store.recall(q, limit=limit)}


@app.get("/v1/intelligence/stats")
def intelligence_stats() -> dict[str, Any]:
    stats = ledger.stats()
    evaluation: dict[str, Any] | None = None
    if EVAL_FILE.exists():
        try:
            evaluation = json.loads(EVAL_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            evaluation = None
    return {
        "barrier_version": __version__,
        "stats": stats,
        "guard": guard_status(),
        "posture": screener.posture(),
        "threat_memory": screener.immune.size(),
        "tolerance_memory": screener.tolerance.size(),
        "guard_versions": ledger.guard_versions(),
        "selftrain": {"available": trainer.available(), "running": trainer.running(),
                      "status": trainer.status, "base_model": trainer.base_model},
        "store": getattr(screener.store, "name", "unknown"),
        "policies": [{"id": p.id, "text": p.text, "action": p.action.value} for p in POLICIES],
        "thresholds": {"quarantine_at": QUARANTINE_AT, "escalate_at": ESCALATE_AT},
        "training_rows_from_feedback": len(ledger.training_rows()),
        # None until training/evaluate.py has actually been run. The dashboard
        # shows "not yet measured" rather than inventing a number.
        "evaluation": evaluation,
    }


@app.get("/v1/policies")
def policies() -> dict[str, Any]:
    return {"policies": [{"id": p.id, "text": p.text, "categories": list(p.categories),
                          "action": p.action.value, "min_risk": p.min_risk} for p in POLICIES]}


# ----------------------------------------------------------------- posture

class PostureBody(BaseModel):
    mode: Literal["enforce", "shadow"]


@app.get("/v1/posture")
def get_posture() -> dict[str, Any]:
    return {"mode": screener.posture()}


@app.post("/v1/posture")
def set_posture(body: PostureBody) -> dict[str, Any]:
    return {"mode": screener.set_posture(body.mode)}


# ------------------------------------------------------------ threat memory

@app.get("/v1/threats")
def threats() -> dict[str, Any]:
    return {"antibodies": ledger.threats(), "count": screener.immune.size()}


@app.get("/v1/tolerances")
def tolerances() -> dict[str, Any]:
    return {"tolerances": ledger.tolerances(), "count": screener.tolerance.size()}


# --------------------------------------------------- self-improvement engine

@app.get("/v1/guard/versions")
def guard_versions() -> dict[str, Any]:
    return {"versions": ledger.guard_versions(), "trainer": trainer.status,
            "available": trainer.available(), "running": trainer.running(),
            "base_model": trainer.base_model}


class SelfTrainBody(BaseModel):
    base_model: str | None = None


@app.post("/v1/selftrain")
def selftrain(body: SelfTrainBody | None = None) -> dict[str, Any]:
    """Retrain the owned guard on the org's own mistakes. No engineer in the loop."""
    return trainer.start(body.base_model if body else None)


@app.get("/v1/selftrain/status")
def selftrain_status() -> dict[str, Any]:
    return {"running": trainer.running(), "status": trainer.status}


# ---------------------------------------------------------- live event stream

@app.get("/v1/events")
def events() -> StreamingResponse:
    """Server-Sent Events: every decision, ruling and training step, live."""
    return StreamingResponse(bus.stream(), media_type="text/event-stream",
                             headers={"cache-control": "no-cache", "x-accel-buffering": "no"})


# -------------------------------------------------------------- demo reset

class ResetBody(BaseModel):
    fresh_brain: bool = True


@app.post("/v1/demo/reset")
def demo_reset(body: ResetBody | None = None) -> dict[str, Any]:
    """Truncate all state so a rehearsal never breaks the live run. The file
    stays in place, so a dashboard that is already open clears live."""
    from .ledger import reset_db

    reset_db(ledger.db_path)
    screener.immune._count = -1  # force the antibody index to rebuild
    return {"reset": True, "stats": ledger.stats()}


# ------------------------------------------------ HTTP bridge into the gates

class RpcBody(BaseModel):
    """A JSON-RPC-shaped call for harnesses that speak HTTP more easily than
    stdio - `method` and `params` mirror MCP's tools/call, and `agent` stands
    in for the clientInfo an MCP handshake would have carried."""

    method: str = "tools/call"
    agent: str = "http-agent"
    params: dict[str, Any] = Field(default_factory=dict)


@app.post("/v1/mcp/rpc")
def mcp_rpc(body: RpcBody) -> dict[str, Any]:
    from .mcp_proxy import BarrierMCP

    server = BarrierMCP.__new__(BarrierMCP)
    server.screener = screener          # share the live screener and its DB
    server.client_name = body.agent
    response = server.handle({"jsonrpc": "2.0", "id": 1,
                              "method": body.method, "params": body.params})
    return response or {"jsonrpc": "2.0", "id": 1, "result": None}


# ------------------------------------------------------ Memorable extraction

@app.post("/v1/memorable/extract")
def memorable_extract(payload: dict[str, Any]) -> Any:
    """Screen an agent trace before it becomes a shared procedure.

    Poisoned traces get a 403 with the reason. Clean traces are forwarded to
    Memorable's documented POST /v1/extract when MEMORABLE_API_KEY is set;
    without a key the screening verdict is returned with forwarded=false.
    The forward path is UNVERIFIED against the live Memorable API.
    """
    steps: list[str] = []
    for call in payload.get("tool_calls", payload.get("trace", [])) or []:
        if isinstance(call, str):
            steps.append(call)
        elif isinstance(call, dict):
            name = call.get("tool") or call.get("name") or "step"
            args = call.get("arguments") or call.get("input") or ""
            steps.append(f"{name}: {json.dumps(args) if not isinstance(args, str) else args}")
    if not steps and payload.get("content"):
        steps = [str(payload["content"])]
    if not steps:
        raise HTTPException(400, "no tool_calls/trace/content in payload")

    result = screener.screen_procedure(
        steps,
        source_id=str(payload.get("source", "memorable/extract")),
        source_label=str(payload.get("source", "Memorable extract")),
        source_kind="agent",
        trust=Trust(str(payload.get("trust", "unknown"))),
        agent_id=str(payload.get("agent_id", "unknown-agent")),
        writer=str(payload.get("agent_id", "agent")),
    )
    if result.verdict is not Verdict.ALLOW:
        raise HTTPException(403, detail={
            "refused": True, **result.to_dict(),
            "message": f"Barrier {result.verdict.value}: {result.reason}",
        })

    api_key = os.environ.get("MEMORABLE_API_KEY", "")
    if not api_key:
        return {"screened": True, "forwarded": False,
                "note": "MEMORABLE_API_KEY not set - trace cleared but not forwarded",
                **result.to_dict()}
    import urllib.error
    import urllib.request
    request = urllib.request.Request(
        os.environ.get("MEMORABLE_URL", "https://api.memorable.dev") + "/v1/extract",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {api_key}"},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            upstream = json.loads(resp.read().decode())
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        return {"screened": True, "forwarded": False, "error": str(exc), **result.to_dict()}
    return {"screened": True, "forwarded": True, "memorable": upstream, **result.to_dict()}


# ---------------------------------------------------------------- dashboard

@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"ok": True, "version": __version__})


def main() -> None:
    import uvicorn

    port = int(os.environ.get("BARRIER_PORT", "7777"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
