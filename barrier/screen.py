"""The single screening entrypoint every gate goes through.

One `screen()` function, two tiers, one honest answer. The tiers are layered so
the expensive one is optional: if no guard model is configured Barrier still
runs, still decides, and reports `tier: rules` and a model_version that says
so. Nothing here ever reports a model verdict that was not actually obtained.
"""

from __future__ import annotations

import os
import time
from typing import Any

from . import policy as policy_mod
from . import rules as rules_mod
from .events import bus
from .guard import Guard, get_guard
from .immune import ImmuneSystem, ToleranceSystem
from .ledger import Ledger
from .models import (
    CATEGORIES,
    ESCALATE_AT,
    QUARANTINE_AT,
    Evidence,
    Gate,
    ScreenRequest,
    ScreenResult,
    Trust,
    Verdict,
    new_id,
)
from .store import LocalStore, get_store

STRICTNESS = {Verdict.ALLOW: 0, Verdict.QUARANTINE: 1, Verdict.BLOCK: 2}

REASON_TEMPLATES = {
    "financial_fact_tampering": "{source} attempts to replace trusted payment information",
    "persistent_instruction": "{source} attempts to install a standing instruction",
    "sleeper_instruction": "{source} plants behaviour triggered by a future request",
    "recommendation_poisoning": "{source} attempts to rig what agents recommend",
    "instruction_injection": "{source} issues hidden instructions to the agent",
    "identity_role_hijack": "{source} attempts to redefine the agent's role",
    "credential_exfiltration": "{source} instructs agents to move secrets off-system",
    "secret_storage": "Live credential would be written into shared agent memory",
    "procedure_poisoning": "Reusable procedure carries a dangerous step",
    "malicious_command": "Procedure executes remotely downloaded code",
    "source_impersonation": "{source} claims authority it cannot prove",
}

SOURCE_PHRASE = {
    Trust.EXTERNAL: "External source",
    Trust.UNKNOWN: "Unverified source",
    Trust.TRUSTED: "Partner source",
    Trust.INTERNAL: "Internal source",
}


def _verdict_from(risk: float, category: str | None, floor: Verdict | None) -> Verdict:
    """Category decides BLOCK vs QUARANTINE; risk decides whether anything happens."""
    if risk < QUARANTINE_AT:
        verdict = Verdict.ALLOW
    else:
        default = CATEGORIES[category].default_action if category in CATEGORIES else Verdict.QUARANTINE
        if default is Verdict.ALLOW:
            verdict = Verdict.ALLOW
        elif default is Verdict.BLOCK and risk < ESCALATE_AT:
            # Strong category, middling confidence: hold it for a human rather
            # than refusing outright.
            verdict = Verdict.QUARANTINE
        else:
            verdict = default
    if floor is not None and risk >= QUARANTINE_AT and STRICTNESS[floor] > STRICTNESS[verdict]:
        verdict = floor
    return verdict


class Screener:
    def __init__(self, ledger: Ledger | None = None, store: Any | None = None,
                 guard: Guard | None = None) -> None:
        self.ledger = ledger or Ledger()
        self.store = store if store is not None else get_store()
        self.guard = guard or get_guard()
        self.immune = ImmuneSystem(self.ledger)
        self.tolerance = ToleranceSystem(self.ledger)
        self.model_mode = os.environ.get("BARRIER_MODEL_MODE", "auto").lower()

    # ---------------------------------------------------------------- posture

    def posture(self) -> str:
        """'enforce' (default) or 'shadow'. In shadow, Barrier decides but does
        not act: everything is written through and the verdict is recorded as
        what *would* have happened. The demo's before/after is one toggle."""
        return self.ledger.get_setting("posture",
                                       os.environ.get("BARRIER_POSTURE", "enforce")) or "enforce"

    def set_posture(self, mode: str) -> str:
        mode = mode.lower()
        if mode not in ("enforce", "shadow"):
            raise ValueError("posture must be 'enforce' or 'shadow'")
        self.ledger.set_setting("posture", mode)
        return mode

    # ------------------------------------------------------------------ core

    def _should_call_model(self, rules_risk: float) -> bool:
        if self.model_mode == "off" or not self.guard.available():
            return False
        if self.model_mode == "always":
            return True
        # auto: skip the model only when the rules are already unambiguous.
        return rules_risk < 0.90

    def decide(self, req: ScreenRequest) -> ScreenResult:
        """Run both tiers and merge. Does not write to the ledger or the store."""
        started = time.perf_counter()

        raw_evidence = rules_mod.detect(req.content)
        benign = rules_mod.benign_markers(req.content)
        outcome = policy_mod.apply(req, raw_evidence, benign)

        rules_risk = outcome.risk
        dominant = None
        weighted = [e for e in outcome.notes if e.tier == "rules" and e.weight > 0]
        if weighted:
            dominant = max(weighted, key=lambda e: e.weight).category

        # Tier 3 (immune) runs before the verdict is formed: an antibody hit
        # raises the risk floor even when no rule matched at all.
        immune_hit = self.immune.match(req.content, entity=req.entity, trust=req.trust)
        if immune_hit is not None:
            if immune_hit.kind == "template":
                detail = (f"Resembles confirmed attack {immune_hit.antibody.decision_id} "
                          f"(similarity {immune_hit.similarity:.0%}, learned from "
                          f"{immune_hit.antibody.source_id})")
            else:
                detail = (f"Entity '{immune_hit.antibody.entity}' was already attacked once "
                          f"({immune_hit.antibody.decision_id}); external write introduces a "
                          f"new identifier for it - heightened scrutiny")
            evidence_note = Evidence("immune", immune_hit.antibody.category,
                                     immune_hit.weight, detail)
            outcome.notes.append(evidence_note)
            rules_risk = rules_risk + immune_hit.weight - (rules_risk * immune_hit.weight)
            if dominant is None or immune_hit.weight > 0.6:
                dominant = immune_hit.antibody.category

        # Suppressor half: a write resembling one an analyst already released
        # gets its risk damped - Barrier stops repeating corrected mistakes.
        tol_hit = None
        if immune_hit is None and rules_risk >= QUARANTINE_AT:
            tol_hit = self.tolerance.match(req.content, dominant, req.trust)
            if tol_hit is not None:
                before = rules_risk
                rules_risk *= tol_hit.damping
                outcome.notes.append(Evidence(
                    "tolerance", dominant or "benign", 0.0,
                    f"Resembles a write an analyst released ({tol_hit.similarity:.0%} similar to "
                    f"{tol_hit.tolerance.decision_id}); risk damped {before:.0%} -> {rules_risk:.0%}"))

        rules_verdict = _verdict_from(rules_risk, dominant, outcome.floor)
        evidence: list[Evidence] = list(outcome.notes)

        tier0 = "immune" if immune_hit is not None and rules_risk >= QUARANTINE_AT else "rules"
        verdict, risk, category, tier = rules_verdict, rules_risk, dominant or "benign", tier0
        reason = self._reason(req, category, rules_risk, benign)
        if tol_hit is not None and verdict is Verdict.ALLOW:
            tier = "tolerance"
            reason = ("Learned tolerance: an analyst already released a write like this "
                      f"({tol_hit.tolerance.decision_id})")
        if immune_hit is not None and tier == "immune":
            if immune_hit.kind == "template":
                reason = (f"Matches an attack this organization already confirmed "
                          f"({immune_hit.similarity:.0%} similar to {immune_hit.antibody.decision_id})")
            else:
                reason = (f"{immune_hit.antibody.entity} was targeted before "
                          f"({immune_hit.antibody.decision_id}); this external write changes "
                          f"its identifiers again")
        model_version = self.guard.model_version

        if self._should_call_model(rules_risk):
            guard_verdict = self.guard.screen(req)
            if guard_verdict is not None:
                evidence.append(Evidence(
                    "model", guard_verdict.category, guard_verdict.risk,
                    f"{self.guard.name} guard: {guard_verdict.verdict.value} "
                    f"({guard_verdict.risk:.2f}) - {guard_verdict.reason}"))
                model_version = guard_verdict.model_version
                # The stricter of the two wins; a model that sees something the
                # rules missed is the entire reason tier two exists.
                if STRICTNESS[guard_verdict.verdict] > STRICTNESS[verdict]:
                    verdict, category, reason, tier = (
                        guard_verdict.verdict, guard_verdict.category, guard_verdict.reason, "model")
                risk = max(risk, guard_verdict.risk)
            else:
                evidence.append(Evidence("model", "unavailable", 0.0,
                                         "Guard model did not answer; decision is rules-only"))
                model_version = f"{model_version} (model tier unavailable)"

        if verdict is Verdict.ALLOW and category not in CATEGORIES:
            category = "benign"

        result = ScreenResult(
            verdict=verdict,
            risk=round(risk, 4),
            category=category,
            reason=reason,
            tier=tier,
            model_version=model_version,
            evidence=evidence,
            policy_ids=outcome.policy_ids,
            decision_id=new_id("dec"),
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        return result

    def _reason(self, req: ScreenRequest, category: str | None, risk: float, benign: list[str]) -> str:
        if not category or risk < QUARANTINE_AT:
            if benign:
                return f"Ordinary organizational knowledge ({benign[0].lower()})"
            return "No trust signal triggered"
        template = REASON_TEMPLATES.get(category)
        if template:
            return template.format(source=SOURCE_PHRASE.get(req.trust, "Source"))
        cat = CATEGORIES.get(category)
        return cat.description if cat else "Policy signal triggered"

    # ----------------------------------------------------------------- gates

    def screen(self, req: ScreenRequest, *, commit: bool = True) -> ScreenResult:
        """Screen, record, and - for an allowed memory write - store it.

        In shadow posture the decision is still made and recorded in full, but
        Barrier does not act on it: the write goes through, stamped with the
        verdict that WOULD have applied. That is the demo's before/after in a
        single toggle, and it is also how a cautious org rolls Barrier out.
        """
        result = self.decide(req)
        if not commit:
            return result

        shadow = self.posture() == "shadow"
        enforced_verdict = result.verdict
        if shadow and result.verdict is not Verdict.ALLOW:
            result.evidence.append(Evidence(
                "posture", result.category, 0.0,
                f"SHADOW MODE: would have been {result.verdict.value}; written through unscreened"))
            result.verdict = Verdict.ALLOW

        self.ledger.record(req, result)
        self.ledger.set_decision_posture(result.decision_id,
                                         "shadow" if shadow else "enforce",
                                         enforced_verdict.value)
        bus.publish("decision", {"decision": self.ledger.decision(result.decision_id)})
        if req.gate is Gate.MEMORY and result.verdict is Verdict.ALLOW:
            memory_id = self.store.remember(
                req.content,
                entity=req.entity,
                source_id=req.source_id,
                source_label=req.source_label,
                agent_id=req.agent_id,
                provenance=f"{req.source_kind}:{req.source_id}",
                decision_id=result.decision_id,
                risk_score=result.risk,
                model_version=result.model_version,
            )
            result.memory_id = memory_id
            self.ledger.attach_memory(result.decision_id, memory_id)
        return result

    def screen_memory(self, content: str, **kwargs: Any) -> ScreenResult:
        return self.screen(self._request(Gate.MEMORY, content, **kwargs))

    def screen_procedure(self, steps: list[str] | str, **kwargs: Any) -> ScreenResult:
        body = steps if isinstance(steps, str) else "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        kwargs.setdefault("operation", "extract_procedure")
        return self.screen(self._request(Gate.PROCEDURE, body, **kwargs))

    def screen_action(self, action: str, **kwargs: Any) -> ScreenResult:
        """The operation gate. Beyond the normal tiers, an action that
        references an identifier introduced by a quarantined or blocked write
        is refused outright - the poisoned account number is radioactive even
        when the sentence around it is perfectly polite."""
        kwargs.setdefault("operation", "act")
        req = self._request(Gate.ACTION, action, **kwargs)
        taint = self._tainted_identifier(action)
        if taint is not None:
            identifier, origin = taint
            result = self.decide(req)
            result.verdict = Verdict.BLOCK
            result.risk = max(result.risk, 0.95)
            result.category = "financial_fact_tampering"
            result.tier = "lineage"
            past = {"QUARANTINE": "quarantined", "BLOCK": "blocked"}.get(origin["verdict"], "stopped")
            result.reason = (f"References {identifier}, introduced by a write Barrier "
                             f"{past} ({origin['id']})")
            result.evidence.append(Evidence(
                "lineage", "financial_fact_tampering", 0.95,
                f"Identifier {identifier} first appeared in {origin['verdict']} decision "
                f"{origin['id']} from {origin['source_label']}"))
            self.ledger.record(req, result)
            self.ledger.set_decision_posture(result.decision_id, self.posture(), Verdict.BLOCK.value)
            return result
        return self.screen(req)

    _IDENTIFIER = None  # compiled lazily below

    def _tainted_identifier(self, content: str) -> tuple[str, dict[str, Any]] | None:
        """Does this action reference an account/identifier that entered the
        organization through a stopped write? Cross-referencing the decision
        ledger is what source lineage buys at the *action* layer."""
        import re
        if Screener._IDENTIFIER is None:
            Screener._IDENTIFIER = re.compile(r"\b\d[\d\-]{5,}\d\b")
        candidates = set(Screener._IDENTIFIER.findall(content))
        if not candidates:
            return None
        for dec in self.ledger.decisions(limit=500):
            if dec["verdict"] not in ("QUARANTINE", "BLOCK") and not (
                    dec.get("posture") == "shadow" and
                    dec.get("enforced_verdict") in ("QUARANTINE", "BLOCK")):
                continue
            for ident in candidates:
                if ident in dec["content"]:
                    verdict = dec["verdict"] if dec["verdict"] != "ALLOW" else dec["enforced_verdict"]
                    return ident, {"id": dec["id"], "verdict": verdict,
                                   "source_label": dec["source_label"]}
        return None

    def _request(self, gate: Gate, content: str, **kwargs: Any) -> ScreenRequest:
        trust = kwargs.pop("trust", Trust.EXTERNAL)
        if isinstance(trust, str):
            trust = Trust(trust)
        existing = kwargs.pop("existing", None)
        refs: list[tuple[str, str]] = kwargs.pop("existing_refs", [])
        if existing is None and gate is Gate.MEMORY:
            entity = kwargs.get("entity")
            probe = entity or content
            try:
                rows = self.store.recall(probe, limit=5)
                existing = [m["content"] for m in rows]
                refs = [(m.get("id", ""), m["content"]) for m in rows]
            except Exception:
                existing = []
        return ScreenRequest(gate=gate, content=content, trust=trust,
                             existing=existing or [], existing_refs=refs, **kwargs)

    # ------------------------------------------------------- human decisions

    def approve(self, decision_id: str, analyst: str = "analyst") -> dict[str, Any] | None:
        """An analyst overrules a quarantine: the memory is written after all."""
        decision = self.ledger.decision(decision_id)
        if not decision or decision["resolved"]:
            return decision
        self.ledger.resolve(decision_id, Verdict.ALLOW.value, analyst)
        # The released false positive becomes a tolerance: Barrier will not
        # keep quarantining this shape of write from equally-trusted sources.
        self.ledger.learn_tolerance(decision_id, decision["content"], decision["category"],
                                    decision["source_id"], decision["trust"], analyst,
                                    entity=decision["entity"])
        bus.publish("ruling", {"decision_id": decision_id, "verdict": "ALLOW",
                               "learned": "tolerance"})
        # Only a held write needs releasing; an allowed one is already stored.
        if decision["gate"] == Gate.MEMORY.value and decision["verdict"] == Verdict.QUARANTINE.value:
            memory_id = self.store.remember(
                decision["content"],
                entity=decision["entity"],
                source_id=decision["source_id"],
                source_label=decision["source_label"],
                agent_id=decision["agent_id"],
                provenance=f"{decision['source_kind']}:{decision['source_id']}",
                decision_id=decision_id,
                risk_score=decision["risk"],
                model_version=decision["model_version"],
            )
            self.ledger.attach_memory(decision_id, memory_id)
        return self.ledger.decision(decision_id)

    def reject(self, decision_id: str, analyst: str = "analyst") -> dict[str, Any] | None:
        """An analyst confirms the catch. This is the row that trains the next guard."""
        decision = self.ledger.decision(decision_id)
        if not decision or decision["resolved"]:
            return decision
        self.ledger.resolve(decision_id, Verdict.BLOCK.value, analyst)
        self.ledger.mark_compromised(decision["source_id"], True)
        # The confirmed attack becomes an antibody: the immune tier now catches
        # paraphrases of it, effective immediately, no retraining.
        self.ledger.learn_threat(decision_id, decision["content"], decision["category"],
                                 decision["source_id"], analyst, entity=decision["entity"])
        bus.publish("ruling", {"decision_id": decision_id, "verdict": "BLOCK",
                               "learned": "antibody"})
        return self.ledger.decision(decision_id)

    # --------------------------------------------------------- blast radius

    def withdraw_source(self, source_id: str, reason: str = "source confirmed compromised") -> dict[str, Any]:
        if not isinstance(self.store, LocalStore):
            memories = [m for m in self.ledger.source(source_id)["memories"] if not m["withdrawn"]]
            withdrawn = [m["id"] for m in memories if self.store.forget(m["id"], reason)]
        else:
            withdrawn = self.store.withdraw_source(source_id, reason)
        self.ledger.mark_compromised(source_id, True)
        bus.publish("withdraw", {"source_id": source_id, "count": len(withdrawn)})
        return {"source_id": source_id, "withdrawn": withdrawn, "count": len(withdrawn), "reason": reason}
