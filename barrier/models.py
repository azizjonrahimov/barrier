"""Core types shared by every gate, tier and adapter."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now() -> float:
    return time.time()


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class Gate(str, Enum):
    MEMORY = "memory"
    PROCEDURE = "procedure"
    ACTION = "action"
    QM = "qm"


class Trust(str, Enum):
    """How much standing the writing source has inside this organization."""

    INTERNAL = "internal"   # a person or system inside the org
    TRUSTED = "trusted"     # a verified external partner
    UNKNOWN = "unknown"     # never seen before
    EXTERNAL = "external"   # arbitrary external content (email, web, API)


# --------------------------------------------------------------------------
# Risk categories.
#
# `default_action` is what the category earns *if* the risk clears the
# threshold. Category decides BLOCK vs QUARANTINE; risk decides whether
# anything happens at all. Financial tampering quarantines rather than blocks
# because a bank-detail change can be genuine - it needs a human, not a wall.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Category:
    key: str
    label: str
    default_action: Verdict
    description: str


CATEGORIES: dict[str, Category] = {
    c.key: c
    for c in [
        Category("instruction_injection", "Instruction injection", Verdict.BLOCK,
                 "External content issuing instructions to the agent."),
        Category("persistent_instruction", "Persistent instruction injection", Verdict.BLOCK,
                 "External content trying to create a standing instruction."),
        Category("sleeper_instruction", "Sleeper instruction", Verdict.BLOCK,
                 "An instruction that lies dormant until a trigger phrase appears."),
        Category("recommendation_poisoning", "Recommendation poisoning", Verdict.BLOCK,
                 "Content that rigs what the agent recommends."),
        Category("financial_fact_tampering", "Financial fact tampering", Verdict.QUARANTINE,
                 "A change to payment, banking or billing facts."),
        Category("identity_role_hijack", "Identity or role hijack", Verdict.BLOCK,
                 "Content that redefines who the agent is or who it answers to."),
        Category("credential_exfiltration", "Credential exfiltration", Verdict.BLOCK,
                 "Instructions to read secrets and send them somewhere."),
        Category("secret_storage", "Secret storage", Verdict.BLOCK,
                 "A live credential being written into shared memory."),
        Category("procedure_poisoning", "Procedure poisoning", Verdict.BLOCK,
                 "A reusable procedure carrying an injected or dangerous step."),
        Category("malicious_command", "Malicious command", Verdict.BLOCK,
                 "Shell behaviour that executes remote code or destroys data."),
        Category("source_impersonation", "Source impersonation", Verdict.QUARANTINE,
                 "Content claiming an authority its source does not have."),
        Category("benign", "Benign", Verdict.ALLOW,
                 "Ordinary organizational knowledge."),
        Category("benign_correction", "Benign correction", Verdict.ALLOW,
                 "An internal correction to something already known."),
        Category("legitimate_policy_change", "Legitimate policy change", Verdict.ALLOW,
                 "A policy change from a source entitled to make it."),
    ]
}

ATTACK_CATEGORIES = [k for k, c in CATEGORIES.items() if c.default_action is not Verdict.ALLOW]
BENIGN_CATEGORIES = [k for k, c in CATEGORIES.items() if c.default_action is Verdict.ALLOW]

# Risk thresholds. Below QUARANTINE_AT nothing happens, whatever the category.
QUARANTINE_AT = 0.50
ESCALATE_AT = 0.80


@dataclass
class Evidence:
    """One reason a tier reached its conclusion. This is what the analyst reads."""

    tier: str            # "rules" | "policy" | "model"
    category: str
    weight: float        # 0..1 contribution to risk
    detail: str          # human-readable, quotes the trigger where possible


@dataclass
class ScreenRequest:
    """One thing an agent wants to learn, reuse or do."""

    gate: Gate
    content: str
    source_id: str = "unknown"
    source_label: str = "unknown source"
    source_kind: str = "external"        # email | slack | web | document | api | agent | human
    trust: Trust = Trust.EXTERNAL
    agent_id: str = "unknown-agent"      # which harness is writing (Claude Code, Codex, ...)
    writer: str = "agent"
    entity: str | None = None            # the org/person the content is about
    operation: str = "remember"          # the verb being attempted
    existing: list[str] = field(default_factory=list)  # what we already believe
    # (memory_id, content) pairs behind `existing`, so a conflict can cite the
    # exact trusted memory it contradicts - "conflicts with mem_x", not "a fact".
    existing_refs: list[tuple[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> dict[str, Any]:
        return {
            "gate": self.gate.value,
            "content": self.content,
            "source_id": self.source_id,
            "source_label": self.source_label,
            "source_kind": self.source_kind,
            "trust": self.trust.value,
            "agent_id": self.agent_id,
            "writer": self.writer,
            "entity": self.entity,
            "operation": self.operation,
        }


@dataclass
class ScreenResult:
    """What Barrier decided, and everything needed to defend the decision."""

    verdict: Verdict
    risk: float
    category: str
    reason: str
    tier: str                                  # tier that set the final verdict
    model_version: str
    evidence: list[Evidence] = field(default_factory=list)
    policy_ids: list[str] = field(default_factory=list)
    decision_id: str = ""
    memory_id: str | None = None
    latency_ms: float = 0.0

    @property
    def category_label(self) -> str:
        cat = CATEGORIES.get(self.category)
        return cat.label if cat else self.category

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "verdict": self.verdict.value,
            "risk": round(self.risk, 4),
            "category": self.category,
            "category_label": self.category_label,
            "reason": self.reason,
            "tier": self.tier,
            "model_version": self.model_version,
            "policy_ids": self.policy_ids,
            "memory_id": self.memory_id,
            "latency_ms": round(self.latency_ms, 2),
            "evidence": [
                {"tier": e.tier, "category": e.category, "weight": round(e.weight, 3), "detail": e.detail}
                for e in self.evidence
            ],
        }


@dataclass
class GuardVerdict:
    """What the model tier returns. Deliberately the same shape the guard is trained to emit."""

    verdict: Verdict
    risk: float
    category: str
    reason: str
    model_version: str
    raw: str = ""
