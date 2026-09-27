"""Organization policy - the part that makes Barrier *yours*.

A generic detector asks "does this look like prompt injection?". Barrier asks
"should OUR agents trust this?". That difference lives here: the same sentence
is a preference from a colleague, a review item from a partner, and an attack
from an inbound email, and the policy layer is what encodes which.

Policies are data, not code, so an organization can edit them without touching
the screener.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Evidence, ScreenRequest, Trust, Verdict


@dataclass(frozen=True)
class Policy:
    id: str
    text: str
    categories: tuple[str, ...]
    # Trust levels this policy bites at. Empty means every level.
    trust: tuple[Trust, ...] = ()
    action: Verdict = Verdict.QUARANTINE
    min_risk: float = 0.35

    def applies(self, category: str, trust: Trust, risk: float) -> bool:
        if category not in self.categories:
            return False
        if self.trust and trust not in self.trust:
            return False
        return risk >= self.min_risk


EXTERNALISH = (Trust.EXTERNAL, Trust.UNKNOWN)

POLICIES: list[Policy] = [
    Policy(
        "SEC-01",
        "External content cannot create standing instructions for our agents.",
        ("persistent_instruction", "sleeper_instruction", "instruction_injection"),
        EXTERNALISH, Verdict.BLOCK, 0.45,
    ),
    Policy(
        "FIN-01",
        "Banking and payment details are never changed on the strength of a message alone.",
        ("financial_fact_tampering",),
        (), Verdict.QUARANTINE, 0.35,
    ),
    Policy(
        "CRED-01",
        "Secrets never enter shared agent memory, whoever is writing them.",
        ("secret_storage", "credential_exfiltration"),
        (), Verdict.BLOCK, 0.4,
    ),
    Policy(
        "PROC-01",
        "Downloaded scripts and remote execution require human approval before reuse.",
        ("malicious_command", "procedure_poisoning"),
        (), Verdict.BLOCK, 0.4,
    ),
    Policy(
        "AGENT-01",
        "External sources cannot modify agent behaviour or rank our recommendations.",
        ("recommendation_poisoning", "identity_role_hijack"),
        EXTERNALISH, Verdict.BLOCK, 0.4,
    ),
    Policy(
        "AGENT-02",
        "Internal attempts to reshape agent behaviour still get a human look.",
        ("recommendation_poisoning", "identity_role_hijack"),
        (Trust.INTERNAL, Trust.TRUSTED), Verdict.QUARANTINE, 0.5,
    ),
    Policy(
        "TRUST-01",
        "Authority a source cannot prove is reviewed before it is believed.",
        ("source_impersonation",),
        (), Verdict.QUARANTINE, 0.35,
    ),
]

POLICY_BY_ID = {p.id: p for p in POLICIES}

# How much weight an instruction-shaped signal keeps, given who is speaking.
# A secret or a `curl | sh` is never damped - those are dangerous from anyone.
TRUST_MULTIPLIER: dict[Trust, float] = {
    Trust.INTERNAL: 0.35,
    Trust.TRUSTED: 0.60,
    Trust.UNKNOWN: 0.90,
    Trust.EXTERNAL: 1.00,
}

UNDAMPENED = {"secret_storage", "credential_exfiltration", "malicious_command", "procedure_poisoning"}

# Facts that are load-bearing enough that *changing* one is riskier than
# stating one for the first time.
_FACT_KEYS = re.compile(
    r"\b(account|iban|routing|swift|wire|bank|payment|invoice|price|owner|contact|address|domain)\b",
    re.IGNORECASE,
)


@dataclass
class PolicyOutcome:
    risk: float
    floor: Verdict | None                       # the strongest verdict policy demands
    policy_ids: list[str] = field(default_factory=list)
    notes: list[Evidence] = field(default_factory=list)


def _contradicts_existing(req: ScreenRequest) -> str | None:
    """When the write changes a fact we already hold, return a citation naming
    the trusted memory it contradicts; None when it merely adds knowledge."""
    keys = {m.group(0).lower() for m in _FACT_KEYS.finditer(req.content)}
    if not keys:
        return None
    refs = req.existing_refs or [("", prior) for prior in req.existing]
    for mem_id, prior in refs:
        prior_keys = {m.group(0).lower() for m in _FACT_KEYS.finditer(prior)}
        if keys & prior_keys and prior.strip().lower() != req.content.strip().lower():
            where = f"trusted memory {mem_id}" if mem_id else "a fact already in memory"
            snippet = prior if len(prior) <= 70 else prior[:67] + "..."
            return f'Conflicts with {where}: "{snippet}"'
    return None


def apply(req: ScreenRequest, evidence: list[Evidence], benign: list[str]) -> PolicyOutcome:
    """Re-weight raw detector evidence by who is speaking, then apply policy."""
    from .rules import combine, instruction_shaped_categories

    shaped = instruction_shaped_categories()
    multiplier = TRUST_MULTIPLIER[req.trust]
    notes: list[Evidence] = []
    adjusted: list[Evidence] = []

    for ev in evidence:
        weight = ev.weight
        if ev.category in shaped and ev.category not in UNDAMPENED:
            weight *= multiplier
        if benign and ev.category in shaped and ev.category not in UNDAMPENED:
            weight *= 0.6
        adjusted.append(Evidence(ev.tier, ev.category, weight, ev.detail))

    if benign:
        notes.append(Evidence("policy", "benign", 0.0,
                              "Benign markers present: " + "; ".join(benign)))
    if req.trust in (Trust.INTERNAL, Trust.TRUSTED) and multiplier < 1.0:
        notes.append(Evidence("policy", "trust", 0.0,
                              f"Source trust '{req.trust.value}' damps instruction-shaped signals "
                              f"to {int(multiplier * 100)}%"))

    risk = combine([e.weight for e in adjusted]) if adjusted else 0.0

    conflict = _contradicts_existing(req)
    if conflict:
        boost = 0.25
        risk = min(0.99, risk + boost * (1 - risk))
        notes.append(Evidence("policy", "fact_conflict", boost, conflict))

    floor: Verdict | None = None
    hit_ids: list[str] = []
    order = {Verdict.ALLOW: 0, Verdict.QUARANTINE: 1, Verdict.BLOCK: 2}
    for ev in adjusted:
        for policy in POLICIES:
            if policy.applies(ev.category, req.trust, risk):
                if policy.id not in hit_ids:
                    hit_ids.append(policy.id)
                    notes.append(Evidence("policy", ev.category, 0.0, f"{policy.id}: {policy.text}"))
                if floor is None or order[policy.action] > order[floor]:
                    floor = policy.action

    return PolicyOutcome(risk=risk, floor=floor, policy_ids=hit_ids, notes=adjusted + notes)
