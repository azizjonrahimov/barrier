"""Tier one: cheap, deterministic detectors.

These run on every write and cost nothing. They are deliberately a *first*
layer, not the product - published rules are rules an attacker can read and
paraphrase around, which is exactly why tier two is a model you own. What the
rules buy is speed on the obvious cases and evidence strings an analyst can
read.

Each detector contributes a weight, not a verdict. Weights combine
probabilistically in `score()`, and the trust of the source decides what the
score means (see policy.py) - "from now on, always cc me on vendor mail" from
an internal colleague is a preference; the same words from an inbound email
are an attempt to install a standing instruction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Evidence

Pattern = re.Pattern[str]


@dataclass(frozen=True)
class Rule:
    category: str
    weight: float
    pattern: Pattern
    detail: str
    # Rules flagged instruction_shaped are the ones whose meaning depends on who
    # is speaking: harmless from an internal human, an attack from a web page.
    instruction_shaped: bool = False


def _p(expr: str) -> Pattern:
    return re.compile(expr, re.IGNORECASE | re.DOTALL)


RULES: list[Rule] = [
    # -- standing / persistent instructions ---------------------------------
    Rule("persistent_instruction", 0.55,
         _p(r"\b(from now on|going forward|starting (today|tomorrow|now)|in (all|every) future|"
            r"always (remember|make sure|ensure)|never (again|mention|tell))\b"),
         "Phrasing that installs a standing instruction", instruction_shaped=True),
    Rule("persistent_instruction", 0.7,
         _p(r"\bremember\b[^.\n]{0,60}\b(as|is|are)\b[^.\n]{0,40}"
            r"\b(trusted|trustworthy|top[- ]priority|must[- ]meet|preferred|approved|official)\b"),
         "Attempts to install a trust fact about a named party", instruction_shaped=True),

    # -- sleeper triggers ---------------------------------------------------
    Rule("sleeper_instruction", 0.65,
         _p(r"\b(when(ever)?|if)\s+(anyone|someone|a user|the user|you(?:'re| are)?)\s+"
            r"(asks?|requests?|mentions?|says?|queries)\b"),
         "Behaviour conditioned on a future trigger phrase", instruction_shaped=True),
    Rule("sleeper_instruction", 0.5,
         _p(r"\b(only|just)\s+(when|if|after)\b[^.\n]{0,50}\b(then|do|say|recommend|reply)\b"),
         "Dormant conditional instruction", instruction_shaped=True),

    # -- recommendation poisoning -------------------------------------------
    Rule("recommendation_poisoning", 0.7,
         _p(r"\b(recommend|suggest|propose|prioriti[sz]e|rank|mention|promote)\b[^.\n]{0,50}"
            r"\b(first|foremost|above|over|ahead of|instead of|before)\b"),
         "Rigs the ordering of what the agent recommends"),
    Rule("recommendation_poisoning", 0.6,
         _p(r"\b(do not|don't|never)\s+(recommend|suggest|mention|offer)\b"),
         "Suppresses a competitor or option"),

    # -- financial fact tampering -------------------------------------------
    Rule("financial_fact_tampering", 0.75,
         _p(r"\b(bank(?:ing|s)?|wire(?:s|d)?|wiring|routing|iban|swift|account(?:\s+numbers?|s)?|"
            r"payment details?|remittance)\b[^.\n]{0,60}\b(chang(?:e|ed|ing)|updat(?:e|ed)|new|"
            r"switch(?:ed)?|now)\b"),
         "Changes payment or banking facts"),
    Rule("financial_fact_tampering", 0.7,
         _p(r"\b(chang(?:e|ed|ing)|updat(?:e|ed)|new|switch(?:ed)?|mov(?:e|ed|ing))\b[^.\n]{0,60}"
            r"\b(bank(?:ing|s)?|wire(?:s|d)?|routing|iban|swift|account(?:\s+numbers?|s)?|"
            r"payment details?)\b"),
         "Changes payment or banking facts"),
    Rule("financial_fact_tampering", 0.6,
         _p(r"\b(remember|use|send|pay|wire|route|forward)\b[^.\n]{0,50}"
            r"\b(account|iban|routing|bank)\b[^.\n]{0,70}"
            r"\b(invoices?|payments?|billing|remittance|going forward|future|from now)\b"),
         "Binds a payee to an account for future payments"),
    Rule("financial_fact_tampering", 0.45,
         _p(r"\b(?:acct|account|iban|routing)\b[^a-z0-9]{0,12}[0-9][0-9\- ]{5,}"),
         "Supplies a specific account number"),

    # -- identity / role hijack ---------------------------------------------
    Rule("identity_role_hijack", 0.85,
         _p(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}"
            r"\b(previous|prior|earlier|above|all|any)\b[^.\n]{0,20}"
            r"\b(instruction|prompt|rule|direction|message)s?\b"),
         "Attempts to override the agent's instructions"),
    Rule("identity_role_hijack", 0.7,
         _p(r"\b(you are now|your new (role|job|task|purpose)|act as|pretend to be|"
            r"from now on you)\b"),
         "Redefines who the agent is"),
    Rule("identity_role_hijack", 0.6,
         _p(r"\b(system prompt|developer message|admin(?:istrator)? mode|god mode|"
            r"jailbreak|sudo mode)\b"),
         "Claims privileged control of the agent"),

    # -- exfiltration --------------------------------------------------------
    Rule("credential_exfiltration", 0.85,
         _p(r"\b(send|upload|post|email|forward|transmit|exfiltrat\w*|leak|share)\b[^.\n]{0,60}"
            r"\b(credential|password|secret|token|api[ _-]?key|private key|\.env|ssh key|cookie)s?\b"),
         "Instruction to move secrets off the machine"),
    Rule("credential_exfiltration", 0.6,
         _p(r"\b(cat|type|read|print|dump|copy)\b[^.\n]{0,30}"
            r"(\.env|id_rsa|credentials|\.aws|secrets?\.(?:json|ya?ml)|keychain)\b"),
         "Reads a credential store"),

    # -- secrets being stored in shared memory ------------------------------
    Rule("secret_storage", 0.9,
         _p(r"\b(sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"xox[baprs]-[A-Za-z0-9\-]{10,})"),
         "Contains what looks like a live credential"),
    Rule("secret_storage", 0.8,
         _p(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
         "Contains a private key block"),
    Rule("secret_storage", 0.55,
         _p(r"\b(password|passwd|api[ _-]?key|secret|token)\b\s*[:=]\s*\S{8,}"),
         "Stores a credential as a key/value pair"),

    # -- dangerous commands --------------------------------------------------
    Rule("malicious_command", 0.9,
         _p(r"\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,120}\|\s*(sudo\s+)?(ba|z|d)?sh\b"),
         "Pipes a downloaded script straight into a shell"),
    Rule("malicious_command", 0.85,
         _p(r"\b(rm\s+-rf\s+/(?!\w)|mkfs|dd\s+if=/dev/(?:zero|random)\s+of=/dev/|"
            r":\(\)\s*\{\s*:\|:&\s*\}\s*;:)"),
         "Destructive command"),
    Rule("malicious_command", 0.8,
         _p(r"\b(powershell(?:\.exe)?\s+-(?:enc|e|encodedcommand)|iex\s*\(\s*new-object\s+net\.webclient)"),
         "Obfuscated remote execution"),
    Rule("malicious_command", 0.6,
         _p(r"\b(chmod\s+777|sudo\s+chown\s+-R|nc\s+-e\s|/dev/tcp/)"),
         "Privilege or reverse-shell behaviour"),

    # -- generic injection ---------------------------------------------------
    Rule("instruction_injection", 0.7,
         _p(r"\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|notify|mention to|show)\b"
            r"[^.\n]{0,20}\b(the )?(user|human|owner|operator)\b"),
         "Tells the agent to hide behaviour from its operator"),
    Rule("instruction_injection", 0.6,
         _p(r"\b(important|urgent|attention)\s*[:!]\s*(ai|assistant|agent|claude|gpt|model|llm)\b"),
         "Content addressed to the model rather than the reader"),
    Rule("instruction_injection", 0.55,
         _p(r"<\s*/?\s*(system|assistant|instructions?|tool_call)\s*>"),
         "Embeds control markup in prose"),

    # -- impersonation -------------------------------------------------------
    Rule("source_impersonation", 0.6,
         _p(r"\b(this (message|request) is (from|on behalf of)|i am|this is)\b[^.\n]{0,25}"
            r"\b(the )?(ceo|cfo|cto|coo|security team|it (department|team)|legal|compliance|"
            r"your (manager|administrator))\b"),
         "Claims authority the source cannot prove"),
    Rule("source_impersonation", 0.5,
         _p(r"\b(verified|official|authori[sz]ed)\b[^.\n]{0,25}\b(notice|update|request|communication)\b"),
         "Self-asserted verification"),
]

# Hard negatives: phrasing that superficially matches an attack rule but is
# routine when it comes from inside. These damp the instruction-shaped rules so
# a colleague setting a preference does not land in the quarantine queue.
BENIGN_MARKERS: list[tuple[Pattern, str]] = [
    (_p(r"\b(i|we|my|our)\s+(prefer|like|want|would like|usually|normally)\b"),
     "First-person preference"),
    (_p(r"\b(standup|stand-up|sprint|retro|all[- ]hands|1:1|meeting|demo)\b[^.\n]{0,40}"
        r"\b(moved|moving|rescheduled|now at|starts at|shifted)\b"),
     "Ordinary schedule change"),
    (_p(r"\b(refund|return|warranty|support)\s+(window|policy|period)\b"),
     "Documented policy fact"),
    (_p(r"\b(for reference|for the record|fyi|note that|as discussed)\b"),
     "Informational framing"),
    (_p(r"\b(example|sample|do not act on|quoted|illustrat\w+|phishing (attempt|email)|"
        r"security (note|advisory|bulletin))\b"),
     "Quotes an attack rather than issuing one"),
]


def detect(content: str) -> list[Evidence]:
    """Run every rule. Returns one Evidence per distinct (category, detail) hit."""
    found: dict[tuple[str, str], Evidence] = {}
    for rule in RULES:
        match = rule.pattern.search(content)
        if not match:
            continue
        snippet = " ".join(match.group(0).split())
        if len(snippet) > 90:
            snippet = snippet[:87] + "..."
        key = (rule.category, rule.detail)
        weight = rule.weight
        prior = found.get(key)
        if prior and prior.weight >= weight:
            continue
        found[key] = Evidence(
            tier="rules",
            category=rule.category,
            weight=weight,
            detail=f'{rule.detail}: "{snippet}"',
        )
    return list(found.values())


def benign_markers(content: str) -> list[str]:
    return [label for pattern, label in BENIGN_MARKERS if pattern.search(content)]


def instruction_shaped_categories() -> set[str]:
    return {r.category for r in RULES if r.instruction_shaped}


def combine(weights: list[float]) -> float:
    """Noisy-OR. Several weak signals add up; one strong signal is enough."""
    risk = 0.0
    for w in weights:
        risk = risk + w - (risk * w)
    return min(risk, 0.99)


def score(content: str) -> tuple[float, str | None, list[Evidence]]:
    """Returns (risk, dominant category, evidence)."""
    evidence = detect(content)
    if not evidence:
        return 0.0, None, []
    risk = combine([e.weight for e in evidence])
    dominant = max(evidence, key=lambda e: e.weight).category
    return risk, dominant, evidence
