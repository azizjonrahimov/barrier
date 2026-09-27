"""Tier three: the immune system.

Rules catch what their author imagined. Models catch what they were trained
on. This tier catches *what has already happened to this organization*: every
attack an analyst confirms becomes an antibody, and every future write is
compared against the antibody set before anything else runs.

The comparison is deliberately dependency-free - a cosine over hashed
character trigrams, which survives paraphrase, word reordering, light
obfuscation, and (unlike word-level matching) partial language mixing. It is
not an embedding model and does not pretend to be one; it is the reason a
*second* attempt at yesterday's attack fails today, with a reason that names
the exact confirmed attack it resembles.

No other screener has this property: the organization's own attack history is
the training set, and it updates the moment a human clicks "confirm
malicious" - no retraining, no deployment, no API call.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

# 512 buckets is plenty for short memory writes and keeps signatures tiny.
_BUCKETS = 512
_WORD = re.compile(r"[^\W_]+", re.UNICODE)

# Volatile tokens (account numbers, hosts, amounts) are normalized away so an
# attacker cannot dodge the antibody by rotating the account number - the one
# field they always have to change.
_NUMBER = re.compile(r"\d[\d\-. ]{2,}\d")
_URL = re.compile(r"https?://\S+|\b[\w.-]+\.(?:com|io|net|org|sh|dev)\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\b")


def canonicalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold()
    text = _EMAIL.sub(" <addr> ", text)
    text = _URL.sub(" <host> ", text)
    text = _NUMBER.sub(" <num> ", text)
    return " ".join(_WORD.findall(text))


def signature(text: str) -> Counter[int]:
    """Hashed character-trigram counts over the canonical form."""
    canon = canonicalize(text)
    grams: Counter[int] = Counter()
    padded = f"  {canon}  "
    for i in range(len(padded) - 2):
        gram = padded[i:i + 3]
        bucket = int.from_bytes(hashlib.blake2s(gram.encode(), digest_size=4).digest(), "big") % _BUCKETS
        grams[bucket] += 1
    return grams


def cosine(a: Counter[int], b: Counter[int]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(count * b.get(bucket, 0) for bucket, count in a.items())
    if not dot:
        return 0.0
    norm = math.sqrt(sum(c * c for c in a.values())) * math.sqrt(sum(c * c for c in b.values()))
    return dot / norm if norm else 0.0


@dataclass
class Antibody:
    threat_id: str
    decision_id: str
    category: str
    source_id: str
    entity: str | None
    content: str
    sig: Counter[int]


@dataclass
class ImmuneMatch:
    antibody: Antibody
    similarity: float
    kind: str = "template"   # "template" (content match) | "sensitized" (entity watch)

    @property
    def weight(self) -> float:
        if self.kind == "sensitized":
            return SENSITIZED_WEIGHT
        # 0.55 similarity -> ~0.5 risk contribution, 0.9 -> ~0.93.
        return min(0.95, 0.5 + (self.similarity - MATCH_AT) * 1.2)


MATCH_AT = 0.55
# An entity that has already been attacked is on a watchlist: an external write
# that reintroduces identifiers for it gets this much added scrutiny. Enough to
# reach the quarantine threshold on its own; a human still makes the call.
SENSITIZED_WEIGHT = 0.55


class ImmuneSystem:
    """In-memory antibody index, rebuilt lazily from the ledger's threat table.

    Two ways to match:

    template   - the write's trigram signature resembles a confirmed attack.
                 Catches the realistic case: the same poisoned email template
                 re-sent with a fresh account number (the one field an
                 attacker must rotate is exactly the one we normalize away).

    sensitized - the write is external, names an entity that has already been
                 attacked, and introduces a new identifier (number, host or
                 address) for it. Catches the full rewrite that shares no
                 vocabulary with the original - what incident-response teams
                 call a watchlist.
    """

    def __init__(self, ledger) -> None:
        self.ledger = ledger
        self._antibodies: list[Antibody] = []
        self._count = -1

    def _refresh(self) -> None:
        rows = self.ledger.threats()
        if len(rows) == self._count:
            return
        self._antibodies = [
            Antibody(r["id"], r["decision_id"], r["category"], r["source_id"],
                     r.get("entity"), r["content"], signature(r["content"]))
            for r in rows
        ]
        self._count = len(rows)

    def match(self, content: str, entity: str | None = None,
              trust: object = None) -> ImmuneMatch | None:
        self._refresh()
        if not self._antibodies:
            return None
        sig = signature(content)
        best: ImmuneMatch | None = None
        for antibody in self._antibodies:
            score = cosine(sig, antibody.sig)
            if score >= MATCH_AT and (best is None or score > best.similarity):
                best = ImmuneMatch(antibody, score, "template")

        if best is None:
            best = self._sensitized(content, entity, trust)

        if best:
            self.ledger.record_threat_hit(best.antibody.threat_id)
        return best

    def _sensitized(self, content: str, entity: str | None,
                    trust: object) -> ImmuneMatch | None:
        trust_value = getattr(trust, "value", trust)
        if trust_value not in ("external", "unknown"):
            return None
        # canonicalize()'s word regex strips the angle brackets, so the
        # placeholders survive as bare tokens.
        tokens = set(canonicalize(content).split())
        if not tokens & {"num", "host", "addr"}:
            return None
        content_lower = content.casefold()
        for antibody in self._antibodies:
            target = (antibody.entity or "").strip()
            if not target:
                continue
            named = (entity or "").casefold() == target.casefold() or \
                target.casefold() in content_lower
            if named:
                sim = cosine(signature(content), antibody.sig)
                return ImmuneMatch(antibody, sim, "sensitized")
        return None

    def size(self) -> int:
        self._refresh()
        return len(self._antibodies)
