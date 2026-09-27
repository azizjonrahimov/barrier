"""Measure the screeners. Writes data/eval.json, which the dashboard reads.

    python training/evaluate.py

Every screener that is actually configured gets measured; ones that are not are
reported as unavailable rather than estimated. Two sets are scored separately
on purpose:

  test.jsonl        held-out rows from the same distribution as training
  attack_pack.jsonl paraphrased attacks that avoid the rule vocabulary

The gap between those two columns is the honest case for owning a model: hand
written rules do well on the phrasings their author imagined and fall off on
the ones they did not.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, OSError, ValueError):
    pass


def _dash() -> str:
    try:
        "—".encode(sys.stdout.encoding or "ascii")
        return "—"
    except (UnicodeEncodeError, LookupError, TypeError):
        return "-"


DASH = _dash()

from barrier.guard import AnthropicGuard, NullGuard, RiverGuard  # noqa: E402
from barrier.ledger import Ledger  # noqa: E402
from barrier.models import Gate, ScreenRequest, Trust, Verdict  # noqa: E402
from barrier.screen import Screener  # noqa: E402
from barrier.store import LocalStore  # noqa: E402

DATA = ROOT / "data"
EVAL_DB = DATA / "eval.db"


def load(name: str) -> list[dict[str, Any]]:
    path = DATA / f"{name}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def to_request(row: dict[str, Any]) -> ScreenRequest:
    return ScreenRequest(
        gate=Gate.MEMORY,
        content=row["content"],
        source_id=row.get("source", "unknown"),
        source_label=row.get("source", "unknown"),
        source_kind=row.get("source_kind", "external"),
        trust=Trust(row.get("trust", "external")),
        agent_id="eval",
        writer=row.get("writer", "ingest-agent"),
        entity=row.get("entity"),
        operation=row.get("operation", "remember"),
        existing=[],
    )


def measure(screener: Screener, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Blocked-or-held counts as catching an attack; either one stops the write."""
    latencies: list[float] = []
    attacks = caught = benign = false_positives = exact = 0

    for row in rows:
        started = time.perf_counter()
        result = screener.decide(to_request(row))
        latencies.append((time.perf_counter() - started) * 1000)

        is_attack = row["label"] != Verdict.ALLOW.value
        stopped = result.verdict is not Verdict.ALLOW
        if is_attack:
            attacks += 1
            caught += stopped
        else:
            benign += 1
            false_positives += stopped
        exact += result.verdict.value == row["label"]

    return {
        "n": len(rows),
        "attacks": attacks,
        "benign": benign,
        "attack_recall": (caught / attacks) if attacks else None,
        "false_positive_rate": (false_positives / benign) if benign else None,
        "accuracy": (exact / len(rows)) if rows else None,
        "exact_verdict_matches": exact,
        "latency_ms_median": round(statistics.median(latencies), 2) if latencies else None,
        "latency_ms_mean": round(statistics.fmean(latencies), 2) if latencies else None,
    }


def _with_threat_memory(screener: Screener) -> Screener:
    """Simulate a Barrier that has lived through the training-set attacks.

    Every attack row in train.jsonl is planted as a confirmed antibody -
    exactly what reject() does when an analyst rules on a quarantined item.
    Measuring the immune tier this way is honest: the antibodies come only
    from the TRAINING split, the score comes only from held-out rows.
    """
    for row in load("train"):
        if row["label"] != Verdict.ALLOW.value:
            screener.ledger.learn_threat(
                f"train:{row['category']}", row["content"], row["category"],
                row.get("source", "train"), "eval-setup", entity=row.get("entity"))
    screener.immune._count = -1
    return screener


def screeners() -> list[tuple[str, Screener | None, str]]:
    """(label, screener or None when unavailable, note)."""
    import tempfile

    def build(guard: Any, mode: str) -> Screener:
        # Every screener gets its own throwaway DB: the threat-memory variant
        # plants antibodies, which must never leak into the plain-rules row,
        # the production ledger, or a second run.
        db = Path(tempfile.mkdtemp(prefix="barrier-eval-")) / "eval.db"
        screener = Screener(ledger=Ledger(db), store=LocalStore(db), guard=guard)
        screener.model_mode = mode
        return screener

    out: list[tuple[str, Screener | None, str]] = [
        ("Rules + policy only", build(NullGuard(), "off"), "no model consulted"),
        ("Rules + threat memory", _with_threat_memory(build(NullGuard(), "off")),
         "after analysts confirmed the training-set attacks"),
    ]

    river = RiverGuard()
    if river.available():
        out.append((f"Barrier guard (owned, {river.model})", build(river, "always"),
                    "fine-tuned on River, weights ours"))
    else:
        out.append((f"Barrier guard (owned)", None,
                    "not measured - set " + ", ".join(river.missing())))

    claude = AnthropicGuard()
    if claude.available():
        out.append((f"Claude screener ({claude.model})", build(claude, "always"),
                    "general model, not fine-tuned"))
    else:
        out.append(("Claude screener", None, "not measured - set ANTHROPIC_API_KEY"))

    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="cap rows per set (for a quick pass)")
    parser.add_argument("--screeners", default="",
                        help="comma-separated filter: rules, threat, guard, claude (default: all)")
    args = parser.parse_args()

    wanted = {w.strip().lower() for w in args.screeners.split(",") if w.strip()}
    KEYWORD = {"rules": "rules + policy only", "threat": "threat memory",
               "guard": "barrier guard", "claude": "claude"}

    test, pack = load("test"), load("attack_pack")
    if not test and not pack:
        print("No datasets found. Run: python training/dataset.py")
        return
    if args.limit:
        test, pack = test[: args.limit], pack[: args.limit]

    combined = test + pack
    rows_out: list[dict[str, Any]] = []

    print(f"Evaluating on {len(test)} held-out rows + {len(pack)} obfuscated attacks\n")
    header = f"{'screener':<36} {'held-out recall':>16} {'obfusc. recall':>15} {'false pos':>10} {'median ms':>10}"
    print(header)
    print("-" * len(header))

    for name, screener, note in screeners():
        if wanted and not any(KEYWORD.get(w, w) in name.lower() for w in wanted):
            continue
        if screener is None:
            print(f"{name:<36} {DASH:>16} {DASH:>15} {DASH:>10} {DASH:>10}   ({note})")
            rows_out.append({"name": name, "available": False, "note": note,
                             "attack_recall": None, "false_positive_rate": None,
                             "accuracy": None, "n": None})
            continue

        on_test = measure(screener, test)
        on_pack = measure(screener, pack) if pack else {}
        on_all = measure(screener, combined)

        def fmt(value: float | None) -> str:
            return DASH if value is None else f"{value:.0%}"

        print(f"{name:<36} {fmt(on_test.get('attack_recall')):>16} "
              f"{fmt(on_pack.get('attack_recall')):>15} "
              f"{fmt(on_test.get('false_positive_rate')):>10} "
              f"{on_all.get('latency_ms_median', 0):>10}")

        rows_out.append({
            "name": name, "available": True, "note": note,
            "attack_recall": on_test.get("attack_recall"),
            "obfuscated_recall": on_pack.get("attack_recall"),
            "false_positive_rate": on_test.get("false_positive_rate"),
            "accuracy": on_all.get("accuracy"),
            "n": on_all.get("n"),
            "latency_ms_median": on_all.get("latency_ms_median"),
            "held_out": on_test, "attack_pack": on_pack,
        })

    payload = {
        "measured_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "dataset": f"{len(test)} held-out rows + {len(pack)} obfuscated attacks",
        "rows": rows_out,
        "caveat": ("Seed dataset is hand-written; these are real measurements on it, not a "
                   "benchmark result. The obfuscated column is the one that matters."),
    }
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "eval.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWrote {(DATA / 'eval.json').relative_to(ROOT)} — the dashboard Intelligence tab reads it.")


if __name__ == "__main__":
    main()
