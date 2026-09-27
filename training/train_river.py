"""Fine-tune the Barrier guard on River. The weights are yours.

    set RIVER_API_KEY=...
    python training/train_river.py --base <model-id>

UNVERIFIED: this follows River's documented SFT flow (create_model ->
forward_backward -> optim_step -> save_weights) but has not been run against a
live River account from this machine. Treat the first run as the integration
test, and do not put a number from it on a slide until you have seen it.

Two things to confirm with the River team before running:
  * the base model id your event key can reach (--base, or RIVER_BASE_MODEL)
  * the OpenAI-compatible base URL and served name for the saved checkpoint,
    which then go into RIVER_BASE_URL / RIVER_MODEL so the runtime can use it.

The prompt rendering comes from barrier.guard.render_prompt, so what the model
is trained on is exactly what the screener sends at runtime. If you change one,
change both.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from barrier.guard import SYSTEM, render_prompt  # noqa: E402
from barrier.models import Gate, ScreenRequest, Trust  # noqa: E402

DATA = ROOT / "data"


def load(name: str) -> list[dict[str, Any]]:
    path = DATA / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"{path} not found. Run: python training/dataset.py")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def as_request(row: dict[str, Any]) -> ScreenRequest:
    return ScreenRequest(
        gate=Gate.MEMORY, content=row["content"], source_id=row.get("source", "unknown"),
        source_label=row.get("source", "unknown"), source_kind=row.get("source_kind", "external"),
        trust=Trust(row.get("trust", "external")), agent_id="training",
        writer=row.get("writer", "ingest-agent"), entity=row.get("entity"),
        operation=row.get("operation", "remember"), existing=[])


def target(row: dict[str, Any]) -> str:
    """What the guard should emit. Same JSON shape the runtime parses."""
    risk = {"ALLOW": 0.05, "QUARANTINE": 0.82, "BLOCK": 0.94}[row["label"]]
    reason = row.get("reason") or row["category"].replace("_", " ")
    return json.dumps({"verdict": row["label"], "risk": risk,
                       "category": row["category"], "reason": reason[:80]})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("RIVER_BASE_MODEL", ""),
                        help="base model id (ask River which your key can reach)")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--rank", type=int, default=16)
    parser.add_argument("--name", default="barrier-guard-v1")
    parser.add_argument("--dry-run", action="store_true",
                        help="render the training pairs and stop, no API calls")
    args = parser.parse_args()

    train, test = load("train"), load("test") + load("attack_pack")
    print(f"train={len(train)} rows  eval={len(test)} rows")

    if args.dry_run:
        example = train[0]
        print("\n--- prompt ---\n" + render_prompt(as_request(example)))
        print("\n--- target ---\n" + target(example))
        print(f"\nDry run only. {len(train)} pairs would be sent.")
        return

    if not os.environ.get("RIVER_API_KEY"):
        raise SystemExit("RIVER_API_KEY is not set. Get one from the River team at the event.")
    if not args.base:
        raise SystemExit("Pass --base <model-id>, or set RIVER_BASE_MODEL. "
                         "Ask River which base models your key can reach - do not guess.")

    try:
        import river_client as river  # type: ignore
        from transformers import AutoTokenizer  # type: ignore
    except ImportError as exc:
        raise SystemExit(f"Missing dependency: {exc}. pip install river-client transformers") from exc

    client = river.Client(api_key=os.environ["RIVER_API_KEY"])
    tokenizer = AutoTokenizer.from_pretrained(args.base)
    eos = tokenizer.eos_token_id

    def datum(row: dict[str, Any]) -> dict[str, Any]:
        prompt = tokenizer(f"{SYSTEM}\n\n{render_prompt(as_request(row))}",
                           add_special_tokens=False)["input_ids"]
        completion = tokenizer(" " + target(row), add_special_tokens=False)["input_ids"] + [eos]
        ids = prompt + completion
        # Loss only on the completion: the prompt is context, not a target.
        return {"input_ids": ids, "target_tokens": ids[1:] + [eos],
                "weights": [0.0] * (len(prompt) - 1) + [1.0] * (len(completion) + 1)}

    def accuracy(model: Any, rows: list[dict[str, Any]]) -> float:
        from barrier.guard import parse_verdict

        outputs = model.sample(prompts=[f"{SYSTEM}\n\n{render_prompt(as_request(r))}" for r in rows],
                               num_samples=1, max_tokens=64, temperature=0.0)
        correct = 0
        for out, row in zip(outputs, rows):
            parsed = parse_verdict(out[0].text, "eval")
            correct += bool(parsed and parsed.verdict.value == row["label"])
        return correct / max(len(rows), 1)

    rng = random.Random(7)
    with client.session(project="barrier") as session:
        model = session.create_model(base_model=args.base, lora=river.LoraConfig(rank=args.rank))
        print(f"base (untrained adapter) accuracy: {accuracy(model, test):.1%}")

        data = [datum(r) for r in train]
        for epoch in range(args.epochs):
            rng.shuffle(data)
            for start in range(0, len(data), args.batch):
                batch = model.forward_backward(data[start:start + args.batch], loss_fn="cross_entropy")
                model.optim_step(lr=args.lr, grad_clip_norm=1.0)
            print(f"epoch {epoch + 1}/{args.epochs}  step={model.step}  "
                  f"loss={batch.metrics['loss']:.4f}")

        trained = accuracy(model, test)
        print(f"trained accuracy: {trained:.1%}")
        model.save_weights(args.name, mode="inference")
        print(f"\nSaved checkpoint '{args.name}'. Ask River for its served name and base URL, then:")
        print("  set RIVER_BASE_URL=<openai-compatible base url>")
        print(f"  set RIVER_MODEL=<served name for {args.name}>")
        print("  python training/evaluate.py     # now measures the owned model too")


if __name__ == "__main__":
    main()
