"""The owned guard: list base models, train on River, serve on :7788.

    python training/guard_server.py models
    python training/guard_server.py train --base <model-id> --serve
    python training/guard_server.py serve --base <model-id>          # untrained, for comparison

Serving answers POST /screen with {"verdict","risk","category","reason"},
which is exactly what barrier.guard.HttpGuard consumes. Point the runtime at
it with:

    BARRIER_GUARD_URL=http://127.0.0.1:7788

UNVERIFIED against a live River account: the calls follow River's documented
Python API (create_model -> forward_backward -> optim_step -> save_weights,
sampling from the live session), but the first run against a real key is the
integration test. `models` prints whatever the client exposes rather than
guessing ids. Requires: pip install river-client transformers
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from barrier.guard import SYSTEM, parse_verdict, render_prompt  # noqa: E402
from barrier.models import Gate, ScreenRequest, Trust  # noqa: E402

DATA = ROOT / "data"
PORT = int(os.environ.get("BARRIER_GUARD_PORT", "7788"))


def _need_key() -> str:
    key = os.environ.get("RIVER_API_KEY", "")
    if not key:
        raise SystemExit("RIVER_API_KEY is not set. Get one from the River team at the event.")
    return key


def _client():
    try:
        import river_client as river  # type: ignore
    except ImportError:
        raise SystemExit("pip install river-client transformers") from None
    return river, river.Client(api_key=_need_key())


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
    risk = {"ALLOW": 0.05, "QUARANTINE": 0.82, "BLOCK": 0.94}[row["label"]]
    reason = row.get("reason") or row["category"].replace("_", " ")
    return json.dumps({"verdict": row["label"], "risk": risk,
                       "category": row["category"], "reason": reason[:80]})


def cmd_models() -> None:
    """Print the base models this key can actually reach. No guessing."""
    river, client = _client()
    printed = False
    for attr in ("list_models", "models", "available_models", "base_models"):
        candidate = getattr(client, attr, None)
        if candidate is None:
            continue
        try:
            result = candidate() if callable(candidate) else candidate
        except Exception as exc:  # noqa: BLE001 - present the API's own error
            print(f"  client.{attr} -> {exc}")
            continue
        print(f"Models via client.{attr}:")
        for item in result if isinstance(result, (list, tuple)) else [result]:
            print(f"  {getattr(item, 'id', item)}")
        printed = True
        break
    if not printed:
        print("This river-client version exposes no model-listing call I recognise.")
        print("Ask the River team which base models your event key can train, then:")
        print("  python training/guard_server.py train --base <model-id> --serve")


def accuracy(model: Any, rows: list[dict[str, Any]], label: str) -> float:
    outs = model.sample(prompts=[f"{SYSTEM}\n\n{render_prompt(as_request(r))}" for r in rows],
                        num_samples=1, max_tokens=64, temperature=0.0)
    correct = 0
    for out, row in zip(outs, rows):
        parsed = parse_verdict(out[0].text, label)
        correct += bool(parsed and parsed.verdict.value == row["label"])
    score = correct / max(len(rows), 1)
    print(f"{label} accuracy: {score:.1%}  ({correct}/{len(rows)})")
    return score


class GuardHandler(BaseHTTPRequestHandler):
    model: Any = None
    model_name: str = "unconfigured"

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/screen":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            prompt = payload.get("prompt") or render_prompt(ScreenRequest(
                gate=Gate.MEMORY, content=payload.get("content", ""),
                source_label=payload.get("source_label", "unknown"),
                trust=Trust(payload.get("trust", "external"))))
            outs = GuardHandler.model.sample(prompts=[f"{SYSTEM}\n\n{prompt}"], num_samples=1,
                                             max_tokens=64, temperature=0.0)
            parsed = parse_verdict(outs[0][0].text, GuardHandler.model_name)
            body = ({"verdict": parsed.verdict.value, "risk": parsed.risk,
                     "category": parsed.category, "reason": parsed.reason,
                     "model_version": parsed.model_version}
                    if parsed else {"error": "unparseable model output", "raw": outs[0][0].text})
        except Exception as exc:  # noqa: BLE001 - a guard that crashes must say so
            body = {"error": str(exc)}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"  guard: {fmt % args}")


def serve_model(model: Any, name: str) -> None:
    GuardHandler.model = model
    GuardHandler.model_name = name
    print(f"\nServing the guard on http://127.0.0.1:{PORT}/screen")
    print(f"Point Barrier at it:  BARRIER_GUARD_URL=http://127.0.0.1:{PORT}")
    print("Then restart barrier.api and rerun training/evaluate.py for real numbers.")
    ThreadingHTTPServer(("127.0.0.1", PORT), GuardHandler).serve_forever()


def cmd_train(args: argparse.Namespace) -> None:
    river, client = _client()
    from transformers import AutoTokenizer  # type: ignore

    train = load("train")
    test = load("test") + load("attack_pack")
    print(f"train={len(train)} rows  eval={len(test)} rows  base={args.base}")

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

    rng = random.Random(7)
    with client.session(project="barrier") as session:
        model = session.create_model(base_model=args.base, lora=river.LoraConfig(rank=args.rank))
        if not args.skip_base_eval:
            accuracy(model, test, "base (untrained adapter)")
        data = [datum(r) for r in train]
        for epoch in range(args.epochs):
            rng.shuffle(data)
            batch = None
            for start in range(0, len(data), args.batch):
                batch = model.forward_backward(data[start:start + args.batch],
                                               loss_fn="cross_entropy")
                model.optim_step(lr=args.lr, grad_clip_norm=1.0)
            print(f"epoch {epoch + 1}/{args.epochs}  step={model.step}  "
                  f"loss={batch.metrics['loss']:.4f}")
        accuracy(model, test, "trained guard")
        model.save_weights(args.name, mode="inference")
        print(f"Saved checkpoint '{args.name}' (weights are yours).")
        if args.serve:
            # Serve from the SAME live session so the prompt format matches training.
            serve_model(model, f"barrier-guard ({args.base}, owned)")


def cmd_serve(args: argparse.Namespace) -> None:
    river, client = _client()
    with client.session(project="barrier") as session:
        model = session.create_model(base_model=args.base, lora=river.LoraConfig(rank=args.rank))
        serve_model(model, f"untrained base ({args.base})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("models", help="list base models this key can reach")

    for name in ("train", "serve"):
        p = sub.add_parser(name)
        p.add_argument("--base", required=True, help="base model id (from `models`)")
        p.add_argument("--rank", type=int, default=16)
        if name == "train":
            p.add_argument("--epochs", type=int, default=3)
            p.add_argument("--batch", type=int, default=16)
            p.add_argument("--lr", type=float, default=2e-4)
            p.add_argument("--name", default="barrier-guard-v1")
            p.add_argument("--serve", action="store_true", help="serve on :7788 after training")
            p.add_argument("--skip-base-eval", action="store_true")

    args = parser.parse_args()
    if args.cmd == "models":
        cmd_models()
    elif args.cmd == "train":
        cmd_train(args)
    else:
        cmd_serve(args)


if __name__ == "__main__":
    main()
