"""Self-improvement: the product retrains its own guard, from inside the product.

This is the "remembers mistakes and improves itself without outside engineering
support" requirement, made literal. No engineer edits code, runs a script, or
touches a config. An operator clicks one button in the dashboard (or hits
POST /v1/selftrain), and Barrier:

  1. gathers every mistake its analysts corrected - confirmed attacks (reject)
     and released false positives (approve) - straight from the ledger;
  2. folds them into the seed dataset as new labelled rows;
  3. fine-tunes a fresh guard on River (LoRA SFT), owned weights;
  4. measures base vs trained on held-out + obfuscated attacks;
  5. serves the new version and points the running Barrier at it;
  6. records the whole thing as guard v(N+1) in the ledger.

Every step publishes an event, so the dashboard shows the model improving in
real time. The loop closes with no human in it except the one who ruled on the
attacks in the first place - which is exactly the point.

Runs in a background thread; River work is imported lazily so the product
starts fine on a machine with no River access.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from pathlib import Path
from typing import Any

from .events import bus
from .guard import SYSTEM, parse_verdict, render_prompt
from .ledger import Ledger
from .models import Gate, ScreenRequest, Trust

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
GUARD_PORT = int(os.environ.get("BARRIER_GUARD_PORT", "7788"))


def _load(name: str) -> list[dict[str, Any]]:
    path = DATA / f"{name}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def rulings_as_rows(ledger: Ledger) -> list[dict[str, Any]]:
    """Analyst rulings, in the training row shape. This is what 'learning from
    its mistakes' means concretely: the corrections become labelled data."""
    rows: list[dict[str, Any]] = []
    for r in ledger.training_rows():          # confirmed attacks (reject)
        rows.append({**r, "origin": "confirmed_attack"})
    for t in ledger.tolerances():             # released false positives (approve)
        rows.append({
            "content": t["content"], "category": t["category"], "label": "ALLOW",
            "source": t["source_id"], "source_kind": "agent", "trust": t["trust"],
            "entity": t.get("entity"), "writer": "analyst", "operation": "remember",
            "origin": "released_false_positive",
        })
    return rows


def as_request(row: dict[str, Any]) -> ScreenRequest:
    return ScreenRequest(
        gate=Gate.MEMORY, content=row["content"], source_id=row.get("source", "unknown"),
        source_label=row.get("source", "unknown"), source_kind=row.get("source_kind", "external"),
        trust=Trust(row.get("trust", "external")), agent_id="training",
        writer=row.get("writer", "ingest-agent"), entity=row.get("entity"),
        operation=row.get("operation", "remember"), existing=[])


def _target(row: dict[str, Any]) -> str:
    risk = {"ALLOW": 0.05, "QUARANTINE": 0.82, "BLOCK": 0.94}[row["label"]]
    reason = row.get("reason") or row["category"].replace("_", " ")
    return json.dumps({"verdict": row["label"], "risk": risk,
                       "category": row["category"], "reason": reason[:80]})


class SelfTrainer:
    """Owns the one-at-a-time self-training run and its live status."""

    def __init__(self, ledger: Ledger, base_model: str | None = None,
                 screener: Any | None = None) -> None:
        self.ledger = ledger
        self.screener = screener  # so a finished run can make the product USE the new guard
        self.base_model = base_model or os.environ.get("RIVER_BASE_MODEL", "Qwen/Qwen3.5-9B")
        self._thread: threading.Thread | None = None
        self.status: dict[str, Any] = {"state": "idle"}

    def available(self) -> bool:
        return bool(os.environ.get("RIVER_API_KEY"))

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, base_model: str | None = None) -> dict[str, Any]:
        if not self.available():
            return {"started": False, "reason": "RIVER_API_KEY not set"}
        if self.running():
            return {"started": False, "reason": "a self-training run is already in progress"}
        if base_model:
            self.base_model = base_model
        rulings = rulings_as_rows(self.ledger)
        self._thread = threading.Thread(target=self._run, args=(rulings,), daemon=True)
        self._thread.start()
        return {"started": True, "base_model": self.base_model, "from_rulings": len(rulings)}

    # ------------------------------------------------------------------ run

    def _emit(self, step: str, **extra: Any) -> None:
        self.status = {"state": "running", "step": step, **extra}
        bus.publish("selftrain", {"step": step, **extra})

    def _run(self, rulings: list[dict[str, Any]]) -> None:
        seed_train = _load("train")
        test = _load("test") + _load("attack_pack")
        train = seed_train + rulings
        version = self.ledger.add_guard_version(
            self.base_model, len(train), len(rulings),
            note=f"{len(rulings)} analyst rulings folded into {len(seed_train)} seed rows")
        vid = version["id"]
        try:
            self._emit("preparing", version=version["version"], base_model=self.base_model,
                       seed_rows=len(seed_train), ruling_rows=len(rulings))

            import river_client as river  # lazy: keeps startup River-free
            from transformers import AutoTokenizer

            client = river.Client(api_key=os.environ["RIVER_API_KEY"])
            self._emit("connected", version=version["version"])

            tokenizer = AutoTokenizer.from_pretrained(self.base_model)
            eos = tokenizer.eos_token_id

            def datum(row: dict[str, Any]) -> dict[str, Any]:
                prompt = tokenizer(f"{SYSTEM}\n\n{render_prompt(as_request(row))}",
                                   add_special_tokens=False)["input_ids"]
                completion = (tokenizer(" " + _target(row), add_special_tokens=False)["input_ids"]
                              + [eos])
                ids = prompt + completion
                return {"input_ids": ids, "target_tokens": ids[1:] + [eos],
                        "weights": [0.0] * (len(prompt) - 1) + [1.0] * (len(completion) + 1)}

            def score(model: Any) -> float:
                outs = model.sample([f"{SYSTEM}\n\n{render_prompt(as_request(r))}" for r in test],
                                    max_tokens=64, temperature=0.0)
                correct = sum(
                    bool((pv := parse_verdict(o[0].text, "eval")) and pv.verdict.value == r["label"])
                    for o, r in zip(outs, test))
                return correct / max(len(test), 1)

            rng = random.Random(7)
            with client.session(project="barrier") as session:
                model = session.create_model(base_model=self.base_model,
                                             lora=river.LoraConfig(rank=16))
                self._emit("scoring_base", version=version["version"])
                base_acc = score(model)
                self.ledger.finish_guard_version(vid, "training", base_accuracy=base_acc)
                self._emit("base_scored", version=version["version"], base_accuracy=base_acc)

                data = [datum(r) for r in train]
                epochs = 3
                for epoch in range(epochs):
                    rng.shuffle(data)
                    last = None
                    for start in range(0, len(data), 16):
                        last = model.forward_backward(data[start:start + 16], loss_fn="cross_entropy")
                        model.optim_step(lr=2e-4, grad_clip_norm=1.0)
                    loss = float(last.metrics["loss"]) if last else None
                    self._emit("epoch", version=version["version"], epoch=epoch + 1,
                               epochs=epochs, loss=loss)

                trained_acc = score(model)
                self._emit("trained_scored", version=version["version"],
                           base_accuracy=base_acc, accuracy=trained_acc)
                model.save_weights(f"barrier-guard-v{version['version']}", mode="training")

                self.ledger.finish_guard_version(
                    vid, "serving", base_accuracy=base_acc, accuracy=trained_acc,
                    note=f"base {base_acc:.0%} -> trained {trained_acc:.0%} on {len(train)} rows "
                         f"({len(rulings)} from analyst rulings)")

                # Point the running Barrier at the freshly trained model and
                # keep serving it from THIS live session, so the demo can screen
                # a write through the model it just trained.
                self._serve(model, version["version"], base_acc, trained_acc)
        except Exception as exc:  # noqa: BLE001 - a failed run must report, not vanish
            self.ledger.finish_guard_version(vid, "failed", note=str(exc)[:200])
            self.status = {"state": "failed", "error": str(exc)[:200]}
            bus.publish("selftrain", {"step": "failed", "error": str(exc)[:200]})

    def _serve(self, model: Any, version: int, base_acc: float, trained_acc: float) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        name = f"barrier-guard-v{version} (owned, River)"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self._json({"ok": True, "model": name})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length", 0))
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                    prompt = payload.get("prompt", "")
                    outs = model.sample([f"{SYSTEM}\n\n{prompt}"], max_tokens=64, temperature=0.0)
                    pv = parse_verdict(outs[0][0].text, name)
                    self._json({"verdict": pv.verdict.value, "risk": pv.risk,
                                "category": pv.category, "reason": pv.reason,
                                "model_version": name} if pv
                               else {"error": "unparseable", "raw": outs[0][0].text})
                except Exception as exc:  # noqa: BLE001
                    self._json({"error": str(exc)})

            def _json(self, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_: Any) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", GUARD_PORT), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        os.environ["BARRIER_GUARD_URL"] = f"http://127.0.0.1:{GUARD_PORT}"
        # Make the running product actually USE the model it just trained:
        # rebind the live screener's guard to the freshly served one.
        if self.screener is not None:
            from .guard import HttpGuard
            self.screener.guard = HttpGuard()
        self.status = {"state": "serving", "version": version,
                       "base_accuracy": base_acc, "accuracy": trained_acc,
                       "url": os.environ["BARRIER_GUARD_URL"]}
        self._emit("serving", version=version, base_accuracy=base_acc,
                   accuracy=trained_acc, url=os.environ["BARRIER_GUARD_URL"])
        # Keep the session/model alive for the life of the process.
        while True:
            time.sleep(3600)
