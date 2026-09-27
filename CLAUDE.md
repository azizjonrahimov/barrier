# CLAUDE.md — session handoff for the Barrier project

Barrier is **built and tested** on this machine. Do not rewrite or restructure
it; only fix real errors, and say exactly what you changed. Never open, print,
or commit `.env`. Do not push to GitHub unless the user says so.

## What Barrier is

Owned security intelligence for AI agents: four screening tiers between what
agents learn (memory), reuse (procedures), and do (actions).

| Tier | File | What it is |
|---|---|---|
| 1 Rules + policy | `barrier/rules.py`, `barrier/policy.py` | deterministic detectors, re-weighted by source trust, bound by org policy |
| 2 Threat + tolerance memory | `barrier/immune.py` | antibodies (confirmed attacks, raise risk) + tolerances (released false positives, lower risk); trigram-cosine over canonicalized text + entity sensitization |
| 3 Owned guard | `barrier/guard.py` | model tier behind one interface: `BARRIER_GUARD_URL` (HttpGuard, `:7788`) > River API > Claude > none |
| 4 Lineage | `barrier/screen.py::_tainted_identifier` | identifiers introduced by stopped writes are blocked in later actions |

Verdicts: ALLOW / QUARANTINE / BLOCK. Posture: **enforce** (act) or **shadow**
(record what would have happened, let it through).

**Self-improvement** (`barrier/selftrain.py`): `POST /v1/selftrain` gathers every
analyst ruling (confirmed attacks + released false positives) from the ledger,
folds them into the seed dataset, fine-tunes a fresh guard on **River**,
measures base-vs-trained, serves it on `:7788`, rebinds the live screener's
guard to it, and records a `guard_versions` row. All in-process, streamed to the
dashboard over SSE (`GET /v1/events`). This is the "improves itself without
outside engineering" requirement, literal.

**Verified against the live River API on 2026-09-27** (key in `.env`, never
committed): `get_capabilities`, session/create_model (LoRA), list-prompt
sampling, forward_backward + optim_step, save_weights. Standalone run trained
`Qwen/Qwen3.5-9B` and measured owned guard = 100%/100% held-out/obfuscated
recall vs rules 0% on obfuscated. In-app self-train measured base 62.5% ->
trained 79.2% (stricter exact-verdict metric).

## Ground truth about this environment

- Windows 11; venv at `..\.venv` (repo may also get its own `.venv`).
- No Bun/Node on this box → no local GBrain. The demo runs on `LocalStore`
  (same seven verbs: remember/recall/forget/entity/synthesize/context_pack/delta).
  `GBrainBackend` in `barrier/store.py` is written but **UNVERIFIED**.
- QM proxy contract (`/v1/qm/screen`) and Memorable forward
  (`/v1/memorable/extract`) follow the documented shapes but are **UNVERIFIED**
  against live deployments. Never claim they "work with" the product until run.
- River training (`training/guard_server.py`, `training/train_river.py`)
  is **UNVERIFIED**; the first run with a real key is the integration test.
- All measured numbers live in `data/eval.json` (regenerate with
  `python training/evaluate.py`). Never put a number in README that is not in
  that file.

## Commands

```
python -m barrier.api                # API + dashboard on :7777
python -m barrier.demo               # scripted 8-beat story (resets state)
python -m pytest -q                  # 14 tests
python training/dataset.py           # rebuild labelled sets
python training/evaluate.py          # measure screeners -> data/eval.json
python training/guard_server.py models
python training/guard_server.py train --base <id> --serve   # serves :7788
```

MCP entry for harnesses: `barrier/mcp_server.py` (script-safe) or
`python -m barrier.mcp_proxy`. Live-agent demo prompts: `demo/PROMPTS.md`.

## Next, in order

1. River: get key at the event → `guard_server.py models` → pick base →
   `train --base <id> --serve` → set `BARRIER_GUARD_URL=http://127.0.0.1:7788`
   → restart api → `python training/evaluate.py` → real numbers land in
   README and dashboard automatically.
2. Connect real agents per `demo/PROMPTS.md` (remove any direct brain MCP
   server first, or agents bypass Barrier).
3. QM: tunnel :7777 (`cloudflared tunnel --url http://127.0.0.1:7777`), set
   QM's `SECURITY_SCREEN_PROXY_*` env to the tunnel + shared token.
4. Memorable: put `MEMORABLE_API_KEY` in `.env`, restart api.
5. Before the live run: `POST /v1/demo/reset {"fresh_brain":true}`, then seed
   Acme's account (step 0 in `demo/PROMPTS.md`). Rehearsals otherwise poison
   the live run.
