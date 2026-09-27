# Barrier

**AI-native security intelligence layer for AI agents that retrains itself, with no engineer in the loop.**

Your agents share a memory. Anyone who can email you can write a "false fact" into it that every agent then trusts. Barrier sits between agents and their memory and decides — **allow, hold for review, or block** — before the false/poison ever lands. Then it does the thing no security tool does: it remembers every correction a human makes and gets better on its own.

> Own your agents. Own your memory. **Own what they trust.**

Built at the YC *Own Your Intelligence* hackathon. Uses **GBrain, QM, River, Memorable, Superset**.

---

## The one-minute version

```
  An email says: "Acme changed banks — pay account 999-123-4471 from now on."

  WITHOUT Barrier   →  saved to shared memory  →  every agent pays the attacker
  WITH Barrier      →  QUARANTINE (conflicts with the account on file)  →  poison never lands
```

And when it makes a mistake, it fixes itself:

```
  Analyst confirms an attack   →  Barrier catches every re-send of it, instantly
  Analyst releases a false alarm →  Barrier stops flagging that kind of write
  Enough corrections pile up   →  one click retrains the model on River — weights you own
```

---

## How it decides — four tiers, three of them free

Every write crosses four checks in one call:

| Tier | What it does | You own it because |
|---|---|---|
| **1. Rules + policy** | Fast pattern checks, weighted by *who sent it* | you can read every rule, edit every policy |
| **2. Threat & tolerance memory** | Learns from your analysts' rulings — both directions | it's your attack history, nobody else's |
| **3. Owned guard model** | A model fine-tuned on **River** from your own data | the trained weights are yours |
| **4. Lineage** | A poisoned account number stays blocked in later payments | it's built from your own decision log |

The key idea in tier 1: **the same words get different answers depending on who sent them.** "From now on…" from a teammate is a preference. The same words in an inbound email is an attack.

---

## The part that self-improves (tier 2)

This is the "remembers mistakes and improves without outside engineering" requirement, made literal.

```
                 ┌─────────────────────────────────────────────┐
                 │            YOUR ANALYSTS' RULINGS            │
                 │  "confirm malicious"      "release, it's ok" │
                 └──────────────┬───────────────┬──────────────┘
                                │               │
                        ANTIBODY│               │TOLERANCE
                 (raise risk on │               │ (lower risk on
                   look-alikes) │               │  look-alikes)
                                ▼               ▼
                   ┌──────────────────────────────────────┐
                   │  catches the NEXT attack instantly,   │
                   │  stops repeating the SAME false alarm │
                   │        — no retraining needed         │
                   └───────────────────┬──────────────────┘
                                       │  every ruling is also saved as labelled data
                                       ▼
                   ┌──────────────────────────────────────┐
                   │  one click →  RIVER fine-tune (LoRA)  │
                   │  →  new owned guard  →  served live   │
                   │        NO ENGINEER IN THE LOOP        │
                   └──────────────────────────────────────┘
```

- **Confirm an attack** → it becomes an *antibody*. A re-sent copy (even with the account number changed, even reworded) is caught the moment it arrives.
- **Release a false alarm** → it becomes a *tolerance*. Barrier stops quarantining that kind of write from equally-trusted sources — but never excuses a secret, a `curl | sh`, or the same words from an outside source.
- **Click "Retrain"** → Barrier gathers every ruling, fine-tunes a fresh guard on **River**, measures it, and serves it. You watch it happen live in the dashboard.

You can see all of this run in the product: the **Self-improvement** tab shows the training steps and every guard version it has trained for itself. (The tab reports a stricter *exact-verdict* score — allow/hold/block all have to match — so its numbers read lower than the "attack caught" table below; both are real, just measuring different things.)

---

## Run it

Python 3.10+. No Node, no Bun.

```bash
python -m venv .venv && .venv\Scripts\activate      # or: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                                 # optional (River/QM keys)

python -m barrier.api        # dashboard + API on http://127.0.0.1:7777
```

Open the dashboard. Everything is testable by hand:

- **Live test** tab — type any message, pick who sent it, watch Barrier decide in real time. This is the *same* path an agent hits; nothing is faked.
- **Quarantine** tab — rule on held items. Watch the mistake memory grow.
- **Self-improvement** tab — click **Retrain the guard on our mistakes** and watch River train a new model.

Other commands:

```bash
python -m barrier.demo       # a scripted 9-beat story in the terminal
python -m pytest -q          # tests
python training/guard_server.py models    # list the River models your key can train
```

---

## Make a demo video (step by step, all real)

1. `python -m barrier.api`, open `http://127.0.0.1:7777`, go to **Live test**.
2. Click **Wire fraud**, hit **Screen it** → **QUARANTINE** with the reason. *This poison is stopped.*
3. Edit the text — change the account number, reword it — screen again. *Still caught.*
4. Click **Benign (internal)**, screen it → **ALLOW**. *Normal work passes.*
5. Go to **Quarantine**, click **Confirm malicious** on the wire-fraud item.
6. Back to **Live test**, paste a *reworded* version of that attack → **BLOCK, immune tier**. *It just learned.*
7. Go to **Self-improvement**, click **Retrain the guard on our mistakes**. *Watch River train a new owned model, live.*

No pre-clicked buttons, no canned answers — you type, it decides.

---

## Measured results

Real numbers from `python training/evaluate.py` (written to `data/eval.json`, shown on the Intelligence tab). Barrier never shows a number it didn't measure.

On 22 held-out writes + 26 out-of-vocabulary attacks (reworded, obfuscated, and in Russian / Spanish / German / Uzbek):

| Screener | Normal attacks caught | Reworded/foreign attacks caught | False alarms |
|---|---|---|---|
| Rules only | 93% | **0%** | 12% |
| Rules + learned threat memory | 93% | **23%** | 12% |
| Rules + **owned River-trained guard** | **100%** | **100%** | 12% |

Read it top to bottom. Hand-written rules catch **0%** of the reworded and foreign-language attacks — a rule only knows the phrasings its author imagined. Learning from confirmed attacks recovers some (**23%**) for free, no code changed. The **owned guard, fine-tuned on River** (base model `Qwen/Qwen3.5-9B`), closes the whole gap — **100%**, on writes it has never seen, in languages the rules can't read. Weights you keep.

*Honest caveat: the test set is small and hand-written, so treat 100% as "clean sweep on this set," not a benchmark. The **shape** — rules blind to what they didn't anticipate, the owned model catching it — is the real result. The owned guard is slower (~2.7s/screen, a round-trip to the model) which is why Barrier screens at the write, once, not on every read.*

---

## How each sponsor is used

| Sponsor | How Barrier uses it |
|---|---|
| **GBrain** | Barrier speaks GBrain's memory verbs (`remember, recall, forget, entity, …`) as an MCP server your agents connect to *instead of* the brain. Reads pass through; writes are screened. `forget` powers one-click source withdrawal. |
| **River** | Trains and serves the **owned guard model** — the product retrains itself on River from its own mistakes, live, from inside the app (`training/guard_server.py`, `barrier/selftrain.py`). Verified working against the live River API. |
| **Memorable** | The procedure gate: `POST /v1/memorable/extract` screens a tool-call trace and forwards clean ones to Memorable; poisoned ones (`curl \| sh`, credential reads) are refused before any agent learns them. |
| **QM** | Barrier implements QM's security-screen proxy contract (`POST /v1/qm/screen`) with `enforce`/`shadow` postures, so QM agents get screened external content. |
| **Superset** | Used to build the project in parallel workspaces during the hackathon. |

Honest status: GBrain (local store), River (self-training), Memorable and QM screening are all working here. The live-GBrain adapter and the Memorable/QM *forwarding* to their hosted APIs follow the documented contracts but need a live endpoint to confirm — we don't claim "works with X" until it's run against X.

---

## Under the hood

```
barrier/
  rules.py       tier 1: pattern detectors
  policy.py      tier 1: your policies + trust weighting
  immune.py      tier 2: antibodies (attacks) + tolerances (false alarms)
  guard.py       tier 3: the owned model, behind one swappable interface
  screen.py      the one screening call; tier 4 lineage; enforce/shadow
  selftrain.py   the self-improvement engine (River, from inside the app)
  ledger.py      every decision, ruling, mistake, guard version (SQLite)
  store.py       protected memory: GBrain verbs (local + live adapter)
  mcp_proxy.py   the MCP server agents connect to
  api.py         FastAPI + live event stream (SSE)
  static/        the dashboard
training/        dataset, evaluate, guard_server (train + serve on :7788)
demo/            the scripted story + live-agent run book
```

## Configuration (all optional)

```
RIVER_API_KEY          train + serve the owned guard on River
BARRIER_GUARD_URL      point at an already-serving guard (e.g. :7788)
QM_API_KEY             QM integration
MEMORABLE_API_KEY      forward clean traces to Memorable
GBRAIN_URL             use a live GBrain instead of the local store
```

With none of it set, Barrier runs tiers 1, 2 and 4 — and tells you the model tier is off rather than pretending otherwise.
