# Barrier

**Owned security intelligence for AI agents.** Barrier sits between what your agents learn and what your agents do — and unlike every screening API you could rent, the intelligence doing the deciding belongs to you: your rules, your policies, your attack history, your model weights.

> Own your agents. Own your models. Own your memory. **Own what they trust.**

Built for the YC *Own Your Intelligence* hackathon (GBrain × QM × River × Memorable × Superset).

---

## The problem

A prompt injection ends when the session ends. **A poisoned memory keeps working for weeks.**

Shared agent brains are built so a memory one agent saves is visible to every agent connected to the brain. That is the feature — and the attack surface. Anyone who can email you can write a "fact" that every AI on your team will then trust. Access controls guard *who may write*; nothing inspects *what gets written*.

```mermaid
flowchart LR
    A[📧 One poisoned email] --> B[Agent A ingests it]
    B --> C[(Shared brain)]
    C --> D[Agent B<br/>different harness]
    C --> E[Agent C]
    C --> F[Agent D]
    D --> G[💸 Pays the attacker's account]
    style A fill:#7f1d1d,stroke:#f87171,color:#fff
    style G fill:#7f1d1d,stroke:#f87171,color:#fff
```

Barrier screens **at the write, not the read**: a memory is written once and recalled thousands of times, so one check at write time protects every future recall.

## The architecture

```mermaid
flowchart TB
    subgraph world [External world]
        E1[Email] ; E2[Slack] ; E3[Web] ; E4[Other agents]
    end
    subgraph agents [AI agents]
        A1[Claude Code] ; A2[Codex] ; A3[QM agents]
    end
    world --> agents
    agents -->|"remember / extract / act"| B{{"BARRIER<br/>4 screening tiers"}}
    B -->|ALLOW| M[(Protected memory<br/>GBrain verbs)]
    B -->|QUARANTINE| Q[/Human review queue/]
    B -->|BLOCK| X[refused, with the reason]
    Q -->|"analyst: malicious"| T[(Threat memory<br/>antibodies)]
    Q -->|"analyst ruling"| R[(Training rows)]
    T -.->|"instant, no retraining"| B
    R -->|"River fine-tune"| G[Owned guard model]
    G -.-> B
    style B fill:#1e3a8a,stroke:#60a5fa,color:#fff
    style T fill:#4c1d95,stroke:#c084fc,color:#fff
```

### The four tiers — and who owns each one

Every write crosses four tiers in one `screen()` call. The unusual part: **each tier is a different kind of ownership**, and three of the four run with zero configuration and zero cost.

| # | Tier | How it decides | Owned because | Cost |
|---|---|---|---|---|
| 1 | **Rules + policy** | Deterministic detectors produce weighted evidence; the policy layer re-weights it by *who is speaking* | you can read every rule and edit every policy | ~0.2 ms |
| 2 | **Threat memory** | Antibodies from attacks *your* analysts confirmed — template match + entity watchlist | it is literally your attack history; exists nowhere else | ~1 ms |
| 3 | **Owned guard model** | LoRA fine-tune on River from your data and your rulings | the trained weights belong to you | one model call |
| 4 | **Lineage** | Identifiers introduced by stopped writes stay radioactive in later actions | derived from your own decision ledger | ~1 ms |

Tier 1's key idea: **the same sentence gets different verdicts depending on who said it.** `"From now on…"` from a colleague on Slack is a preference. The same words in an inbound email are an attempt to install a standing instruction. Generic detectors ask *"does this look like injection?"* — Barrier asks *"should **our** agents trust this?"*

### Tier 2 is the part nobody else has

When an analyst clicks **Confirm malicious** on a quarantined item, the attack becomes an *antibody* — instantly, with no retraining and no deploy:

```mermaid
sequenceDiagram
    participant Att as Attacker
    participant B as Barrier
    participant H as Analyst
    Att->>B: "Acme changed banks → account 999-123-4471"
    B->>H: QUARANTINE (policy FIN-01, conflicts with trusted memory)
    H->>B: Confirm malicious ✔
    Note over B: antibody stored — threat memory owns this attack now
    Att->>B: same template, rotated account 5590-8814
    B-->>Att: BLOCK — 86% similar to confirmed attack dec_… (immune tier)
    Att->>B: full rewrite, no shared words, new number for Acme
    B-->>Att: QUARANTINE — Acme is watchlisted; external write changes its identifiers (immune tier)
```

Two matchers, both dependency-free:

- **Template match** — cosine over hashed character trigrams of the *canonicalized* text. Account numbers, hosts and addresses are normalized away first, so the one field an attacker must rotate is exactly the field that cannot save them.
- **Entity sensitization** — an entity that has been attacked once is on a watchlist: an external write that reintroduces identifiers for it goes to a human, even if it shares no vocabulary with the original. This is what incident-response teams do; Barrier does it automatically.

### Tier 4: the radioactive account number

Source lineage doesn't stop at memory. Weeks later, when someone politely asks the finance agent to *"pay invoice #4821 to account 999-123-4471"*, Barrier cross-references the ledger, finds that this account entered the organization through a quarantined write, and blocks the payment — **the sentence is polite; the number carries its history.**

---

## Run it

Python 3.10+ (tested on 3.12). No Node, no Bun, no network unless you configure a model.

```bash
python -m venv .venv && .venv\Scripts\activate     # or source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                                # optional; runs fine with none of it set

python -m barrier.api        # dashboard + API on http://127.0.0.1:7777  (or run.bat)
python -m barrier.demo       # the scripted 8-beat story                 (or demo.bat)
python -m pytest -q          # 14 tests
```

## The demo (8 beats, ~3 minutes)

| # | Beat | What the room sees |
|---|---|---|
| 0 | Seed | What the org already knows — including 3 facts from one inbound pitch email |
| 1 | **Shadow mode** | The poisoned bank-change email sails into shared memory; Codex, on a different harness, repeats the attacker's account. *Barrier saw it and recorded what enforce would have done — it just wasn't allowed to act.* |
| 2 | One toggle | Withdraw the poison, flip Shadow→Enforce, replay the same email → **QUARANTINE, 95%, FIN-01**, and the citation names the exact trusted memory it conflicts with |
| 3 | The ruling | Analyst confirms malicious → training row **and antibody**, in the same click |
| 4 | The re-send | Rotated account number: **blocked by the immune tier** — no rule matched, nothing was retrained. Full rewrite: quarantined — Acme is watchlisted |
| 5 | The payment | *"Pay invoice #4821 to 999-123-4471"* → **BLOCK (lineage)**. The clean account pays normally |
| 6 | Ordinary life | The standup change and the `"from now on"` preference sail through — a security layer that blocks the ordinary case is one nobody keeps |
| 7 | Procedures | A Memorable-style trace with `curl … \| sh` and a credential read is refused before any agent learns it |
| 8 | The close | Four tiers: rules you can read, policy you wrote, threat memory you confirmed, a model you own |

For the live two-agent version (real Claude Code + Codex against the MCP server), see **`demo/PROMPTS.md`**.

---

## Measured results — never invented

From `python training/evaluate.py`, written to `data/eval.json`, shown on the dashboard's Intelligence tab. Unconfigured screeners are reported *not measured* — Barrier does not display estimates.

Measured 2026-09-27 on 22 held-out rows + 26 out-of-vocabulary attacks (paraphrased, obfuscated, and in Russian, Spanish, German and Uzbek):

| Screener | Held-out recall | Obfuscated recall | False positives | Median |
|---|---|---|---|---|
| Rules + policy only | 93% | **0%** | 12% | 1.4 ms |
| Rules + **threat memory** | 93% | **23%** | 12% | 2.8 ms |
| Barrier guard (owned) | *not measured — needs River access* | | | |
| Claude screener | *not measured — needs `ANTHROPIC_API_KEY`* | | | |

Read the story in the gap:

- **0%** — hand-written rules catch the phrasings their author imagined and *nothing else*. Published rules are also rules an attacker can read. This is the honest ceiling of every rules-only product.
- **23%** — after living through the training-set attacks (antibodies planted from the *training* split only; scored on held-out rows only), the immune tier claws back a quarter of the out-of-vocabulary attacks *at zero added false positives*, including template variants of known attacks in any wording.
- The remaining gap is the case for the **owned guard model** — trained on your data, your rulings, your synthetic attacks, with weights that never leave you.

*Caveat, stated plainly: the dataset is hand-written and small. These are real measurements on it, not a benchmark claim.*

---

## The learning loop

```mermaid
flowchart LR
    A[Attack arrives] --> B[Barrier verdict]
    B --> C[/Quarantine queue/]
    C --> D{Analyst rules}
    D -->|malicious| E[(Antibody<br/>works immediately)]
    D -->|either way| F[(Labelled training row)]
    F --> G[River SFT<br/>LoRA fine-tune]
    G --> H[Guard v2 — weights yours]
    E -.-> A2[Next attack caught]
    H -.-> A2
    style E fill:#4c1d95,stroke:#c084fc,color:#fff
    style H fill:#14532d,stroke:#34d399,color:#fff
```

Two loops at two speeds: the antibody loop closes in **one click**; the model loop closes at the next fine-tune, fed by every ruling the fast loop produced.

## How the sponsors fit

| Sponsor | Where it lives in the backend | Status |
|---|---|---|
| **GBrain** | Barrier speaks GBrain's seven memory verbs (`remember, recall, forget, entity, synthesize, context_pack, delta`) as an MCP server agents connect to *instead of* the brain; reads pass, writes are screened; `forget` powers source withdrawal | Local store implementing the same verbs: **tested**. Live-GBrain adapter (`barrier/store.py`): written, **unverified** |
| **QM** | Barrier implements QM's security-screen proxy contract — `text/hook/metadata` in, `score/threshold/primary_outcome` out — at `POST /v1/qm/screen`, with the shadow/enforce rollout postures QM defines | Contract-shaped and tested locally; **unverified** against a live QM |
| **River** | The owned guard: `training/guard_server.py` trains a LoRA SFT from `data/train.jsonl` and serves it on `:7788`; `BARRIER_GUARD_URL` plugs it into tier 3. Analyst rulings feed the next training run | Written to River's documented API; **unverified** — first run with an event key is the integration test |
| **Memorable** | The procedure gate: `POST /v1/memorable/extract` screens a tool-call trace and forwards clean ones to Memorable's extract API; poisoned ones get a 403 with the reason | Screening: **tested**. Forwarding: **unverified** |
| **Superset** | Build tool for parallel workspaces during the hackathon (macOS) — deliberately *not* forced into the runtime architecture | n/a |

The unverified labels are deliberate: **do not claim "works with X" on stage until it has actually been run against X.** Every integration is a swap behind an existing interface; nothing in the demo depends on any of them.

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/screen/memory` · `/procedure` · `/action` | the three gates |
| `POST /v1/qm/screen` | QM's security-proxy contract |
| `GET/POST /v1/posture` | `enforce` ⇄ `shadow` |
| `GET /v1/quarantine` · `POST /v1/quarantine/{id}/approve` · `/reject` | review queue (reject ⇒ antibody) |
| `GET /v1/threats` | the antibody list, with hit counts |
| `GET /v1/sources` · `POST /v1/sources/withdraw` | lineage + blast-radius withdrawal |
| `POST /v1/memorable/extract` | screen-then-forward for procedure traces |
| `POST /v1/mcp/rpc` | HTTP bridge into the MCP tool surface |
| `POST /v1/demo/reset` | fresh state without touching the file (rehearsal-safe) |
| `GET /v1/intelligence/stats` | tiers, posture, policies, measured evaluation |

MCP server for harnesses: `python -m barrier.mcp_proxy` (or the script-safe `barrier/mcp_server.py`). The client's name from the MCP `initialize` handshake tags every decision — that is how *"Claude Code wrote it, Codex read it"* appears in the ledger. Fallback for hook-based harnesses: `barrier/hook.py` (Claude Code `PreToolUse`).

## Organization policy

Policies are data (`barrier/policy.py`), not code:

| ID | Policy | Action |
|---|---|---|
| SEC-01 | External content cannot create standing instructions for our agents | BLOCK |
| FIN-01 | Banking details are never changed on the strength of a message alone | QUARANTINE |
| CRED-01 | Secrets never enter shared agent memory, whoever writes them | BLOCK |
| PROC-01 | Downloaded scripts require human approval before reuse | BLOCK |
| AGENT-01 | External sources cannot modify agent behaviour or rank recommendations | BLOCK |
| AGENT-02 | Internal attempts to reshape agent behaviour still get a human look | QUARANTINE |
| TRUST-01 | Authority a source cannot prove is reviewed before it is believed | QUARANTINE |

FIN-01 quarantines rather than blocks on purpose: a bank-detail change can be genuine — it needs a human, not a wall. It also holds *internal* finance changes, which is a feature to say out loud, not hide.

## Layout

```
barrier/
  barrier/
    models.py        verdicts, categories, requests, results
    rules.py         tier 1: deterministic detectors
    policy.py        tier 1: org policy + trust weighting
    immune.py        tier 2: antibodies (template match + entity watchlist)
    guard.py         tier 3: HttpGuard(:7788) / River / Claude / none — one seam
    screen.py        the single screening entrypoint; tier 4 lineage; posture
    ledger.py        decisions, sources, rulings, threat memory (SQLite)
    store.py         protected memory: 7 GBrain verbs, local + live adapter
    mcp_proxy.py     MCP server agents connect to instead of the brain
    mcp_server.py    script-safe MCP entry point
    hook.py          Claude Code PreToolUse fallback gate
    api.py           FastAPI: gates, queue, lineage, posture, stats
    static/          dashboard
  training/
    dataset.py       labelled seeds incl. multilingual attack pack
    guard_server.py  models / train / serve the owned guard on :7788
    train_river.py   standalone River SFT script
    evaluate.py      measures every configured screener -> data/eval.json
  demo/
    demo.py          the 8-beat scripted story
    PROMPTS.md       live two-agent run book
    emails/          the poisoned emails, v1 and v2
  tests/test_barrier.py   54 checks; pytest or standalone
  CLAUDE.md          session handoff for Claude Code
```

## Configuration

Everything optional — with none of it set, Barrier runs tiers 1+2+4 and says so.

```
BARRIER_DB              SQLite path                      (default data/barrier.db)
BARRIER_PORT            API port                         (default 7777)
BARRIER_POSTURE         enforce | shadow                 (default enforce)
BARRIER_MODEL_MODE      auto | always | off              (default auto)
BARRIER_GUARD_URL       owned guard server, e.g. http://127.0.0.1:7788
RIVER_API_KEY / RIVER_BASE_URL / RIVER_MODEL     hosted-serving alternative
ANTHROPIC_API_KEY       Claude as screener / data teacher
GBRAIN_URL              live GBrain endpoint             (adapter unverified)
MEMORABLE_API_KEY       forward clean traces to Memorable
SECURITY_SCREEN_PROXY_TOKEN   bearer token QM presents to /v1/qm/screen
```
