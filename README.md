# 🛡️ Agent Immune System

Runtime defense for injection-susceptible AI agents. It does not just detect that an
agent was hijacked. It **proves which input caused it** and **synthesizes a verified
guardrail**, regression-tested against the entire recorded history before it deploys.

Built for the Cyberdefense Hackathon (SF Tech Week, 2026-10-09).

---

## The problem

Agentic AI systems act on whatever is in their context. When that context includes
retrieved documents, tickets, or web pages, an attacker can plant instructions there:
indirect prompt injection. The agent reads a poisoned document and quietly does the
attacker's bidding, such as sending customer data to an external address.

Detection tools tell you *something* happened. They don't tell you **why**, and they
don't **fix** it. That gap is where this project lives.

## What it does

A four-theme loop (threat discovery, attack intelligence, autonomous remediation,
continuous defense) in one system:

1. **Provenance recording.** Every item the agent sees is tagged with its source and a
   trust label (trusted: user/system; untrusted: retrieved/ticket/web). Every tool call
   and reply is recorded to ClickHouse with those tags.
2. **Real-time detection.** A single SQL query flags a session when an *external*
   data-movement tool call carries *sensitive* content **and** the session contains
   *untrusted* input. Detection keys on provenance **flow**, not keywords, so it survives
   paraphrase. (~40 ms over a 3M-row corpus.)
3. **Causal replay.** The flagged session is re-run with each untrusted input removed.
   The item whose removal stops the leak is the proven cause, shown as a side-by-side
   action diff. If a payload is split across items, a minimal causal set is found.
4. **Auto-vaccination.** The isolated attack is mutated into many evasive variants (an
   open model on AkashML, with an offline fallback). A guardrail is synthesized against
   the attack family, then **verified**: it must block every variant **and** produce
   **zero** false positives when replayed against the whole recorded corpus in ClickHouse.
   Only then is it deployed.
5. **Immunity.** The attack is re-run against the deployed guardrail. The poisoned input
   is blocked at the door; no leak.

## Why it is innovative

- **Causal attribution at runtime.** Most defenses classify content as "looks like
  injection." This isolates the *specific* input responsible, with counterfactual
  evidence a human can read.
- **Verified auto-patching against production history.** A new security control is not
  trusted on faith. It is regression-tested against millions of recorded sessions in
  sub-second time, so a rule that would break legitimate traffic never ships.
- **Provenance-flow detection** that is robust to encodings, homoglyphs, and paraphrase,
  because the signal is the data-flow shape, not the wording.

Prior art (e.g. provenance-based agent defenses like CaMeL) informs the design. The
contribution here is the combination: **runtime causal isolation + verified,
history-regression-tested auto-remediation**, in one continuous loop.

## Sponsor fit

- **ClickHouse (real-time analytics):** the event store and the verification engine.
  Detection and whole-history rule regression-testing run in tens to ~120 ms over
  millions of rows. Scale and latency directly drive remediation.
- **AkashML:** hosts the open model used for attack mutation and incident summaries.
- **Pi (agentic product security):** end-to-end: discover → explain → remediate → verify.

## Run it

Fully offline by default (embedded ClickHouse via chDB, deterministic stubs). No keys
needed.

```bash
pip install -r requirements.txt

python run.py seed 200        # record 200 benign + 200 attack sessions
python run.py scale 1000000   # optional: backfill 1M benign sessions (~35s local)
python run.py demo            # full detect -> replay -> vaccinate -> reverify

uvicorn server:app            # dashboard at http://127.0.0.1:8000
```

To use ClickHouse Cloud and AkashML, copy `.env.example` to `.env`, fill it in, and
`set -a; . ./.env; set +a` before running. The code switches automatically.

## Measured (local embedded engine, 3M event rows)

| Step | Result |
|---|---|
| Backfill 1M sessions (3M rows) | ~35 s |
| Detection query | ~40 ms |
| Guardrail verification over full history | ~123 ms |
| Attack variants blocked | 9 / 9 |
| False positives on benign history | 0 |

Numbers reproduce with `python run.py scale 1000000 && python run.py demo`.

## Layout

```
ais/normalize.py   content normalization (encodings, homoglyphs, defang)
ais/store.py       ClickHouse access (Cloud or embedded chDB), same schema
ais/agent.py       deterministic test harness (no real I/O; placeholder data only)
ais/scenarios.py   synthetic benign + labeled attack sessions
ais/detect.py      provenance-flow detection SQL
ais/replay.py      causal replay + action diff
ais/llm.py         AkashML client + offline fallback
ais/vaccine.py     mutate -> synthesize -> verify-against-history -> deploy
ais/backfill.py    direct-to-ClickHouse scale corpus
ais/pipeline.py    the end-to-end loop
server.py          FastAPI dashboard
```

## Safety note

The test harness does no real I/O and holds only opaque placeholder tokens, never real
personal data. Its only purpose is to exercise the defense. This is a defensive tool: it
isolates and blocks attacks; it is not an attack kit.
