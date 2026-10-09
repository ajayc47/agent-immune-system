# Submission

**Project:** Agent Immune System
**Repo:** https://github.com/ajayc47/agent-immune-system
**Team:** Ajay Chandramouly (ajmouly@gmail.com) — solo
**Demo video:** [add link]
**Live site / screenshot:** dashboard via `uvicorn server:app` (screenshot in repo)

## What we built

A runtime defense for injection-susceptible AI agents. When an agent is hijacked by an
indirect prompt injection (a poisoned retrieved document that makes it exfiltrate data),
the system (1) detects it in real time from provenance flow, (2) **proves which input
caused it** via causal replay with a counterfactual action diff, and (3) **synthesizes a
guardrail and verifies it against the entire recorded history** in ClickHouse before
deploying, requiring zero false positives. Re-running the attack is then blocked.

The novelty is runtime **causal attribution** plus **verified auto-remediation
regression-tested against production history**, in one continuous loop covering all four
hackathon themes: discovery, intelligence, remediation, continuous defense.

## Tools used

- **ClickHouse** (real-time analytics): event store and verification engine. Detection
  ~40 ms and full-history guardrail regression-testing ~123 ms over 3M rows. Runs on
  ClickHouse Cloud, or embedded via chDB offline.
- **AkashML**: open model (OpenAI-compatible) for attack-variant generation and incident
  summaries, with an offline fallback.
- Python, FastAPI, uvicorn for the pipeline and dashboard.

## 2-minute demo script

1. **Setup (15s).** "Agents act on whatever is in their context. If a retrieved document
   carries hidden instructions, the agent obeys them. Here's a support agent." Show the
   dashboard; 1,000,000+ sessions already recorded in ClickHouse.
2. **Attack (20s).** Click **Run**. A poisoned ticket enters context; the agent calls
   `send_record → audit@example.test`. Stage 1 flashes **DATA LEAKED**.
3. **Detect (15s).** Stage 2: flagged in ~40 ms by a provenance-flow query, not a keyword
   match. Show the latency.
4. **Explain (25s).** Stage 3: causal replay isolates `ticket-0` as the cause and shows
   the side-by-side diff: with the input, `send_record` fires; without it, the call is
   gone. "This is *why*, with evidence, not just an alert."
5. **Vaccinate (30s).** Stage 4: the attack is mutated into 9 variants on Akash, a
   guardrail is synthesized, then verified against all 3,000,000 recorded rows in ~123 ms:
   **9/9 variants blocked, 0 false positives → DEPLOYED**. "We never ship a rule that
   would break real traffic."
6. **Immune (15s).** Stage 5: re-run the same attack. The poisoned input is blocked; the
   agent does its legitimate lookup and nothing leaks.

Close: "Detect, explain, and self-heal, verified at scale. That's an immune system for
agents."
