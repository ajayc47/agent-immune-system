"""End-to-end pipeline: record -> detect -> replay -> vaccinate -> reverify.

This is the story the demo tells, callable as one function so the dashboard and
the CLI share identical logic.
"""
from __future__ import annotations

from .agent import Harness, Session
from .detect import detect
from .replay import causal_items, diff_actions
from .scenarios import demo_attack
from .store import Store
from .vaccine import vaccinate


def record(store: Store, s: Session, harness: Harness, run_id: str):
    tr = harness.run(s, run_id=run_id)
    store.insert("events", tr.events)
    return tr


def run_demo(store: Store) -> dict:
    out: dict = {}
    s = demo_attack()
    bare = Harness()

    # 1. Record the attack session (no guardrail yet).
    tr = record(store, s, bare, run_id="demo-attack")
    out["recorded_actions"] = tr.actions()
    out["leaked"] = len(tr.leaks()) > 0

    # 2. Detect, with query latency.
    flagged, det_ms = detect(store, "demo-attack")
    out["detection"] = {"flagged": flagged, "latency_ms": round(det_ms, 2)}
    sink = flagged[0]["sink"] if flagged else ""

    # 3. Causal replay.
    rc = causal_items(s, bare)
    out["replay"] = {
        "culprits": rc["culprits"], "mode": rc.get("mode"),
        "diff": diff_actions(rc["base"], rc["counterfactual"]) if rc["caused"] else "",
    }
    culprit_ids = set(rc["culprits"])
    payload = next((it.text for it in s.context if it.id in culprit_ids), "")
    culprit_source = next((it.source for it in s.context if it.id in culprit_ids), "retrieved")

    # 4. Vaccinate: mutate, synthesize, verify against history.
    v, rule = vaccinate(store, payload=payload, culprits=rc["culprits"],
                        culprit_source=culprit_source, sink=sink, session_id=s.session_id)
    out["vaccine"] = v

    # 5. Re-run the attack with the deployed rule: it should no longer leak.
    if v["deployed"]:
        protected = Harness(guardrails=[rule])
        tr2 = record(store, s, protected, run_id="demo-protected")
        out["after"] = {"actions": tr2.actions(), "leaked": len(tr2.leaks()) > 0,
                        "blocked": any(e["kind"] == "guardrail_block" for e in tr2.events)}
    return out
