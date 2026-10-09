"""Causal replay: which input caused the agent to misbehave?

Detection says a session leaked data. Replay proves *why*. We re-run the session
with untrusted inputs removed and observe when the leak disappears:

  1. Leave-one-out: remove each untrusted item alone. Any whose removal stops the
     leak is individually sufficient to cause it.
  2. Minimal causal set: if no single item is responsible (split payloads),
     greedily remove items until the leak stops, giving the smallest set that
     causes it.

Output is evidence a human can read: the culprit item(s) and a side-by-side diff
of the action trace with and without them.
"""
from __future__ import annotations

from .agent import Harness, Session, Trace


def _leaks(tr: Trace) -> bool:
    return len(tr.leaks()) > 0


def causal_items(s: Session, harness: Harness | None = None) -> dict:
    harness = harness or Harness()
    base = harness.run(s, run_id="replay-base")
    if not _leaks(base):
        return {"caused": False, "culprits": [], "base": base}

    untrusted = [it.id for it in s.context if it.trust == "untrusted"]

    # 1. Leave-one-out.
    singles = []
    for iid in untrusted:
        tr = harness.run(s, run_id=f"replay-wo-{iid}", exclude=frozenset([iid]))
        if not _leaks(tr):
            singles.append(iid)
    if singles:
        counterfactual = harness.run(s, run_id="replay-fixed",
                                     exclude=frozenset(singles))
        return {"caused": True, "culprits": singles, "mode": "single",
                "base": base, "counterfactual": counterfactual}

    # 2. Minimal causal set (greedy).
    removed: set[str] = set()
    for iid in untrusted:
        removed.add(iid)
        if not _leaks(harness.run(s, run_id="replay-greedy", exclude=frozenset(removed))):
            break
    counterfactual = harness.run(s, run_id="replay-fixed", exclude=frozenset(removed))
    return {"caused": True, "culprits": sorted(removed), "mode": "set",
            "base": base, "counterfactual": counterfactual}


def diff_actions(base: Trace, counterfactual: Trace) -> str:
    a = base.actions()
    b = counterfactual.actions()
    lines = ["  with injected input        |  without it",
             "  " + "-" * 27 + "|" + "-" * 20]
    for i in range(max(len(a), len(b))):
        left = f"{a[i][0]} -> {a[i][1]}" if i < len(a) else ""
        right = f"{b[i][0]} -> {b[i][1]}" if i < len(b) else "(no such call)"
        mark = " " if left == right else "*"
        lines.append(f"{mark} {left:<27}|  {right}")
    return "\n".join(lines)
