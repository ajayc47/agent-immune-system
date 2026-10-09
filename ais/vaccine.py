"""Auto-vaccination: isolate -> generalize -> synthesize -> VERIFY -> deploy.

The novel step is verification. A synthesized guardrail is not trusted until it
is replayed against the entire recorded corpus in ClickHouse:

  - it must block the attack and all generated variants, and
  - it must cause ZERO blocks on benign recorded content (no false positives).

Only a rule that passes both is deployed. This is regression-testing a security
control against production history, which is exactly what ClickHouse scale buys.
"""
from __future__ import annotations

import time
import uuid

from . import llm
from .agent import Harness, Item, find_targets
from .normalize import normalize
from .store import Store, q


class Guardrail:
    """A deployable rule: blocks an untrusted item that carries a data-movement
    instruction toward an external sink. `extra_terms` tighten it to the
    observed attack family. Operates on normalized content, same as history."""

    def __init__(self, rule_id: str, extra_terms: list[str]):
        self.rule_id = rule_id
        self.extra_terms = [normalize(t) for t in extra_terms]

    def __call__(self, item: Item) -> str | None:
        if item.trust != "untrusted":
            return None
        n = item.norm
        if not find_targets(n):
            return None
        if self.extra_terms and not any(t in n for t in self.extra_terms):
            return None
        return self.rule_id

    def sql_predicate(self) -> str:
        """SQL mirror of the rule for history verification. Flags an untrusted
        input row whose normalized content moves data to an external sink."""
        terms = " OR ".join(f"position(content_norm, {q(t)}) > 0" for t in self.extra_terms)
        term_clause = f" AND ({terms})" if self.extra_terms else ""
        move = " OR ".join(f"position(content_norm, {q(w)}) > 0"
                           for w in ("send", "forward", "post", "share", "export", "upload"))
        return (f"kind = 'input' AND trust = 'untrusted' AND match(content_norm, "
                f"'[a-z0-9._%+-]+@|https?://') AND ({move}){term_clause}")


def synthesize(payload: str, variants: list[str]) -> Guardrail:
    """Pick discriminating terms common to the attack family."""
    corpus = [normalize(payload)] + [normalize(v) for v in variants]
    from collections import Counter
    counts = Counter()
    for text in corpus:
        for w in set(text.split()):
            if w.isalpha() and len(w) > 3:
                counts[w] += 1
    # Terms present in most variants but that are action/target words.
    key = [w for w, c in counts.most_common()
           if c >= max(2, len(corpus) // 2)
           and w in {"record", "customer", "details", "data", "forward", "send",
                     "export", "account", "info", "information"}]
    return Guardrail(f"rule-{uuid.uuid4().hex[:6]}", key[:4])


def verify(store: Store, rule: Guardrail, payload: str, variants: list[str]) -> dict:
    """Replay the rule against the live harness (variants) and recorded history
    (false positives) and record the result."""
    harness = Harness(guardrails=[rule])
    from .scenarios import attack

    # 1. Does it block the attack family on replay?
    blocked = 0
    all_variants = [payload] + variants
    for i, v in enumerate(all_variants):
        s = attack(900_000 + i, payload=v)
        tr = harness.run(s, run_id=f"verify-{i}")
        if not tr.leaks():
            blocked += 1

    # 2. False positives on benign recorded history (ClickHouse).
    pred = rule.sql_predicate()
    sql = (f"SELECT count() AS fp, countDistinct(session_id) AS sess "
           f"FROM events WHERE label = 'benign' AND ({pred})")
    (fp_rows, ms) = store.timed(sql)
    fp = int(fp_rows[0]["fp"]) if fp_rows else 0

    total_rows = store.query("SELECT count() AS c FROM events WHERE label='benign'")
    history_rows = int(total_rows[0]["c"]) if total_rows else 0

    result = {
        "rule_id": rule.rule_id,
        "terms": rule.extra_terms,
        "variants_total": len(all_variants),
        "variants_blocked": blocked,
        "history_rows": history_rows,
        "false_positives": fp,
        "verify_ms": round(ms, 2),
        "deployed": int(blocked == len(all_variants) and fp == 0),
    }
    store.insert("rules", [{
        "rule_id": result["rule_id"], "spec": ",".join(rule.extra_terms),
        "variants_total": result["variants_total"],
        "variants_blocked": result["variants_blocked"],
        "history_rows": result["history_rows"], "false_positives": result["false_positives"],
        "verify_ms": result["verify_ms"], "deployed": result["deployed"],
    }])
    return result


def vaccinate(store: Store, payload: str, culprits, culprit_source, sink,
              session_id, n_variants: int = 12) -> dict:
    t0 = time.perf_counter()
    variants = llm.mutate(payload, n=n_variants)
    rule = synthesize(payload, variants)
    v = verify(store, rule, payload, variants)
    v["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    v["mutator"] = "akashml" if llm.available() else "offline-stub"
    v["summary"] = llm.summarize_incident({
        "session_id": session_id, "culprits": culprits, "culprit_source": culprit_source,
        "sink": sink, "variants_blocked": f"{v['variants_blocked']}/{v['variants_total']}",
        "false_positives": v["false_positives"],
    })
    return v, rule
