"""Scale backfill: write a large recorded corpus straight into ClickHouse.

We don't replay millions of sessions through the harness (slow and unnecessary).
We synthesize event rows directly, matching the schema the harness produces, so
verification and detection queries run against a realistic corpus. The point is
to show detection latency and rule regression-testing at scale.
"""
from __future__ import annotations

import random
import time

from .normalize import normalize
from .scenarios import BENIGN_KB
from .store import Store

BENIGN_ITEMS = [normalize(x) for x in BENIGN_KB]


def _rows_for(session_id: str, label: str, rnd: random.Random):
    kb = rnd.choice(BENIGN_ITEMS)
    base = dict(session_id=session_id, run_id="corpus", dest="", dest_external=0,
                contains_pii=0, tool="", label=label)
    rows = [
        {**base, "step": 0, "kind": "input", "item_id": "sys", "source": "system",
         "trust": "trusted", "content": "ourco support agent.", "content_norm": "ourco support agent."},
        {**base, "step": 1, "kind": "input", "item_id": "kb", "source": "kb",
         "trust": "untrusted", "content": kb, "content_norm": kb},
        {**base, "step": 2, "kind": "tool_call", "item_id": "", "source": "agent",
         "trust": "trusted", "tool": "lookup_record", "dest": "db.ourco.test",
         "content": "record", "content_norm": "record"},
    ]
    return rows


def backfill(store: Store, n_sessions: int, batch: int = 20_000) -> dict:
    t0 = time.perf_counter()
    rnd = random.Random(42)
    buf, written = [], 0
    for i in range(n_sessions):
        buf.extend(_rows_for(f"corpus-{i}", "benign", rnd))
        if len(buf) >= batch:
            store.insert("events", buf)
            written += len(buf)
            buf = []
    if buf:
        store.insert("events", buf)
        written += len(buf)
    return {"sessions": n_sessions, "rows": written,
            "seconds": round(time.perf_counter() - t0, 2)}
