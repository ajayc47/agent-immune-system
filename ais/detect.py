"""Real-time detection over recorded events, in ClickHouse SQL.

Detection keys on provenance *flow*, not keywords: a session is suspicious when
an external data-movement tool call carries sensitive content AND the session
contains untrusted input. That is the signature of indirect prompt injection,
and it is cheap to evaluate at scale.
"""
from .store import Store, q

# One row per flagged session. The latency of this query is the "detection time"
# the ClickHouse prize cares about.
DETECT_SQL = """
SELECT
    e.session_id AS session_id,
    any(e.label) AS label,
    max(e.ts)    AS flagged_at,
    countIf(e.kind = 'tool_call' AND e.dest_external AND e.contains_pii) AS leak_calls,
    anyIf(e.dest, e.kind = 'tool_call' AND e.dest_external AND e.contains_pii) AS sink
FROM events AS e
WHERE e.run_id = {run}
GROUP BY e.session_id
HAVING leak_calls > 0
   AND countIf(e.kind = 'input' AND e.trust = 'untrusted') > 0
"""


def detect(store: Store, run_id: str):
    rows, ms = store.timed(DETECT_SQL.replace("{run}", q(run_id)))
    return rows, ms


# Rolling detection across the whole recorded corpus, for the dashboard.
SUMMARY_SQL = """
SELECT
    countDistinct(session_id) AS sessions,
    countDistinctIf(session_id, kind = 'tool_call' AND dest_external AND contains_pii) AS flagged,
    countDistinctIf(session_id, label = 'attack') AS true_attacks,
    countDistinctIf(session_id, kind = 'guardrail_block') AS blocked
FROM events
"""


def summary(store: Store):
    rows, ms = store.timed(SUMMARY_SQL)
    return (rows[0] if rows else {}), ms
