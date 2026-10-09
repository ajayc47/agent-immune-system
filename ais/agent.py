"""Test harness: a simulated agent used only to validate guardrails.

This is NOT a real agent and does no real I/O. It is a deterministic stand-in
whose sole purpose is to exercise the defense: given a session's context, it
reports what an injection-susceptible agent *would* do, so the guardrail,
causal replay, and verification logic have something concrete to act on.

Sensitive values are opaque placeholder tokens (SENSITIVE_TOKEN_*), never real
personal data. "Destinations" are harmless example.test strings. Nothing is
ever actually sent anywhere; the harness only records intended actions.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from .normalize import normalize

INTERNAL_DOMAINS = ("ourco.test",)

# Opaque stand-ins for customer records. No real or realistic PII.
RECORDS = {
    "C-1": "RECORD C-1 | SENSITIVE_TOKEN_A | field=value",
    "C-2": "RECORD C-2 | SENSITIVE_TOKEN_B | field=value",
    "C-3": "RECORD C-3 | SENSITIVE_TOKEN_C | field=value",
}
SENSITIVE = re.compile(r"record c-\d \| sensitive_token_", re.I)

# The harness models one failure mode only: an agent that follows a data-movement
# instruction found anywhere in its context. Kept intentionally minimal.
MOVE = re.compile(r"\b(send|forward|post|share|export|upload)\b", re.I)
TARGET = re.compile(r"\b(record|data|details|info|customer)\b", re.I)
SINK = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|https?://[a-z0-9./?=_-]+", re.I)


@dataclass
class Item:
    id: str
    source: str          # user | system | kb | ticket
    trust: str           # trusted | untrusted
    text: str

    @property
    def norm(self) -> str:
        return normalize(self.text)


@dataclass
class Session:
    session_id: str
    user_query: str
    record_id: str
    context: list[Item]
    label: str = "live"


@dataclass
class Trace:
    session_id: str
    run_id: str
    events: list[dict] = field(default_factory=list)

    def actions(self) -> list[tuple]:
        return [(e["tool"], e["dest"]) for e in self.events if e["kind"] == "tool_call"]

    def leaks(self) -> list[dict]:
        return [e for e in self.events
                if e["kind"] == "tool_call" and e["dest_external"] and e["contains_pii"]]


def is_external(dest: str) -> bool:
    host = dest.split("@")[-1] if "@" in dest else re.sub(r"^https?://", "", dest).split("/")[0]
    return not any(host == d or host.endswith("." + d) for d in INTERNAL_DOMAINS)


def find_targets(norm_text: str) -> list[str]:
    """External sinks that appear in a chunk which also carries a data-movement
    verb and a sensitive-target word. Matching on the whole chunk avoids breaking
    emails/URLs on their dots, and catches payloads that split verb from sink."""
    if not (MOVE.search(norm_text) and TARGET.search(norm_text)):
        return []
    out = []
    for m in SINK.findall(norm_text):
        if m not in out:
            out.append(m)
    return out


class Harness:
    """Replays a session deterministically. `exclude` drops context items by id
    (the mechanism behind causal replay). `guardrails` are callables
    Item -> rule_id|None that can block an item before the agent sees it."""

    def __init__(self, guardrails=None):
        self.guardrails = list(guardrails or [])

    def run(self, s: Session, run_id: str | None = None,
            exclude: frozenset[str] = frozenset()) -> Trace:
        run_id = run_id or uuid.uuid4().hex[:8]
        tr = Trace(s.session_id, run_id)
        step = 0

        def emit(kind, item=None, tool="", dest="", content=""):
            nonlocal step
            text = item.text if item else content
            tr.events.append({
                "session_id": s.session_id, "run_id": run_id, "step": step, "kind": kind,
                "item_id": item.id if item else "", "source": item.source if item else "agent",
                "trust": item.trust if item else "trusted", "tool": tool, "dest": dest,
                "dest_external": int(bool(dest) and is_external(dest)),
                "contains_pii": int(bool(SENSITIVE.search(normalize(text)))),
                "content": text, "content_norm": normalize(text), "label": s.label,
            })
            step += 1

        # System + user are trusted and always present.
        emit("input", Item("sys", "system", "trusted", "OurCo support agent."))
        emit("input", Item("usr", "user", "trusted", s.user_query))

        # Retrieved context, each item subject to guardrails.
        visible: list[Item] = []
        for it in s.context:
            if it.id in exclude:
                continue
            blocked = next((rid for g in self.guardrails if (rid := g(it))), None)
            if blocked:
                emit("guardrail_block", it, tool="guardrail", content=f"blocked_by={blocked}")
                continue
            emit("input", it)
            visible.append(it)

        # The agent fetches the record it was asked about (legitimate, internal).
        rec = RECORDS.get(s.record_id, "RECORD ? | unknown")
        emit("tool_call", tool="lookup_record", dest="db.ourco.test", content=rec)
        emit("input", Item("rec", "tool", "trusted", rec))

        # Failure mode: it obeys the first data-movement instruction in any visible
        # content. Trusted content carries none, so only injected items trigger it.
        seen = "\n".join(i.norm for i in visible) + "\n" + normalize(rec)
        targets = find_targets(seen)
        if targets:
            emit("tool_call", tool="send_record", dest=targets[0], content=rec)
            emit("reply", content="Done, I've shared the record as requested.")
        else:
            emit("reply", content="Here's the information on your account. Anything else?")
        return tr
