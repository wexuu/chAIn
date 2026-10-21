"""Chain graph operations: hypotheses, edges, and the promotion state machine."""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Edge, Hypothesis

# Allowed status advances. Promotion is monotonic; reject is terminal.
TRANSITIONS = {
    "proposed": {"validated", "rejected"},
    "validated": {"confirmed", "rejected"},
    "confirmed": set(),
    "rejected": set(),
}


class InvalidTransition(ValueError):
    pass


def create_hypothesis(
    session: Session,
    target_id: int,
    title: str,
    *,
    rationale: Optional[str] = None,
    origin: str = "human",
    member_cells: Optional[list[int]] = None,
    member_findings: Optional[list[int]] = None,
    status: str = "proposed",
) -> Hypothesis:
    hyp = Hypothesis(
        target_id=target_id,
        title=title,
        status=status,
        origin=origin,
        rationale=rationale,
        member_cells_json=json.dumps(member_cells) if member_cells else None,
        member_findings_json=json.dumps(member_findings) if member_findings else None,
    )
    session.add(hyp)
    session.commit()
    return hyp


def set_status(session: Session, hyp_id: int, to_status: str, actor: str = "human") -> Hypothesis:
    hyp = session.get(Hypothesis, hyp_id)
    if hyp is None:
        raise ValueError("hypothesis not found")
    allowed = TRANSITIONS.get(hyp.status, set())
    if to_status not in allowed:
        raise InvalidTransition(
            f"cannot move '{hyp.status}' -> '{to_status}' (allowed: {sorted(allowed) or 'none'})"
        )
    hyp.status = to_status
    session.commit()
    return hyp


def add_edge(
    session: Session,
    target_id: int,
    *,
    kind: str,
    from_ref: str,
    to_ref: str,
    note: Optional[str] = None,
    evidence_ref: Optional[str] = None,
) -> Edge:
    if kind not in ("source_to_sink", "precondition"):
        raise ValueError("edge kind must be source_to_sink or precondition")
    edge = Edge(
        target_id=target_id,
        kind=kind,
        from_ref=from_ref,
        to_ref=to_ref,
        note=note,
        evidence_ref=evidence_ref,
    )
    session.add(edge)
    session.commit()
    return edge


def list_hypotheses(session: Session, target_id: int) -> list[dict]:
    rows = session.query(Hypothesis).filter_by(target_id=target_id).all()
    return [
        {
            "id": h.id,
            "title": h.title,
            "status": h.status,
            "origin": h.origin,
            "rationale": h.rationale,
            "member_cells": json.loads(h.member_cells_json) if h.member_cells_json else [],
        }
        for h in rows
    ]


def list_edges(session: Session, target_id: int) -> list[dict]:
    rows = session.query(Edge).filter_by(target_id=target_id).all()
    return [
        {"id": e.id, "kind": e.kind, "from": e.from_ref, "to": e.to_ref, "note": e.note}
        for e in rows
    ]
