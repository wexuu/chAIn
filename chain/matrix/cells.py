"""Cell generation, reason-bearing status edits, and matrix assembly."""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from ..models import CoverageCell, Endpoint, VulnClass

STATUSES = {"untested", "candidate", "confirmed", "tested_negative", "not_applicable", "reviewed"}
# A non-untested verdict must justify itself.
REASON_REQUIRED = {"tested_negative", "not_applicable", "reviewed"}


class InvalidStatus(ValueError):
    pass


class ReasonRequired(ValueError):
    pass


def _endpoint_params(ep: Endpoint) -> list[str]:
    params = json.loads(ep.params_json) if ep.params_json else []
    body = json.loads(ep.body_fields_json) if ep.body_fields_json else []
    out = []
    for p in list(params) + list(body):
        if p not in out:
            out.append(p)
    return out


def _get_cell(session: Session, endpoint_id: int, vc_id: int, param_name: Optional[str]):
    return (
        session.query(CoverageCell)
        .filter_by(endpoint_id=endpoint_id, vuln_class_id=vc_id, param_name=param_name)
        .first()
    )


def generate_cells(session: Session, target_id: int) -> int:
    """Create missing cells for every endpoint × vuln class. Never overwrites an
    existing (possibly hand-edited) cell. Returns the number of cells created."""
    classes = session.query(VulnClass).all()
    endpoints = session.query(Endpoint).filter_by(target_id=target_id).all()
    created = 0
    for ep in endpoints:
        params = _endpoint_params(ep)
        for vc in classes:
            if vc.param_specific:
                if params:
                    for p in params:
                        if _get_cell(session, ep.id, vc.id, p) is None:
                            session.add(
                                CoverageCell(endpoint_id=ep.id, vuln_class_id=vc.id, param_name=p)
                            )
                            created += 1
                else:
                    if _get_cell(session, ep.id, vc.id, None) is None:
                        session.add(
                            CoverageCell(
                                endpoint_id=ep.id,
                                vuln_class_id=vc.id,
                                param_name=None,
                                status="not_applicable",
                                reason="no parameters on this endpoint",
                            )
                        )
                        created += 1
            else:
                if _get_cell(session, ep.id, vc.id, None) is None:
                    session.add(
                        CoverageCell(endpoint_id=ep.id, vuln_class_id=vc.id, param_name=None)
                    )
                    created += 1
    session.commit()
    return created


def set_status(
    session: Session,
    cell_id: int,
    status: str,
    reason: Optional[str] = None,
    scope_note: Optional[str] = None,
) -> CoverageCell:
    if status not in STATUSES:
        raise InvalidStatus(f"status must be one of {sorted(STATUSES)}")
    if status in REASON_REQUIRED and not (reason and reason.strip()):
        raise ReasonRequired(f"status '{status}' requires a reason")
    cell = session.get(CoverageCell, cell_id)
    if cell is None:
        raise ValueError("cell not found")
    cell.status = status
    cell.reason = reason
    if scope_note is not None:
        cell.scope_note = scope_note
    session.commit()
    return cell


def get_matrix(session: Session, target_id: int) -> dict:
    classes = {vc.id: vc for vc in session.query(VulnClass).all()}
    endpoints = session.query(Endpoint).filter_by(target_id=target_id).all()
    ep_ids = [e.id for e in endpoints]
    cells = (
        session.query(CoverageCell).filter(CoverageCell.endpoint_id.in_(ep_ids)).all()
        if ep_ids
        else []
    )

    by_ep: dict[int, list] = {e.id: [] for e in endpoints}
    by_status: dict[str, int] = {s: 0 for s in STATUSES}
    for c in cells:
        vc = classes.get(c.vuln_class_id)
        by_ep[c.endpoint_id].append(
            {
                "id": c.id,
                "vuln_class": vc.key if vc else None,
                "param_name": c.param_name,
                "status": c.status,
                "reason": c.reason,
                "scope_note": c.scope_note,
            }
        )
        by_status[c.status] = by_status.get(c.status, 0) + 1

    applicable = sum(v for k, v in by_status.items() if k != "not_applicable")
    covered = sum(v for k, v in by_status.items() if k not in ("untested", "not_applicable"))
    coverage_pct = round(100 * covered / applicable, 1) if applicable else 0.0

    return {
        "columns": [
            {
                "key": vc.key,
                "label": vc.label,
                "wstg": json.loads(vc.wstg_ids_json) if vc.wstg_ids_json else [],
                "param_specific": vc.param_specific,
            }
            for vc in classes.values()
        ],
        "endpoints": [
            {"id": e.id, "method": e.method, "path": e.path, "cells": by_ep[e.id]}
            for e in endpoints
        ],
        "summary": {
            "total_cells": len(cells),
            "by_status": by_status,
            "applicable": applicable,
            "covered": covered,
            "coverage_pct": coverage_pct,
        },
    }
