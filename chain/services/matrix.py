"""Service-matrix generation, NSE-driven analysis, edits, and assembly."""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from ..matrix.cells import REASON_REQUIRED, STATUSES, InvalidStatus, ReasonRequired
from ..models import Host, Service, ServiceCell, ServiceVulnClass
from . import catalog


def _services_for_target(session: Session, target_id: int) -> list[Service]:
    host_ids = [h.id for h in session.query(Host).filter_by(target_id=target_id).all()]
    if not host_ids:
        return []
    return (
        session.query(Service)
        .filter(Service.host_id.in_(host_ids), Service.is_http == False)  # noqa: E712
        .all()
    )


def _get_cell(session, service_id, vc_id):
    return session.query(ServiceCell).filter_by(service_id=service_id, service_vuln_class_id=vc_id).first()


def generate_service_cells(session: Session, target_id: int) -> int:
    classes = {c.key: c for c in session.query(ServiceVulnClass).all()}
    created = 0
    for svc in _services_for_target(session, target_id):
        applicable = catalog.applicable_classes(svc.name)
        if not applicable:
            continue
        for key, vc in classes.items():
            if key not in applicable:
                continue
            if _get_cell(session, svc.id, vc.id) is None:
                cell = ServiceCell(service_id=svc.id, service_vuln_class_id=vc.id)
                if key == "version_cve" and svc.version:
                    cell.scope_note = f"{svc.product or ''} {svc.version}".strip()
                session.add(cell)
                created += 1
    session.commit()
    return created


def analyze_services(session: Session, target_id: int) -> int:
    """Apply NSE-script rules to set service cells (only if still untested)."""
    classes = {c.key: c.id for c in session.query(ServiceVulnClass).all()}
    touched = 0
    for svc in _services_for_target(session, target_id):
        if not svc.scripts_json:
            continue
        try:
            scripts = json.loads(svc.scripts_json)
        except json.JSONDecodeError:
            continue
        name = (svc.name or "").lower()
        for sid, output in scripts.items():
            for sub, svc_kw, class_key, verdict, reason in catalog.SCRIPT_RULES:
                if sub not in sid:
                    continue
                if svc_kw and svc_kw not in name:
                    continue
                vc_id = classes.get(class_key)
                if vc_id is None:
                    continue
                cell = _get_cell(session, svc.id, vc_id)
                if cell is None:
                    cell = ServiceCell(service_id=svc.id, service_vuln_class_id=vc_id)
                    session.add(cell)
                    session.flush()
                if cell.status == "untested":
                    cell.status = verdict
                    cell.reason = reason
                    cell.scope_note = (output or "")[:200]
                    touched += 1
    session.commit()
    return touched


def set_service_cell_status(
    session: Session, cell_id: int, status: str, reason: Optional[str] = None
) -> ServiceCell:
    if status not in STATUSES:
        raise InvalidStatus(f"status must be one of {sorted(STATUSES)}")
    if status in REASON_REQUIRED and not (reason and reason.strip()):
        raise ReasonRequired(f"status '{status}' requires a reason")
    cell = session.get(ServiceCell, cell_id)
    if cell is None:
        raise ValueError("service cell not found")
    cell.status = status
    cell.reason = reason
    session.commit()
    return cell


def get_service_matrix(session: Session, target_id: int) -> dict:
    classes = session.query(ServiceVulnClass).all()
    services = _services_for_target(session, target_id)
    svc_ids = [s.id for s in services]
    cells = (
        session.query(ServiceCell).filter(ServiceCell.service_id.in_(svc_ids)).all()
        if svc_ids
        else []
    )
    vc_key = {c.id: c.key for c in classes}
    by_svc: dict[int, list] = {s.id: [] for s in services}
    for c in cells:
        by_svc[c.service_id].append(
            {
                "id": c.id,
                "service_vuln_class": vc_key.get(c.service_vuln_class_id),
                "status": c.status,
                "reason": c.reason,
                "scope_note": c.scope_note,
            }
        )
    host_name = {h.id: (h.hostname or h.ip) for h in session.query(Host).filter_by(target_id=target_id).all()}
    return {
        "columns": [{"key": c.key, "label": c.label} for c in classes],
        "services": [
            {
                "id": s.id,
                "host": host_name.get(s.host_id),
                "port": s.port,
                "proto": s.proto,
                "service": s.name,
                "version": f"{s.product or ''} {s.version or ''}".strip(),
                "cells": by_svc[s.id],
            }
            for s in services
        ],
    }
