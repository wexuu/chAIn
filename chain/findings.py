"""Promote a confirmed cell or confirmed hypothesis into a prefilled Finding.

Explicit, human-triggered (augment-don't-replace): it fills class, affected
endpoints, evidence refs, and a suggested CVSS vector per class; the operator
edits before it goes in the report. Score is always derived from the vector.
"""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from . import cvss
from .models import Attempt, CoverageCell, Endpoint, Finding, Hypothesis, VulnClass

DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # Medium-ish starting point

# Starting-point vectors per class; the human adjusts to the actual impact.
SUGGESTED_CVSS = {
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "authz_idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "business_logic": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "method_tampering": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "headers_cors": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "rate_limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
}


def _suggested(vc_key: Optional[str]) -> str:
    return SUGGESTED_CVSS.get(vc_key or "", DEFAULT_VECTOR)


def _cell_evidence(session: Session, cell_id: int) -> list[str]:
    return [
        a.evidence_ref
        for a in session.query(Attempt).filter_by(cell_id=cell_id).all()
        if a.evidence_ref
    ]


def promote_cell(session: Session, cell_id: int) -> Finding:
    cell = session.get(CoverageCell, cell_id)
    if cell is None:
        raise ValueError("cell not found")
    if cell.status != "confirmed":
        raise ValueError("only a confirmed cell can be promoted to a finding")
    vc = session.get(VulnClass, cell.vuln_class_id)
    ep = session.get(Endpoint, cell.endpoint_id)
    vector = _suggested(vc.key if vc else None)
    score, sev = cvss.base_score(vector)
    title = f"{vc.label if vc else 'Finding'} on {ep.method} {ep.path}"
    if cell.param_name:
        title += f" (param {cell.param_name})"
    finding = Finding(
        target_id=ep.target_id,
        title=title,
        vuln_class_id=cell.vuln_class_id,
        cvss_vector=vector,
        cvss_score=score,
        severity=sev,
        endpoints_json=json.dumps([f"{ep.method} {ep.path}"]),
        evidence_refs_json=json.dumps(_cell_evidence(session, cell_id)),
        status="open",
    )
    session.add(finding)
    session.commit()
    return finding


def promote_hypothesis(session: Session, hyp_id: int) -> Finding:
    h = session.get(Hypothesis, hyp_id)
    if h is None:
        raise ValueError("hypothesis not found")
    if h.status != "confirmed":
        raise ValueError("only a confirmed hypothesis can be promoted to a finding")
    member_cells = json.loads(h.member_cells_json) if h.member_cells_json else []
    endpoints: list[str] = []
    evidence: list[str] = []
    for cid in member_cells:
        c = session.get(CoverageCell, cid)
        if c is None:
            continue
        ep = session.get(Endpoint, c.endpoint_id)
        if ep:
            endpoints.append(f"{ep.method} {ep.path}")
        evidence += _cell_evidence(session, cid)
    score, sev = cvss.base_score(DEFAULT_VECTOR)
    finding = Finding(
        target_id=h.target_id,
        title=h.title,
        cvss_vector=DEFAULT_VECTOR,
        cvss_score=score,
        severity=sev,
        endpoints_json=json.dumps(sorted(set(endpoints))),
        evidence_refs_json=json.dumps(evidence),
        status="open",
    )
    session.add(finding)
    session.commit()
    return finding
