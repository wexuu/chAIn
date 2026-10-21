"""Human-gated subdomain approval.

Approving a discovered subdomain is the ONE sanctioned way the target set
expands: it creates a Host, adds an allow ScopeRule, and regenerates the
default-deny egress firewall allow-set. `found`/`excluded` subdomains are never
scanned and never enter the firewall.
"""

from __future__ import annotations

import json
from typing import Callable, Optional

from sqlalchemy.orm import Session

from ..firewall import apply_ruleset, generate_ruleset
from ..models import Host, ScopeRule, Subdomain
from .inventory import upsert_host


def regenerate_firewall(session: Session, target_id: int) -> dict:
    ips: set[str] = set()
    for h in session.query(Host).filter_by(target_id=target_id).all():
        if h.ip:
            ips.add(h.ip)
    for sub in session.query(Subdomain).filter_by(target_id=target_id, status="approved").all():
        if sub.resolved_ips_json:
            ips.update(json.loads(sub.resolved_ips_json))
    ruleset = generate_ruleset(sorted(ips))
    applied = apply_ruleset(ruleset)
    return {"allowed_ips": sorted(ips), "firewall": applied, "ruleset": ruleset}


def approve_subdomain(
    session: Session,
    sub_id: int,
    resolver: Optional[Callable[[str], list[str]]] = None,
) -> dict:
    sub = session.get(Subdomain, sub_id)
    if sub is None:
        raise ValueError("subdomain not found")
    sub.status = "approved"
    upsert_host(session, sub.target_id, hostname=sub.name)
    exists = (
        session.query(ScopeRule)
        .filter_by(target_id=sub.target_id, kind="host", value=sub.name, allow=True)
        .first()
    )
    if exists is None:
        session.add(ScopeRule(target_id=sub.target_id, kind="host", value=sub.name, allow=True))
    if resolver is not None and not sub.resolved_ips_json:
        try:
            ips = resolver(sub.name)
            if ips:
                sub.resolved_ips_json = json.dumps(sorted(set(ips)))
        except Exception:  # noqa: BLE001 — resolution failure shouldn't block approval
            pass
    session.commit()
    return regenerate_firewall(session, sub.target_id)


def exclude_subdomain(session: Session, sub_id: int) -> None:
    sub = session.get(Subdomain, sub_id)
    if sub is None:
        raise ValueError("subdomain not found")
    sub.status = "excluded"
    session.commit()
