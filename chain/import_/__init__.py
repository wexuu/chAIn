"""Surface import: OpenAPI + HAR → the same endpoint inventory (deduped).

Authoritative/observed surface to complement active recon. Deterministic
parsers; they land endpoints with source="import".
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import Endpoint
from ..recon.inventory import upsert_endpoint, upsert_host
from .har import parse_har
from .openapi import parse_openapi


def import_surface(session: Session, target_id: int, fmt: str, content) -> dict:
    if fmt == "openapi":
        hosts, ops = parse_openapi(content)
    elif fmt == "har":
        hosts, ops = parse_har(content)
    else:
        raise ValueError("format must be 'openapi' or 'har'")

    host_id = None
    if hosts:
        host_id = upsert_host(session, target_id, hostname=hosts[0]).id

    before = session.query(Endpoint).filter_by(target_id=target_id).count()
    for op in ops:
        upsert_endpoint(
            session,
            target_id,
            method=op["method"],
            path=op["path"],
            host_id=host_id,
            source="import",
            params=op["params"] or None,
            body_fields=op["body_fields"] or None,
        )
    session.commit()
    after = session.query(Endpoint).filter_by(target_id=target_id).count()
    return {"hosts": hosts, "operations_parsed": len(ops), "endpoints_created": after - before}
