"""Check dispatch + the egress-bound send function factory."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .. import egress
from ..models import AuthProfile, CoverageCell, Endpoint, Target, VulnClass
from . import native
from .base import CheckContext, DestructiveBlocked, apply_auth

# vuln-class key -> native check
CHECKS = {
    "method_tampering": native.method_tampering,
    "headers_cors": native.headers_cors,
    "xss": native.reflection,
    "authz_idor": native.authz_idor,
    "mass_assignment": native.mass_assignment,
}


def bind_send(policy, client, resolver=egress.default_resolver, rate_limiter=None, audit=None):
    """Build a send_fn that applies an auth profile and goes through the chokepoint."""

    async def send_fn(method, url, *, headers=None, content=None, profile=None):
        hdrs = dict(headers or {})
        apply_auth(hdrs, profile)
        return await egress.send(
            policy=policy,
            method=method,
            url=url,
            headers=hdrs,
            content=content,
            client=client,
            resolver=resolver,
            rate_limiter=rate_limiter,
            audit=audit,
        )

    return send_fn


async def run_check(
    session: Session,
    cell: CoverageCell,
    *,
    send_fn,
    auth_profiles: Optional[dict] = None,
    evidence_dir: Optional[str] = None,
) -> dict:
    vc = session.get(VulnClass, cell.vuln_class_id)
    endpoint = session.get(Endpoint, cell.endpoint_id)
    fn = CHECKS.get(vc.key) if vc else None
    if fn is None:
        return {"ran": False, "reason": f"no native check for '{vc.key if vc else '?'}'"}
    target = session.get(Target, endpoint.target_id)
    ctx = CheckContext(
        session=session,
        target=target,
        endpoint=endpoint,
        cell=cell,
        send=send_fn,
        auth_profiles=auth_profiles or {},
        destructive_allowed=bool(target.destructive_opt_in),
        evidence_dir=evidence_dir,
    )
    try:
        result = await fn(ctx)
    except DestructiveBlocked as exc:
        return {"ran": False, "skipped": True, "reason": str(exc)}
    if result.status is not None:
        cell.status = result.status
        cell.reason = result.reason
        if result.scope_note is not None:
            cell.scope_note = result.scope_note
            cell.tested_scope_derived = True
        session.commit()
    return {"ran": True, "status": result.status, "reason": result.reason}
