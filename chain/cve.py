"""Service version -> CVE/exploit enrichment.

searchsploit is the offline backbone (local Exploit-DB, `-j` JSON, no key); vulnx
(cloud, free key/keyless) is an optional online enricher. Neither touches the
target (local DB / the VM's own internet), so no launch gate is needed. Tools
absent or offline => gracefully skipped.
"""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from .config import settings
from .models import Host, Service, ServiceCell, ServiceVulnClass


def _parse_searchsploit(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    out = []
    for r in data.get("RESULTS_EXPLOIT", []) or []:
        if isinstance(r, dict) and r.get("EDB-ID"):
            out.append({"id": f"edb:{r['EDB-ID']}", "title": r.get("Title", "")})
    return out


def _parse_vulnx(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else (data.get("results") or data.get("data") or [])
    out = []
    for it in items:
        if isinstance(it, dict):
            cid = it.get("cve_id") or it.get("id")
            if cid:
                out.append({"id": str(cid), "title": (it.get("summary") or it.get("description") or "")[:80]})
    return out


async def _run(runner, argv: list[str]) -> Optional[str]:
    try:
        return (await runner.run(argv, 120.0)).stdout
    except Exception:  # noqa: BLE001 — tool missing / offline => skip this source
        return None


async def lookup(runner, product: str, version: Optional[str]) -> list[dict]:
    terms = [t for t in (product, version) if t]
    refs: list[dict] = []
    out = await _run(runner, ["searchsploit", "--json", *terms])
    if out:
        refs += _parse_searchsploit(out)
    if settings.cve_online_enabled:
        vout = await _run(runner, ["vulnx", "--json", "-q", " ".join(terms)])
        if vout:
            refs += _parse_vulnx(vout)
    seen: dict[str, str] = {}
    for r in refs:
        seen.setdefault(r["id"], r["title"])
    return [{"id": k, "title": v} for k, v in seen.items()]


async def enrich_service_version_cves(session: Session, target_id: int, runner) -> dict:
    vc = session.query(ServiceVulnClass).filter_by(key="version_cve").first()
    if vc is None:
        return {"updated": 0}
    host_ids = [h.id for h in session.query(Host).filter_by(target_id=target_id).all()]
    if not host_ids:
        return {"updated": 0}
    updated = 0
    services = (
        session.query(Service)
        .filter(Service.host_id.in_(host_ids), Service.is_http == False)  # noqa: E712
        .all()
    )
    for svc in services:
        if not svc.product:
            continue
        cell = session.query(ServiceCell).filter_by(service_id=svc.id, service_vuln_class_id=vc.id).first()
        if cell is None:
            cell = ServiceCell(service_id=svc.id, service_vuln_class_id=vc.id)
            session.add(cell)
            session.flush()
        if cell.status != "untested":  # never override a human/confirmed verdict
            continue
        refs = await lookup(runner, svc.product, svc.version)
        if refs:
            cell.status = "candidate"
            cell.reason = "public exploits/CVEs: " + ", ".join(r["id"] for r in refs[:8])
        else:
            cell.status = "tested_negative"
            cell.reason = f"no public exploits found for {svc.product} {svc.version or ''}".strip()
        updated += 1
    session.commit()
    return {"updated": updated}
