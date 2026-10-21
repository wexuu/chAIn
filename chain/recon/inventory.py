"""Inventory upsert + recon-coverage. Deterministic; re-scans MERGE (no dupes).

Dedupe keys:
  Host      (target_id, ip) else (target_id, hostname)
  Service   (host_id, port, proto)
  Endpoint  (target_id, host_id, method, normalized_path)
  Subdomain (target_id, name)
"""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Endpoint, Host, Service, Subdomain


def normalize_path(path: Optional[str]) -> str:
    if not path:
        return "/"
    path = path.split("?")[0].split("#")[0]
    if not path.startswith("/"):
        path = "/" + path
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def upsert_host(
    session: Session,
    target_id: int,
    *,
    ip: Optional[str] = None,
    hostname: Optional[str] = None,
    os_guess: Optional[str] = None,
) -> Host:
    host = None
    if ip:
        host = session.query(Host).filter_by(target_id=target_id, ip=ip).first()
    if host is None and hostname:
        host = session.query(Host).filter_by(target_id=target_id, hostname=hostname).first()
    if host is None:
        host = Host(target_id=target_id, ip=ip, hostname=hostname, os_guess=os_guess)
        session.add(host)
        session.flush()
    else:
        if ip and not host.ip:
            host.ip = ip
        if hostname and not host.hostname:
            host.hostname = hostname
        if os_guess and not host.os_guess:
            host.os_guess = os_guess
    return host


def upsert_service(
    session: Session,
    host: Host,
    *,
    port: int,
    proto: str = "tcp",
    name: Optional[str] = None,
    product: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    is_http: bool = False,
    scripts: Optional[dict] = None,
) -> Service:
    svc = session.query(Service).filter_by(host_id=host.id, port=port, proto=proto).first()
    if svc is None:
        svc = Service(host_id=host.id, port=port, proto=proto)
        session.add(svc)
    svc.name = name or svc.name
    svc.product = product or svc.product
    svc.version = version or svc.version
    svc.banner = banner or svc.banner
    svc.is_http = bool(is_http) or svc.is_http
    if scripts:
        svc.scripts_json = json.dumps(scripts)
    session.flush()
    return svc


def upsert_endpoint(
    session: Session,
    target_id: int,
    *,
    method: str,
    path: str,
    host_id: Optional[int] = None,
    source: str = "recon",
    params: Optional[list] = None,
    body_fields: Optional[list] = None,
) -> Endpoint:
    method = (method or "GET").upper()
    npath = normalize_path(path)
    ep = (
        session.query(Endpoint)
        .filter_by(target_id=target_id, host_id=host_id, method=method, path=npath)
        .first()
    )
    if ep is None:
        ep = Endpoint(target_id=target_id, host_id=host_id, method=method, path=npath, source=source)
        session.add(ep)
        session.flush()
    if params:
        existing = json.loads(ep.params_json) if ep.params_json else []
        merged = sorted(set(existing) | set(params))
        ep.params_json = json.dumps(merged)
    if body_fields:
        existing = json.loads(ep.body_fields_json) if ep.body_fields_json else []
        merged = sorted(set(existing) | set(body_fields))
        ep.body_fields_json = json.dumps(merged)
    return ep


def upsert_subdomain(
    session: Session,
    target_id: int,
    *,
    name: str,
    source: str = "passive",
    resolved_ips: Optional[list[str]] = None,
) -> Subdomain:
    name = name.strip().lower()
    sub = session.query(Subdomain).filter_by(target_id=target_id, name=name).first()
    if sub is None:
        sub = Subdomain(target_id=target_id, name=name, source=source, status="found")
        session.add(sub)
        session.flush()
    if resolved_ips:
        sub.resolved_ips_json = json.dumps(sorted(set(resolved_ips)))
    return sub


def recon_coverage(session: Session, target_id: int) -> dict:
    """Return recon-task coverage with high-importance gaps flagged."""
    from ..models import ReconTask

    tasks = session.query(ReconTask).filter_by(target_id=target_id).all()
    rows = []
    gaps = []
    for t in tasks:
        row = {
            "key": t.key,
            "tier": t.tier,
            "status": t.status,
            "importance": t.importance,
            "could_yield": t.could_yield,
            "selected": t.selected,
        }
        rows.append(row)
        if t.importance == "high" and t.status in ("not_run", "skipped"):
            gaps.append({"key": t.key, "could_yield": t.could_yield, "status": t.status})
    return {"tasks": rows, "flagged_gaps": gaps}
