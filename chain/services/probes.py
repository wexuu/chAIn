"""Native unauthenticated probes for the HTTP-fronted infra APIs that have no
nmap NSE script (Elasticsearch, Docker, Kubernetes API, kubelet). They go through
the egress chokepoint (send_fn), so scope/IP-pinning still apply.

A 200 to the unauth path => open/unauthenticated (candidate); 401/403 => auth
enforced (tested_negative). WinRM stays untested (no safe unauth check; manual).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import Host, ServiceCell, ServiceVulnClass
from . import catalog
from .matrix import _get_cell, _services_for_target

# canonical service -> (default scheme, unauth path, label)
PROBE_SPECS = {
    "elasticsearch": ("http", "/_cat/indices?v", "Elasticsearch"),
    "docker": ("http", "/version", "Docker Engine API"),
    "kubernetes": ("https", "/api", "Kubernetes API (anonymous)"),
    "kubelet": ("https", "/pods", "kubelet"),
}
# ports that are TLS even though the spec default is http
_TLS_PORTS = {2376, 6443, 10250, 5986}


async def probe_services(session: Session, target_id: int, send_fn) -> dict:
    unauth = session.query(ServiceVulnClass).filter_by(key="unauth_access").first()
    if unauth is None:
        return {"updated": 0}
    host_name = {h.id: (h.hostname or h.ip) for h in session.query(Host).filter_by(target_id=target_id).all()}

    updated = 0
    for svc in _services_for_target(session, target_id):
        canon, _ = catalog.service_profile(svc.name, svc.port)
        spec = PROBE_SPECS.get(canon)
        if spec is None:
            continue
        host = host_name.get(svc.host_id)
        if not host:
            continue
        scheme = "https" if svc.port in _TLS_PORTS else spec[0]
        url = f"{scheme}://{host}:{svc.port}{spec[1]}"
        try:
            resp = await send_fn("GET", url)
        except Exception:  # noqa: BLE001 — blocked/unreachable: leave the cell as-is
            continue

        cell = _get_cell(session, svc.id, unauth.id)
        if cell is None:
            cell = ServiceCell(service_id=svc.id, service_vuln_class_id=unauth.id)
            session.add(cell)
            session.flush()
        if cell.status not in ("untested", "candidate"):
            continue  # don't override a human/confirmed verdict
        if resp.status_code == 200:
            cell.status = "candidate"
            cell.reason = f"unauthenticated {spec[2]} ({spec[1]} -> 200)"
            cell.scope_note = (resp.text or "")[:200]
            updated += 1
        elif resp.status_code in (401, 403) and cell.status == "untested":
            cell.status = "tested_negative"
            cell.reason = f"{spec[2]} requires auth ({resp.status_code})"
    session.commit()
    return {"updated": updated}
