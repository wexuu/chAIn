"""FastAPI app skeleton — bound to localhost, reached via SSH tunnel.

Phase 0 surface: health + Target / ScopeRule / authorization-ack management,
each audited. Recon, matrix, checks, chains, MCP, and export arrive in later
phases. The egress chokepoint (egress.py) is wired into request-sending code in
Phase 3; it already exists and is tested.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel

from . import audit, cve, cvss, db, export, findings, jobq, ops
from .chains import graph as chains_graph
from .import_ import import_surface
from .checks import jobs as check_jobs
from .checks import runner as checks_runner
from .config import settings
from .matrix import cells as matrix_cells
from .matrix.vulnclasses import seed_vuln_classes
from .models import (
    AuthProfile,
    CoverageCell,
    Endpoint,
    Finding,
    Host,
    ScopeRule,
    Subdomain,
    Target,
    VulnClass,
)
from .ratelimit import RateLimiter
from .recon import inventory, subdomains, worker
from .scope import policy_from_rules
from .sequences import runner as seq_runner
from .services import matrix as service_matrix
from .services.catalog import seed_service_classes


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.ensure()
    s = db.session()
    try:
        worker.recover_stale(s)  # fail any recon jobs/tasks left running by a crash
        check_jobs.recover_stale_checks(s)  # same for wrapped-check jobs
        seed_vuln_classes(s)  # idempotent web-matrix column seed
        seed_service_classes(s)  # idempotent service-matrix column seed
        ops.reap_evidence(s)  # drop evidence past its retention window
    finally:
        s.close()
    jobq.start()  # background worker that drains queued recon/check jobs
    yield
    await jobq.stop()


app = FastAPI(title="chAIn", version="0.0.1", lifespan=lifespan)


@app.middleware("http")
async def _optional_token_auth(request, call_next):
    """If CHAIN_UI_TOKEN is set, require it (header or ?token=); else open (default)."""
    from fastapi.responses import JSONResponse

    token = settings.ui_auth_token
    if token and request.url.path != "/health":
        supplied = request.headers.get("x-chain-token") or request.query_params.get("token")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = supplied or auth[7:]
        if supplied != token:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


class TargetIn(BaseModel):
    name: str
    address: str | None = None


class AddressIn(BaseModel):
    address: str


class ScopeRuleIn(BaseModel):
    kind: str  # host | cidr | url_prefix
    value: str
    allow: bool = True


class EndpointIn(BaseModel):
    method: str = "GET"
    path: str  # a path or a full URL; query string is parsed out by the caller
    params: list[str] | None = None  # query-param NAMES (not values)
    body_fields: list[str] | None = None  # body field NAMES (e.g. JSON keys)
    host_id: int | None = None
    notes: str | None = None


class AuthorizeIn(BaseModel):
    note: str


@app.get("/")
def index():
    return RedirectResponse(url="/app/")


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/preflight")
def preflight():
    return ops.tool_preflight()


@app.get("/recon/catalog")
def recon_catalog():
    """Static catalog of recon tasks, for the Recon checklist UI."""
    from .recon.catalog import CATALOG

    return [
        {
            "key": s.key,
            "label": s.label,
            "tier": s.tier,
            "importance": s.importance,
            "could_yield": s.could_yield,
            "tool": s.tool,
            "default_selected": s.default_selected,
        }
        for s in CATALOG.values()
    ]


# Serve the built React SPA at /app when present (built by `npm run build` in web/);
# the no-build static page at / is always the fallback.
_SPA_DIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "dist")
if os.path.isdir(_SPA_DIST):
    from fastapi.staticfiles import StaticFiles

    app.mount("/app", StaticFiles(directory=_SPA_DIST, html=True), name="spa")


@app.get("/targets/list")
def list_targets(archived: bool = False):
    s = db.session()
    try:
        return [
            {
                "id": t.id,
                "name": t.name,
                "address": t.address,
                "authorized": t.authorized,
                "archived": t.archived,
                "destructive_opt_in": t.destructive_opt_in,
            }
            for t in s.query(Target)
            .filter(Target.archived == archived)
            .order_by(Target.id)
            .all()
        ]
    finally:
        s.close()


def _autoscope(s, target_id: int, address: str) -> None:
    """Add the allow-rules that make `address` scannable and reachable.

    A host rule makes the recon launch gate pass (it checks the host string with
    ip=None); for an IP we also add a /32 (or /128) allow-cidr so the egress
    default-block set is overridden at request time (e.g. HTB's 10.10.x).
    """
    import ipaddress

    address = (address or "").strip()
    if not address:
        return
    existing = {(r.kind, r.value) for r in s.query(ScopeRule).filter_by(target_id=target_id).all()}
    wanted: list[tuple[str, str]] = []
    if "/" in address:  # CIDR
        wanted += [("cidr", address), ("host", address)]
    else:
        try:
            ip = ipaddress.ip_address(address)
            wanted += [("host", address), ("cidr", f"{address}/{32 if ip.version == 4 else 128}")]
        except ValueError:  # hostname
            wanted.append(("host", address))
    for kind, value in wanted:
        if (kind, value) not in existing:
            s.add(ScopeRule(target_id=target_id, kind=kind, value=value, allow=True))


@app.post("/targets", status_code=201)
def create_target(body: TargetIn):
    s = db.session()
    try:
        t = Target(
            name=body.name,
            address=(body.address or None),
            rate_limit_rps=settings.default_rate_rps,
            max_concurrency=settings.default_concurrency,
        )
        s.add(t)
        try:
            s.commit()
        except Exception:
            s.rollback()
            raise HTTPException(status_code=409, detail="target name already exists")
        if t.address:
            _autoscope(s, t.id, t.address)
            s.commit()
        audit.record(s, action="target.create", target_id=t.id, ref=t.name)
        return {"id": t.id, "name": t.name, "address": t.address, "authorized": t.authorized}
    finally:
        s.close()


@app.post("/targets/{target_id}/archive")
def archive_target(target_id: int):
    return _set_archived(target_id, True)


@app.post("/targets/{target_id}/restore")
def restore_target(target_id: int):
    return _set_archived(target_id, False)


def _set_archived(target_id: int, archived: bool):
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        t.archived = archived
        s.commit()
        audit.record(s, action="target.archive" if archived else "target.restore", target_id=t.id)
        return {"id": t.id, "name": t.name, "archived": t.archived}
    finally:
        s.close()


@app.delete("/targets/{target_id}")
def delete_target(target_id: int):
    """Permanently delete a target and everything scoped to it."""
    from .models import (
        Attempt,
        AuthProfile,
        CheckJob,
        CheckTask,
        CoverageCell,
        Edge,
        Endpoint,
        Evidence,
        Finding,
        Host,
        Hypothesis,
        ReconJob,
        ReconTask,
        Request,
        ScopeRule,
        SequenceRun,
        Service,
        ServiceCell,
        StepSequence,
        Subdomain,
    )

    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        host_ids = [r[0] for r in s.query(Host.id).filter_by(target_id=target_id)]
        ep_ids = [r[0] for r in s.query(Endpoint.id).filter_by(target_id=target_id)]
        svc_ids = (
            [r[0] for r in s.query(Service.id).filter(Service.host_id.in_(host_ids))]
            if host_ids
            else []
        )
        cell_ids = (
            [r[0] for r in s.query(CoverageCell.id).filter(CoverageCell.endpoint_id.in_(ep_ids))]
            if ep_ids
            else []
        )

        def wipe(q):
            q.delete(synchronize_session=False)

        if cell_ids:
            wipe(s.query(Attempt).filter(Attempt.cell_id.in_(cell_ids)))
            wipe(s.query(CoverageCell).filter(CoverageCell.id.in_(cell_ids)))
        if svc_ids:
            wipe(s.query(ServiceCell).filter(ServiceCell.service_id.in_(svc_ids)))
            wipe(s.query(Service).filter(Service.id.in_(svc_ids)))
        for Model in (
            CheckTask, SequenceRun, ReconTask, CheckJob, ReconJob, Endpoint, Host, Subdomain,
            ScopeRule, AuthProfile, Evidence, Request, Edge, Hypothesis, Finding, StepSequence,
        ):
            wipe(s.query(Model).filter_by(target_id=target_id))
        name = t.name
        s.delete(t)
        audit.record(s, action="target.delete", ref=name)
        s.commit()
        return {"deleted": target_id, "name": name}
    finally:
        s.close()


@app.post("/targets/{target_id}/address")
def set_target_address(target_id: int, body: AddressIn):
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        t.address = body.address.strip() or None
        if t.address:
            _autoscope(s, t.id, t.address)
        s.commit()
        audit.record(s, action="target.address", target_id=t.id, ref=t.address or "")
        return {"id": t.id, "name": t.name, "address": t.address}
    finally:
        s.close()


_ALLOWED_KINDS = {"host", "cidr", "url_prefix"}


@app.post("/targets/{target_id}/scope", status_code=201)
def add_scope_rule(target_id: int, body: ScopeRuleIn):
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {sorted(_ALLOWED_KINDS)}")
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        rule = ScopeRule(target_id=target_id, kind=body.kind, value=body.value, allow=body.allow)
        s.add(rule)
        s.commit()
        audit.record(
            s,
            action="scope.add",
            target_id=target_id,
            ref=f"{body.kind}:{body.value}:{'allow' if body.allow else 'deny'}",
        )
        return {"id": rule.id, "kind": rule.kind, "value": rule.value, "allow": rule.allow}
    finally:
        s.close()


@app.get("/targets/{target_id}/scope")
def list_scope(target_id: int):
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        return [
            {"id": r.id, "kind": r.kind, "value": r.value, "allow": r.allow} for r in t.scope_rules
        ]
    finally:
        s.close()


@app.post("/targets/{target_id}/authorize")
def authorize(target_id: int, body: AuthorizeIn):
    """Record the operator's authorization ATTESTATION (not a verification)."""
    import datetime as dt

    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        t.authorized = True
        t.authorized_at = dt.datetime.now(dt.timezone.utc)
        t.authorized_note = body.note
        s.commit()
        audit.record(s, action="target.authorize", target_id=target_id, ref=body.note)
        return {"id": t.id, "authorized": True, "note": t.authorized_note}
    finally:
        s.close()


class ReconIn(BaseModel):
    tier: str  # quick | thorough
    host: str
    keys: list[str] | None = None


@app.post("/targets/{target_id}/recon", status_code=201)
def start_recon(target_id: int, body: ReconIn):
    if body.tier not in ("quick", "thorough"):
        raise HTTPException(status_code=422, detail="tier must be quick or thorough")
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        if not t.authorized:
            raise HTTPException(status_code=403, detail="target not authorized")
        job = worker.create_job(s, target_id, body.tier, keys=body.keys, target_host=body.host)
        audit.record(s, action="recon.create", target_id=target_id, ref=f"{body.tier}:{body.host}")
        jobq.submit("recon", job.id)  # background worker runs it
        return {
            "job_id": job.id,
            "tier": job.tier,
            "status": job.status,
            "tasks": [{"key": t.key, "selected": t.selected, "status": t.status} for t in job.tasks],
        }
    finally:
        s.close()


@app.get("/targets/{target_id}/recon/{job_id}")
def get_recon(target_id: int, job_id: int):
    from .models import ReconJob

    s = db.session()
    try:
        job = s.get(ReconJob, job_id)
        if job is None or job.target_id != target_id:
            raise HTTPException(status_code=404, detail="recon job not found")
        return {
            "job_id": job.id,
            "tier": job.tier,
            "status": job.status,
            "error": job.error,
            "tasks": [
                {"key": t.key, "status": t.status, "importance": t.importance, "note": t.note}
                for t in job.tasks
            ],
        }
    finally:
        s.close()


@app.get("/targets/{target_id}/recon-coverage")
def recon_coverage(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        return inventory.recon_coverage(s, target_id)
    finally:
        s.close()


@app.get("/targets/{target_id}/inventory")
def get_inventory(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        hosts = s.query(Host).filter_by(target_id=target_id).all()
        endpoints = s.query(Endpoint).filter_by(target_id=target_id).all()
        return {
            "hosts": [
                {
                    "id": h.id,
                    "hostname": h.hostname,
                    "ip": h.ip,
                    "os_guess": h.os_guess,
                    "services": [
                        {
                            "port": sv.port,
                            "proto": sv.proto,
                            "name": sv.name,
                            "product": sv.product,
                            "version": sv.version,
                            "is_http": sv.is_http,
                        }
                        for sv in h.services
                    ],
                }
                for h in hosts
            ],
            "endpoints": [
                {
                    "id": e.id,
                    "method": e.method,
                    "path": e.path,
                    "source": e.source,
                    "host_id": e.host_id,
                    "params": json.loads(e.params_json) if e.params_json else [],
                    "body_fields": json.loads(e.body_fields_json) if e.body_fields_json else [],
                    "notes": e.notes,
                }
                for e in endpoints
            ],
        }
    finally:
        s.close()


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


@app.post("/targets/{target_id}/endpoints", status_code=201)
def add_endpoint(target_id: int, body: EndpointIn):
    """Manually catalog an endpoint as you discover it.

    We store the method, path, and the NAMES of query params and body fields —
    not a raw sample request. That's what the matrix uses to spin up
    param-specific test cells, and what an agent needs to synthesise requests;
    a whole captured request would be brittle and redundant.
    """
    method = (body.method or "GET").upper()
    if method not in _HTTP_METHODS:
        raise HTTPException(status_code=422, detail=f"method must be one of {sorted(_HTTP_METHODS)}")
    import ipaddress

    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        host_id = body.host_id
        if host_id is None:
            h = s.query(Host).filter_by(target_id=target_id).first()
            if h is None and t.address and "/" not in t.address:
                try:
                    ipaddress.ip_address(t.address)
                    h = inventory.upsert_host(s, target_id, ip=t.address)
                except ValueError:
                    h = inventory.upsert_host(s, target_id, hostname=t.address)
                s.flush()
            host_id = h.id if h else None
        elif s.get(Host, host_id) is None:
            raise HTTPException(status_code=422, detail="host_id not found")
        # Lift query-param names out of the path so a raw ?a=1&b=2 is captured
        # even when the caller didn't split it out.
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(body.path)
        q_keys = list(parse_qs(parts.query).keys())
        params = sorted(set((body.params or []) + q_keys)) or None
        ep = inventory.upsert_endpoint(
            s,
            target_id,
            method=method,
            path=parts.path or body.path,
            host_id=host_id,
            source="manual",
            params=params,
            body_fields=body.body_fields or None,
        )
        if body.notes:
            ep.notes = body.notes.strip() or None
        s.commit()
        audit.record(s, action="endpoint.add", target_id=target_id, ref=f"{method} {ep.path}")
        return {"id": ep.id, "method": ep.method, "path": ep.path, "source": ep.source}
    finally:
        s.close()


@app.get("/targets/{target_id}/subdomains")
def list_subdomains(target_id: int):
    s = db.session()
    try:
        subs = s.query(Subdomain).filter_by(target_id=target_id).all()
        return [{"id": sd.id, "name": sd.name, "status": sd.status, "source": sd.source} for sd in subs]
    finally:
        s.close()


@app.post("/targets/{target_id}/subdomains/{sub_id}/approve")
def approve_subdomain_endpoint(target_id: int, sub_id: int):
    s = db.session()
    try:
        sub = s.get(Subdomain, sub_id)
        if sub is None or sub.target_id != target_id:
            raise HTTPException(status_code=404, detail="subdomain not found")
        result = subdomains.approve_subdomain(s, sub_id)
        audit.record(s, action="subdomain.approve", target_id=target_id, ref=sub.name)
        return {"approved": sub.name, "allowed_ips": result["allowed_ips"], "firewall": result["firewall"]}
    finally:
        s.close()


@app.post("/targets/{target_id}/matrix/generate", status_code=201)
def generate_matrix(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        created = matrix_cells.generate_cells(s, target_id)
        audit.record(s, action="matrix.generate", target_id=target_id, ref=f"created={created}")
        return {"created": created}
    finally:
        s.close()


@app.get("/targets/{target_id}/matrix")
def get_matrix(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        return matrix_cells.get_matrix(s, target_id)
    finally:
        s.close()


class CellPatch(BaseModel):
    status: str
    reason: str | None = None
    scope_note: str | None = None


@app.patch("/cells/{cell_id}")
def patch_cell(cell_id: int, body: CellPatch):
    s = db.session()
    try:
        try:
            cell = matrix_cells.set_status(
                s, cell_id, body.status, reason=body.reason, scope_note=body.scope_note
            )
        except matrix_cells.InvalidStatus as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except matrix_cells.ReasonRequired as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except ValueError:
            raise HTTPException(status_code=404, detail="cell not found")
        audit.record(
            s, action="cell.update", ref=f"cell={cell_id} status={body.status}"
        )
        return {"id": cell.id, "status": cell.status, "reason": cell.reason}
    finally:
        s.close()


class AuthProfileIn(BaseModel):
    name: str
    type: str = "none"  # none | bearer | cookie | header | basic
    secret: str | None = None
    headers: dict | None = None
    notes: str | None = None


@app.post("/targets/{target_id}/auth-profiles", status_code=201)
def create_auth_profile(target_id: int, body: AuthProfileIn):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        p = AuthProfile(
            target_id=target_id,
            name=body.name,
            type=body.type,
            secret=body.secret,
            headers_json=json.dumps(body.headers) if body.headers else None,
            notes=body.notes,
        )
        s.add(p)
        s.commit()
        audit.record(s, action="auth_profile.create", target_id=target_id, ref=body.name)
        return {"id": p.id, "name": p.name, "type": p.type}
    finally:
        s.close()


@app.get("/targets/{target_id}/auth-profiles")
def list_auth_profiles(target_id: int):
    s = db.session()
    try:
        profiles = s.query(AuthProfile).filter_by(target_id=target_id).all()
        # Secrets are never returned over the API.
        return [{"id": p.id, "name": p.name, "type": p.type, "notes": p.notes} for p in profiles]
    finally:
        s.close()


class DestructiveIn(BaseModel):
    enabled: bool


@app.post("/targets/{target_id}/destructive")
def set_destructive(target_id: int, body: DestructiveIn):
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        t.destructive_opt_in = body.enabled
        s.commit()
        audit.record(
            s,
            action="target.destructive",
            target_id=target_id,
            ref=f"enabled={body.enabled}",
            destructive=body.enabled,
        )
        return {"id": t.id, "destructive_opt_in": t.destructive_opt_in}
    finally:
        s.close()


@app.post("/cells/{cell_id}/check")
async def run_cell_check(cell_id: int):
    import httpx

    s = db.session()
    try:
        cell = s.get(CoverageCell, cell_id)
        if cell is None:
            raise HTTPException(status_code=404, detail="cell not found")
        endpoint = s.get(Endpoint, cell.endpoint_id)
        target = s.get(Target, endpoint.target_id)
        if not target.authorized:
            raise HTTPException(status_code=403, detail="target not authorized")
        policy = policy_from_rules(target.scope_rules)
        profiles = {p.name: p for p in s.query(AuthProfile).filter_by(target_id=target.id).all()}
        rl = RateLimiter(rps=target.rate_limit_rps, concurrency=target.max_concurrency)
        async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
            send_fn = checks_runner.bind_send(policy, client, rate_limiter=rl)
            result = await checks_runner.run_check(
                s, cell, send_fn=send_fn, auth_profiles=profiles
            )
        audit.record(
            s,
            action="cell.check",
            target_id=target.id,
            ref=f"cell={cell_id}",
            destructive=target.destructive_opt_in,
        )
        return result
    finally:
        s.close()


class HypothesisIn(BaseModel):
    title: str
    rationale: str | None = None
    member_cells: list[int] | None = None


@app.post("/targets/{target_id}/hypotheses", status_code=201)
def create_hypothesis(target_id: int, body: HypothesisIn):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        hyp = chains_graph.create_hypothesis(
            s, target_id, body.title, rationale=body.rationale, member_cells=body.member_cells
        )
        audit.record(s, action="hypothesis.create", target_id=target_id, ref=body.title)
        return {"id": hyp.id, "title": hyp.title, "status": hyp.status, "origin": hyp.origin}
    finally:
        s.close()


@app.get("/targets/{target_id}/hypotheses")
def list_hypotheses(target_id: int):
    s = db.session()
    try:
        return chains_graph.list_hypotheses(s, target_id)
    finally:
        s.close()


class PromoteIn(BaseModel):
    to: str  # validated | confirmed | rejected


@app.post("/hypotheses/{hyp_id}/promote")
def promote_hypothesis(hyp_id: int, body: PromoteIn):
    s = db.session()
    try:
        try:
            hyp = chains_graph.set_status(s, hyp_id, body.to, actor="human")
        except chains_graph.InvalidTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ValueError:
            raise HTTPException(status_code=404, detail="hypothesis not found")
        audit.record(s, action="hypothesis.promote", ref=f"hyp={hyp_id} -> {body.to}")
        return {"id": hyp.id, "status": hyp.status}
    finally:
        s.close()


class EdgeIn(BaseModel):
    kind: str  # source_to_sink | precondition
    from_ref: str
    to_ref: str
    note: str | None = None


@app.post("/targets/{target_id}/edges", status_code=201)
def add_edge(target_id: int, body: EdgeIn):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        try:
            edge = chains_graph.add_edge(
                s, target_id, kind=body.kind, from_ref=body.from_ref, to_ref=body.to_ref, note=body.note
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        audit.record(s, action="edge.add", target_id=target_id, ref=f"{body.from_ref}->{body.to_ref}")
        return {"id": edge.id, "kind": edge.kind, "from": edge.from_ref, "to": edge.to_ref}
    finally:
        s.close()


@app.get("/targets/{target_id}/edges")
def list_edges(target_id: int):
    s = db.session()
    try:
        return chains_graph.list_edges(s, target_id)
    finally:
        s.close()


class FindingIn(BaseModel):
    title: str
    cvss_vector: str
    vuln_class_key: str | None = None
    endpoints: list[str] | None = None
    remediation: str | None = None


@app.post("/targets/{target_id}/findings", status_code=201)
def create_finding(target_id: int, body: FindingIn):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        try:
            score, sev = cvss.base_score(body.cvss_vector)
        except cvss.InvalidVector as exc:
            raise HTTPException(status_code=422, detail=f"invalid CVSS vector: {exc}")
        vc_id = None
        if body.vuln_class_key:
            vc = s.query(VulnClass).filter_by(key=body.vuln_class_key).first()
            vc_id = vc.id if vc else None
        f = Finding(
            target_id=target_id,
            title=body.title,
            vuln_class_id=vc_id,
            cvss_vector=body.cvss_vector,
            cvss_score=score,
            severity=sev,
            endpoints_json=json.dumps(body.endpoints) if body.endpoints else None,
            remediation=body.remediation,
        )
        s.add(f)
        s.commit()
        audit.record(s, action="finding.create", target_id=target_id, ref=body.title)
        return {"id": f.id, "title": f.title, "cvss_score": f.cvss_score, "severity": f.severity}
    finally:
        s.close()


def _promote(make) -> dict:
    s = db.session()
    try:
        try:
            f = make(s)
        except ValueError as exc:
            code = 404 if "not found" in str(exc) else 409
            raise HTTPException(status_code=code, detail=str(exc))
        audit.record(s, action="finding.promote", target_id=f.target_id, ref=f.title)
        return {"id": f.id, "title": f.title, "cvss_score": f.cvss_score, "severity": f.severity}
    finally:
        s.close()


@app.post("/cells/{cell_id}/promote-finding", status_code=201)
def promote_cell_finding(cell_id: int):
    return _promote(lambda s: findings.promote_cell(s, cell_id))


@app.post("/hypotheses/{hyp_id}/promote-finding", status_code=201)
def promote_hypothesis_finding(hyp_id: int):
    return _promote(lambda s: findings.promote_hypothesis(s, hyp_id))


@app.get("/targets/{target_id}/export")
def export_report(target_id: int, format: str = "json"):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        if format == "md":
            return PlainTextResponse(
                export.render_markdown(s, target_id), media_type="text/markdown"
            )
        return export.build_report(s, target_id)
    finally:
        s.close()


class ImportIn(BaseModel):
    format: str  # openapi | har
    content: str


@app.post("/targets/{target_id}/import", status_code=201)
def import_endpoints(target_id: int, body: ImportIn):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        try:
            result = import_surface(s, target_id, body.format, body.content)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        audit.record(
            s, action="import", target_id=target_id,
            ref=f"{body.format}:{result['endpoints_created']} new",
        )
        return result
    finally:
        s.close()


class CheckJobIn(BaseModel):
    cell_ids: list[int] | None = None


@app.post("/targets/{target_id}/checkjobs", status_code=201)
def create_check_job(target_id: int, body: CheckJobIn):
    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        if not t.authorized:
            raise HTTPException(status_code=403, detail="target not authorized")
        job = check_jobs.create_check_job(s, target_id, cell_ids=body.cell_ids)
        audit.record(s, action="checkjob.create", target_id=target_id, ref=f"tasks={len(job.tasks)}")
        jobq.submit("check", job.id)  # background worker runs it
        return {
            "job_id": job.id,
            "status": job.status,
            "tasks": [{"id": t.id, "cell_id": t.cell_id, "tool": t.tool, "status": t.status} for t in job.tasks],
        }
    finally:
        s.close()


@app.get("/targets/{target_id}/checkjobs/{job_id}")
def get_check_job(target_id: int, job_id: int):
    from .models import CheckJob

    s = db.session()
    try:
        job = s.get(CheckJob, job_id)
        if job is None or job.target_id != target_id:
            raise HTTPException(status_code=404, detail="check job not found")
        return {
            "job_id": job.id,
            "status": job.status,
            "error": job.error,
            "tasks": [
                {"cell_id": t.cell_id, "tool": t.tool, "status": t.status, "note": t.note}
                for t in job.tasks
            ],
        }
    finally:
        s.close()


@app.post("/targets/{target_id}/service-matrix/generate", status_code=201)
def generate_service_matrix(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        created = service_matrix.generate_service_cells(s, target_id)
        analyzed = service_matrix.analyze_services(s, target_id)
        audit.record(
            s, action="service_matrix.generate", target_id=target_id,
            ref=f"created={created} analyzed={analyzed}",
        )
        return {"created": created, "analyzed": analyzed}
    finally:
        s.close()


@app.post("/targets/{target_id}/service-matrix/cve")
async def enrich_service_cve(target_id: int):
    from .recon.runner import ToolRunner

    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        result = await cve.enrich_service_version_cves(s, target_id, ToolRunner())
        audit.record(s, action="service_matrix.cve", target_id=target_id, ref=f"updated={result['updated']}")
        return result
    finally:
        s.close()


@app.post("/targets/{target_id}/service-matrix/default-creds")
async def service_default_creds(target_id: int):
    from .recon.runner import ToolRunner

    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        try:
            result = await service_matrix.run_default_cred_pass(s, target_id, ToolRunner())
        except service_matrix.DefaultCredDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        audit.record(
            s, action="service_matrix.default_creds", target_id=target_id,
            ref=f"updated={result['updated']}", destructive=True,
        )
        return result
    finally:
        s.close()


@app.post("/targets/{target_id}/service-matrix/probe")
async def probe_service_matrix(target_id: int):
    import httpx

    from .services import probes as service_probes

    s = db.session()
    try:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="target not found")
        if not t.authorized:
            raise HTTPException(status_code=403, detail="target not authorized")
        policy = policy_from_rules(t.scope_rules)
        rl = RateLimiter(rps=t.rate_limit_rps, concurrency=t.max_concurrency)
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            send_fn = checks_runner.bind_send(policy, client, rate_limiter=rl)
            result = await service_probes.probe_services(s, target_id, send_fn)
        audit.record(s, action="service_matrix.probe", target_id=target_id, ref=f"updated={result['updated']}")
        return result
    finally:
        s.close()


@app.get("/targets/{target_id}/service-matrix")
def get_service_matrix(target_id: int):
    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        return service_matrix.get_service_matrix(s, target_id)
    finally:
        s.close()


@app.patch("/service-cells/{cell_id}")
def patch_service_cell(cell_id: int, body: CellPatch):
    s = db.session()
    try:
        try:
            cell = service_matrix.set_service_cell_status(s, cell_id, body.status, reason=body.reason)
        except matrix_cells.InvalidStatus as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except matrix_cells.ReasonRequired as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except ValueError:
            raise HTTPException(status_code=404, detail="service cell not found")
        audit.record(s, action="service_cell.update", ref=f"cell={cell_id} status={body.status}")
        return {"id": cell.id, "status": cell.status, "reason": cell.reason}
    finally:
        s.close()


class SequenceIn(BaseModel):
    name: str
    steps: list[dict]


@app.post("/targets/{target_id}/sequences", status_code=201)
def create_sequence(target_id: int, body: SequenceIn):
    from .models import StepSequence

    s = db.session()
    try:
        if s.get(Target, target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        if not isinstance(body.steps, list) or not body.steps:
            raise HTTPException(status_code=422, detail="steps must be a non-empty list")
        seq = StepSequence(target_id=target_id, name=body.name, steps_json=json.dumps(body.steps))
        s.add(seq)
        s.commit()
        audit.record(s, action="sequence.create", target_id=target_id, ref=body.name)
        return {"id": seq.id, "name": seq.name, "steps": len(body.steps)}
    finally:
        s.close()


@app.get("/targets/{target_id}/sequences")
def list_sequences(target_id: int):
    from .models import StepSequence

    s = db.session()
    try:
        rows = s.query(StepSequence).filter_by(target_id=target_id).all()
        return [{"id": q.id, "name": q.name, "steps": len(json.loads(q.steps_json))} for q in rows]
    finally:
        s.close()


class SequenceRunIn(BaseModel):
    host: str | None = None


@app.post("/sequences/{seq_id}/run")
async def run_sequence_endpoint(seq_id: int, body: SequenceRunIn):
    import httpx

    from .models import Host, StepSequence

    s = db.session()
    try:
        seq = s.get(StepSequence, seq_id)
        if seq is None:
            raise HTTPException(status_code=404, detail="sequence not found")
        target = s.get(Target, seq.target_id)
        if not target.authorized:
            raise HTTPException(status_code=403, detail="target not authorized")
        host = body.host
        if not host:
            h = s.query(Host).filter_by(target_id=target.id).first()
            host = (h.hostname or h.ip) if h else "localhost"
        policy = policy_from_rules(target.scope_rules)
        profiles = {p.name: p for p in s.query(AuthProfile).filter_by(target_id=target.id).all()}
        rl = RateLimiter(rps=target.rate_limit_rps, concurrency=target.max_concurrency)
        async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
            send_fn = checks_runner.bind_send(policy, client, rate_limiter=rl)
            run = await seq_runner.run_sequence(
                s, seq, send_fn=send_fn, auth_profiles=profiles, host=host
            )
        audit.record(s, action="sequence.run", target_id=target.id, ref=f"seq={seq_id}")
        return {"run_id": run.id, "status": run.status, "results": json.loads(run.results_json)}
    finally:
        s.close()


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()
