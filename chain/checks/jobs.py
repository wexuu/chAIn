"""Async wrapped-check jobs: CheckJob/CheckTask, run through an injected runner
(like the recon worker). Launch-gated, per-task timeouts, crash recovery.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy.orm import Session

from .. import audit, evidence
from ..models import (
    Attempt,
    CheckJob,
    CheckTask,
    CoverageCell,
    Endpoint,
    Request,
    Target,
    VulnClass,
)
from ..recon.runner import ToolRunner
from ..scope import policy_from_rules
from . import wrapped

TOOL_TIMEOUT = 1800.0


def _now():
    return dt.datetime.now(dt.timezone.utc)


class LaunchDenied(Exception):
    pass


def create_check_job(session: Session, target_id: int, cell_ids: Optional[list[int]] = None) -> CheckJob:
    """Create a job with a task per (cell, applicable wrapped tool). If cell_ids is
    None, cover every cell whose class has a wrapped adapter and isn't resolved yet."""
    q = session.query(CoverageCell).join(Endpoint, CoverageCell.endpoint_id == Endpoint.id).filter(
        Endpoint.target_id == target_id
    )
    if cell_ids is not None:
        q = q.filter(CoverageCell.id.in_(cell_ids))
    vc_key = {v.id: v.key for v in session.query(VulnClass).all()}

    job = CheckJob(target_id=target_id, status="pending")
    session.add(job)
    session.flush()
    n = 0
    for cell in q.all():
        adapter = wrapped.adapter_for(vc_key.get(cell.vuln_class_id, ""))
        if adapter is None:
            continue
        if cell_ids is None and cell.status in ("confirmed", "not_applicable"):
            continue
        session.add(CheckTask(job_id=job.id, target_id=target_id, cell_id=cell.id, tool=adapter.tool))
        n += 1
    session.commit()
    return job


def _record(session, cell, tool, url, stdout, verdict, evidence_dir):
    tid = cell_target_id(session, cell)
    ev = evidence.store_blob(session, tid, "tool_output", stdout, evidence_dir=evidence_dir)
    req = Request(
        target_id=tid,
        endpoint_id=cell.endpoint_id,
        method=f"TOOL:{tool}",
        url=url,
    )
    session.add(req)
    session.flush()
    att = Attempt(
        cell_id=cell.id,
        request_id=req.id,
        verdict=verdict,
        evidence_ref=ev.path,
        response_ref=str(ev.id),
    )
    session.add(att)
    session.flush()
    return ev.path


def cell_target_id(session, cell) -> int:
    ep = session.get(Endpoint, cell.endpoint_id)
    return ep.target_id


async def run_check_job(
    session: Session,
    job: CheckJob,
    runner: Optional[ToolRunner] = None,
    *,
    evidence_dir: Optional[str] = None,
) -> CheckJob:
    runner = runner or ToolRunner()
    target = session.get(Target, job.target_id)
    if target is None or not target.authorized:
        job.status = "error"
        job.error = "launch denied: target not authorized"
        session.commit()
        raise LaunchDenied("target not authorized")
    policy = policy_from_rules(target.scope_rules)

    job.status = "running"
    job.started_at = _now()
    session.commit()

    vc_key = {v.id: v.key for v in session.query(VulnClass).all()}
    for task in job.tasks:
        cell = session.get(CoverageCell, task.cell_id)
        endpoint = session.get(Endpoint, cell.endpoint_id)
        host = None
        from ..models import Host

        if endpoint.host_id:
            h = session.get(Host, endpoint.host_id)
            host = h.hostname or h.ip if h else None
        host = host or "localhost"
        if not policy.check(host, None, endpoint.path).allowed:
            task.status = "skipped"
            task.note = f"host {host} not in scope"
            session.commit()
            continue

        adapter = wrapped.adapter_for(vc_key.get(cell.vuln_class_id, ""))
        task.status = "running"
        task.started_at = _now()
        session.commit()
        try:
            url = wrapped.cell_target_url(session, endpoint, cell.param_name)
            argv = adapter.build_argv(url, cell.param_name)
            result = await runner.run(argv, TOOL_TIMEOUT)
            verdict, reason = adapter.parse(result.stdout)
            ref = _record(session, cell, task.tool, url, result.stdout, verdict, evidence_dir)
            task.evidence_ref = ref
            # Only move an untested/candidate cell; never override a human verdict.
            if cell.status in ("untested", "candidate"):
                cell.status = verdict
                cell.reason = reason
            task.status = "done"
            task.note = reason
        except Exception as exc:  # noqa: BLE001
            task.status = "error"
            task.note = f"{type(exc).__name__}: {exc}"
        task.finished_at = _now()
        session.commit()

    job.status = "done"
    job.finished_at = _now()
    session.commit()
    audit.record(session, action="checkjob.run", target_id=job.target_id, ref=f"job={job.id}")
    return job


def recover_stale_checks(session: Session) -> int:
    n = 0
    for job in session.query(CheckJob).filter(CheckJob.status.in_(["running", "pending"])).all():
        job.status = "error"
        job.error = ((job.error or "") + " interrupted-recovered").strip()
        n += 1
    for task in session.query(CheckTask).filter(CheckTask.status.in_(["running", "queued"])).all():
        task.status = "error"
        task.note = ((task.note or "") + " interrupted-recovered").strip()
    session.commit()
    return n
