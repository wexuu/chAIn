"""Recon worker: create jobs, run selected tasks through an injected runner,
parse + ingest, with per-task status, timeouts, and crash recovery.

Launch gate: a job only runs if the Target is authorized AND the host is in
scope. Recon tools are then constrained per-packet by the firewall (firewall.py).
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Optional

from sqlalchemy.orm import Session

from ..models import ReconJob, ReconTask, Target
from ..scope import policy_from_rules
from .catalog import CATALOG
from .runner import ToolRunner


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create_job(
    session: Session,
    target_id: int,
    tier: str,
    keys: Optional[list[str]] = None,
    target_host: Optional[str] = None,
) -> ReconJob:
    job = ReconJob(target_id=target_id, tier=tier, status="pending", target_host=target_host)
    session.add(job)
    session.flush()
    for spec in CATALOG.values():
        # An explicit key list may span tiers (the UI checklist); without one,
        # fall back to this tier's default-selected tasks.
        if keys is None and spec.tier != tier:
            continue
        selected = (spec.key in keys) if keys is not None else spec.default_selected
        session.add(
            ReconTask(
                job_id=job.id,
                target_id=target_id,
                key=spec.key,
                tier=spec.tier,
                selected=selected,
                status="queued" if selected else "not_run",
                importance=spec.importance,
                could_yield=spec.could_yield,
            )
        )
    session.commit()
    return job


class LaunchDenied(Exception):
    pass


async def run_job(
    session: Session,
    job: ReconJob,
    runner: Optional[ToolRunner] = None,
    *,
    target_host: Optional[str] = None,
    evidence_dir: Optional[str] = None,
) -> ReconJob:
    runner = runner or ToolRunner()
    host = target_host or job.target_host
    if not host:
        raise ValueError("no target host for recon job")

    target = session.get(Target, job.target_id)
    if target is None or not target.authorized:
        job.status = "error"
        job.error = "launch denied: target not authorized"
        session.commit()
        raise LaunchDenied("target not authorized")

    policy = policy_from_rules(target.scope_rules)
    if not policy.check(host, None, "/").allowed:
        job.status = "error"
        job.error = f"launch denied: host {host} not in scope"
        session.commit()
        raise LaunchDenied(f"host {host} not in scope")

    job.status = "running"
    job.started_at = _now()
    session.commit()

    for task in [t for t in job.tasks if t.selected]:
        spec = CATALOG.get(task.key)
        if spec is None:
            task.status = "skipped"
            task.note = "unknown task key"
            session.commit()
            continue
        task.status = "running"
        task.started_at = _now()
        session.commit()
        try:
            result = await runner.run(spec.build_argv(host), spec.timeout)
            if evidence_dir:
                os.makedirs(os.path.join(evidence_dir, str(job.id)), exist_ok=True)
                ref = os.path.join(evidence_dir, str(job.id), f"{task.key}.out")
                with open(ref, "w") as fh:
                    fh.write(result.stdout)
                task.evidence_ref = ref
            records = spec.parse(result.stdout)
            spec.ingest(session, job.target_id, records, host)
            task.status = "done"
        except Exception as exc:  # noqa: BLE001 — record, don't crash the job
            task.status = "error"
            task.note = f"{type(exc).__name__}: {exc}"
        task.finished_at = _now()
        session.commit()

    job.status = "done"
    job.finished_at = _now()
    session.commit()
    return job


def recover_stale(session: Session) -> int:
    """On startup, fail jobs/tasks left running by a crash (idempotent restart)."""
    n = 0
    for job in session.query(ReconJob).filter(ReconJob.status.in_(["running", "pending"])).all():
        job.status = "error"
        job.error = ((job.error or "") + " interrupted-recovered").strip()
        n += 1
    for task in session.query(ReconTask).filter(ReconTask.status.in_(["running", "queued"])).all():
        task.status = "error"
        task.note = ((task.note or "") + " interrupted-recovered").strip()
    session.commit()
    return n
