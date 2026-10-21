"""Background job worker: a single asyncio worker drains an in-process queue of
recon/check jobs with a concurrency cap. Create endpoints enqueue (thread-safe
from the sync request threadpool) and return immediately.

Jobs left `running` by a crash are failed on next startup by the existing
recover_stale passes; a job that never started stays `pending` (fail-safe).
"""

from __future__ import annotations

import asyncio
from typing import Optional

from . import db
from .config import settings
from .recon.runner import ToolRunner

_queue: Optional[asyncio.Queue] = None
_loop: Optional[asyncio.AbstractEventLoop] = None
_worker_task: Optional[asyncio.Task] = None

# Overridable in tests to avoid needing the real external tools installed.
RUNNER = ToolRunner()


async def _run_one(kind: str, job_id: int) -> None:
    from .checks import jobs as check_jobs
    from .models import CheckJob, ReconJob
    from .recon import worker as recon_worker

    s = db.session()
    try:
        if kind == "recon":
            job = s.get(ReconJob, job_id)
            if job is not None:
                await recon_worker.run_job(
                    s, job, RUNNER, target_host=job.target_host, evidence_dir=settings.evidence_dir
                )
        elif kind == "check":
            job = s.get(CheckJob, job_id)
            if job is not None:
                await check_jobs.run_check_job(s, job, RUNNER, evidence_dir=settings.evidence_dir)
    except Exception:  # noqa: BLE001 — run_job persists its own error status; never kill the worker
        pass
    finally:
        s.close()


async def _worker_loop(concurrency: int) -> None:
    assert _queue is not None
    sem = asyncio.Semaphore(concurrency)

    async def _task(kind: str, job_id: int) -> None:
        async with sem:
            await _run_one(kind, job_id)
        _queue.task_done()

    while True:
        kind, job_id = await _queue.get()
        asyncio.create_task(_task(kind, job_id))


def start(concurrency: int = 2) -> None:
    global _queue, _loop, _worker_task
    _loop = asyncio.get_running_loop()
    _queue = asyncio.Queue()
    _worker_task = _loop.create_task(_worker_loop(concurrency))


async def stop() -> None:
    global _worker_task, _queue, _loop
    if _worker_task is not None:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
    _worker_task = None
    _queue = None
    _loop = None


def submit(kind: str, job_id: int) -> bool:
    """Enqueue a job to run. Thread-safe: callable from sync FastAPI endpoints."""
    if _loop is None or _queue is None:
        return False
    _loop.call_soon_threadsafe(_queue.put_nowait, (kind, job_id))
    return True
