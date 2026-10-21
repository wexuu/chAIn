import pytest

from chain import db
from chain.models import Host, ScopeRule, Service, Target
from chain.recon import worker
from chain.recon.runner import ToolResult
from tests.test_parsers import NMAP_XML


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'w.db'}")
    s = db.session()
    yield s
    s.close()


class FakeRunner:
    """Returns canned stdout keyed by the tool binary (argv[0])."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    async def run(self, argv, timeout):
        self.calls.append(argv)
        return ToolResult(0, self.outputs.get(argv[0], ""), "")


def _authorized_target(s, *, authorized=True, in_scope=True):
    t = Target(name="t", authorized=authorized)
    s.add(t)
    s.flush()
    if in_scope:
        s.add(ScopeRule(target_id=t.id, kind="host", value="example.com", allow=True))
    s.commit()
    return t


async def test_run_job_ingests_from_fake_tools(session):
    t = _authorized_target(session)
    job = worker.create_job(session, t.id, "quick", keys=["nmap_quick"], target_host="example.com")
    runner = FakeRunner({"nmap": NMAP_XML})
    await worker.run_job(session, job, runner, target_host="example.com")

    session.refresh(job)
    assert job.status == "done"
    assert all(t.status == "done" for t in job.tasks if t.selected)
    assert session.query(Host).filter_by(target_id=t.id).count() == 1
    assert session.query(Service).filter_by().count() == 2


async def test_launch_denied_when_not_authorized(session):
    t = _authorized_target(session, authorized=False)
    job = worker.create_job(session, t.id, "quick", keys=["nmap_quick"], target_host="example.com")
    with pytest.raises(worker.LaunchDenied):
        await worker.run_job(session, job, FakeRunner({}), target_host="example.com")
    session.refresh(job)
    assert job.status == "error"


async def test_launch_denied_when_host_out_of_scope(session):
    t = _authorized_target(session, in_scope=False)
    job = worker.create_job(session, t.id, "quick", keys=["nmap_quick"], target_host="example.com")
    with pytest.raises(worker.LaunchDenied):
        await worker.run_job(session, job, FakeRunner({}), target_host="example.com")


async def test_task_error_does_not_crash_job(session):
    t = _authorized_target(session)
    job = worker.create_job(session, t.id, "quick", keys=["nmap_quick"], target_host="example.com")

    class Boom:
        async def run(self, argv, timeout):
            raise RuntimeError("tool exploded")

    await worker.run_job(session, job, Boom(), target_host="example.com")
    session.refresh(job)
    assert job.status == "done"
    assert job.tasks[0].status == "error"
    assert "tool exploded" in job.tasks[0].note


def test_recover_stale_fails_running_jobs(session):
    t = _authorized_target(session)
    job = worker.create_job(session, t.id, "quick", target_host="example.com")
    job.status = "running"
    for task in job.tasks:
        task.status = "running"
    session.commit()

    n = worker.recover_stale(session)
    session.refresh(job)
    assert n == 1
    assert job.status == "error"
    assert all(t.status == "error" for t in job.tasks)


async def test_rescan_is_idempotent(session):
    t = _authorized_target(session)
    runner = FakeRunner({"nmap": NMAP_XML})
    for _ in range(2):
        job = worker.create_job(
            session, t.id, "quick", keys=["nmap_quick"], target_host="example.com"
        )
        await worker.run_job(session, job, runner, target_host="example.com")
    # Two scans, still one host and two services — merged, not duplicated.
    assert session.query(Host).filter_by(target_id=t.id).count() == 1
    assert session.query(Service).count() == 2
