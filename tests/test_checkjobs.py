import pytest

from chain import db
from chain.checks import jobs
from chain.recon.runner import ToolResult
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import seed_vuln_classes
from chain.models import Attempt, CoverageCell, ScopeRule, Target, VulnClass
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'cj.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    async def run(self, argv, timeout):
        self.calls.append(argv)
        return ToolResult(0, self.outputs.get(argv[0], ""), "")


def _target(s, authorized=True, in_scope=True):
    t = Target(name="t", authorized=authorized)
    s.add(t)
    s.flush()
    if in_scope:
        s.add(ScopeRule(target_id=t.id, kind="host", value="example.com", allow=True))
    h = upsert_host(s, t.id, hostname="example.com")
    upsert_endpoint(s, t.id, method="GET", path="/items", host_id=h.id, params=["id"])
    s.commit()
    mc.generate_cells(s, t.id)
    return t


def _sqli_cell(s, tid):
    return (
        s.query(CoverageCell)
        .join(VulnClass, CoverageCell.vuln_class_id == VulnClass.id)
        .filter(VulnClass.key == "sqli")
        .first()
    )


def test_create_job_only_for_wrapped_classes(session):
    t = _target(session)
    job = jobs.create_check_job(session, t.id)
    tools = {task.tool for task in job.tasks}
    # sqli->sqlmap, xss->dalfox, ssti/cmdi/path->nuclei; no task for authz/headers/etc.
    assert tools <= {"sqlmap", "dalfox", "nuclei"}
    assert "sqlmap" in tools


async def test_run_job_sets_candidate_on_sqli(session):
    t = _target(session)
    cell = _sqli_cell(session, t.id)
    job = jobs.create_check_job(session, t.id, cell_ids=[cell.id])
    runner = FakeRunner({"sqlmap": "Parameter: id (GET)\n    Type: boolean-based blind"})
    await jobs.run_check_job(session, job, runner)
    session.refresh(job)
    session.refresh(cell)
    assert job.status == "done"
    assert cell.status == "candidate"
    assert session.query(Attempt).filter_by(cell_id=cell.id).count() == 1


async def test_run_job_negative(session):
    t = _target(session)
    cell = _sqli_cell(session, t.id)
    job = jobs.create_check_job(session, t.id, cell_ids=[cell.id])
    runner = FakeRunner({"sqlmap": "all tested parameters do not appear to be injectable"})
    await jobs.run_check_job(session, job, runner)
    session.refresh(cell)
    assert cell.status == "tested_negative"


async def test_launch_denied_unauthorized(session):
    t = _target(session, authorized=False)
    job = jobs.create_check_job(session, t.id)
    with pytest.raises(jobs.LaunchDenied):
        await jobs.run_check_job(session, job, FakeRunner({}))


async def test_out_of_scope_tasks_skipped(session):
    t = _target(session, in_scope=False)
    cell = _sqli_cell(session, t.id)
    job = jobs.create_check_job(session, t.id, cell_ids=[cell.id])
    await jobs.run_check_job(session, job, FakeRunner({"sqlmap": "x"}))
    session.refresh(job)
    assert job.status == "done"
    assert all(task.status == "skipped" for task in job.tasks)


async def test_wont_override_human_confirmed(session):
    t = _target(session)
    cell = _sqli_cell(session, t.id)
    mc.set_status(session, cell.id, "confirmed")  # human verdict
    job = jobs.create_check_job(session, t.id, cell_ids=[cell.id])
    await jobs.run_check_job(session, job, FakeRunner({"sqlmap": "all tested parameters do not appear to be injectable"}))
    session.refresh(cell)
    assert cell.status == "confirmed"  # unchanged


def test_recover_stale_checks(session):
    t = _target(session)
    job = jobs.create_check_job(session, t.id)
    job.status = "running"
    for task in job.tasks:
        task.status = "running"
    session.commit()
    assert jobs.recover_stale_checks(session) == 1
    session.refresh(job)
    assert job.status == "error"
