import asyncio


from chain import db, jobq
from chain.models import ReconJob, ScopeRule, Target
from chain.recon import worker
from chain.recon.inventory import upsert_endpoint, upsert_host
from chain.recon.runner import ToolResult
from tests.test_parsers import NMAP_XML


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs

    async def run(self, argv, timeout):
        return ToolResult(0, self.outputs.get(argv[0], ""), "")


async def test_worker_runs_submitted_recon_job(tmp_path, monkeypatch):
    db.init(f"sqlite:///{tmp_path/'jq.db'}")
    s = db.session()
    t = Target(name="t", authorized=True)
    s.add(t)
    s.flush()
    s.add(ScopeRule(target_id=t.id, kind="host", value="example.com", allow=True))
    h = upsert_host(s, t.id, hostname="example.com")
    upsert_endpoint(s, t.id, method="GET", path="/", host_id=h.id)
    s.commit()
    job = worker.create_job(s, t.id, "quick", keys=["nmap_quick"], target_host="example.com")
    job_id = job.id
    s.close()

    monkeypatch.setattr(jobq, "RUNNER", FakeRunner({"nmap": NMAP_XML}))
    jobq.start(concurrency=1)
    assert jobq.submit("recon", job_id) is True
    await asyncio.sleep(0.1)  # let the thread-safe enqueue land on the loop
    await asyncio.wait_for(jobq._queue.join(), timeout=5)  # wait until the worker finished
    await jobq.stop()

    s2 = db.session()
    done = s2.get(ReconJob, job_id)
    assert done.status == "done"  # ran to completion without any manual run call
    s2.close()


def test_submit_is_noop_when_worker_not_started():
    # Fresh module state (previous test stopped the worker).
    assert jobq._loop is None
    assert jobq.submit("recon", 123) is False
