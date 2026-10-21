import pytest

from chain import cve, db
from chain.models import Host, Service, ServiceCell, ServiceVulnClass, Target
from chain.services.catalog import seed_service_classes
from chain.services.matrix import generate_service_cells


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'cve.db'}")
    s = db.session()
    seed_service_classes(s)
    yield s
    s.close()


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    async def run(self, argv, timeout):
        from chain.recon.runner import ToolResult

        self.calls.append(argv[0])
        return ToolResult(0, self.outputs.get(argv[0], ""), "")


SEARCHSPLOIT_JSON = (
    '{"RESULTS_EXPLOIT":[{"Title":"OpenSSH 8.2 - User Enum","EDB-ID":"45939","Path":"x"},'
    '{"Title":"OpenSSH - Another","EDB-ID":"40888","Path":"y"}]}'
)


def _ssh(s):
    t = Target(name="t")
    s.add(t)
    s.flush()
    h = Host(target_id=t.id, hostname="box.htb")
    s.add(h)
    s.flush()
    s.add(Service(host_id=h.id, port=22, name="ssh", product="OpenSSH", version="8.2", is_http=False))
    s.commit()
    generate_service_cells(s, t.id)
    return t.id


def test_parse_searchsploit():
    refs = cve._parse_searchsploit(SEARCHSPLOIT_JSON)
    assert {r["id"] for r in refs} == {"edb:45939", "edb:40888"}


async def test_enrich_sets_candidate(session):
    tid = _ssh(session)
    runner = FakeRunner({"searchsploit": SEARCHSPLOIT_JSON})
    out = await cve.enrich_service_version_cves(session, tid, runner)
    assert out["updated"] == 1
    vc = session.query(ServiceVulnClass).filter_by(key="version_cve").first()
    svc = session.query(Service).filter_by(name="ssh").first()
    cell = session.query(ServiceCell).filter_by(service_id=svc.id, service_vuln_class_id=vc.id).first()
    assert cell.status == "candidate"
    assert "edb:45939" in cell.reason


async def test_enrich_negative_when_no_exploits(session):
    tid = _ssh(session)
    runner = FakeRunner({"searchsploit": '{"RESULTS_EXPLOIT":[]}'})
    await cve.enrich_service_version_cves(session, tid, runner)
    vc = session.query(ServiceVulnClass).filter_by(key="version_cve").first()
    svc = session.query(Service).filter_by(name="ssh").first()
    cell = session.query(ServiceCell).filter_by(service_id=svc.id, service_vuln_class_id=vc.id).first()
    assert cell.status == "tested_negative"
    assert "OpenSSH" in cell.reason
