import pytest

from chain import db
from chain.models import Host, Service, ServiceCell, ServiceVulnClass, ScopeRule, Target
from chain.recon.runner import ToolResult
from chain.services import matrix as sm
from chain.services.catalog import seed_service_classes


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'dc.db'}")
    s = db.session()
    seed_service_classes(s)
    yield s
    s.close()


MYSQL_EMPTY_XML = """<?xml version="1.0"?>
<nmaprun><host>
<address addr="10.10.10.5" addrtype="ipv4"/>
<hostnames><hostname name="box.htb" type="user"/></hostnames>
<ports><port protocol="tcp" portid="3306"><state state="open"/>
<service name="mysql"/>
<script id="mysql-empty-password" output="root account has empty password"/>
</port></ports></host></nmaprun>"""


class FakeRunner:
    def __init__(self, out):
        self.out = out
        self.calls = []

    async def run(self, argv, timeout):
        self.calls.append(argv)
        return ToolResult(0, self.out, "")


def _target(s, *, authorized=True, destructive=True, in_scope=True):
    t = Target(name="t", authorized=authorized, destructive_opt_in=destructive)
    s.add(t)
    s.flush()
    if in_scope:
        s.add(ScopeRule(target_id=t.id, kind="host", value="box.htb", allow=True))
    h = Host(target_id=t.id, hostname="box.htb", ip="10.10.10.5")
    s.add(h)
    s.flush()
    s.add(Service(host_id=h.id, port=3306, name="mysql", product="MySQL", version="5.7", is_http=False))
    s.commit()
    sm.generate_service_cells(s, t.id)
    return t


async def test_default_cred_hit_sets_unauth_candidate(session):
    t = _target(session)
    runner = FakeRunner(MYSQL_EMPTY_XML)
    out = await sm.run_default_cred_pass(session, t.id, runner)
    assert out["updated"] == 1
    # the nmap invocation used the empty-password scripts
    assert any("mysql-empty-password" in a for a in runner.calls[0])
    svc = session.query(Service).filter_by(name="mysql").first()
    unauth = session.query(ServiceVulnClass).filter_by(key="unauth_access").first()
    cell = session.query(ServiceCell).filter_by(service_id=svc.id, service_vuln_class_id=unauth.id).first()
    assert cell.status == "candidate"
    assert "empty password" in cell.reason.lower()


async def test_requires_destructive_opt_in(session):
    t = _target(session, destructive=False)
    with pytest.raises(sm.DefaultCredDenied):
        await sm.run_default_cred_pass(session, t.id, FakeRunner(MYSQL_EMPTY_XML))


async def test_requires_authorization(session):
    t = _target(session, authorized=False)
    with pytest.raises(sm.DefaultCredDenied):
        await sm.run_default_cred_pass(session, t.id, FakeRunner(MYSQL_EMPTY_XML))
