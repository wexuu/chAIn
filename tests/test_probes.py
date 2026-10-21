import httpx
import pytest

from chain import db
from chain.models import Host, Service, ServiceCell, ServiceVulnClass, Target
from chain.services import catalog
from chain.services import matrix as sm
from chain.services import probes
from chain.services.catalog import seed_service_classes


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'probe.db'}")
    s = db.session()
    seed_service_classes(s)
    yield s
    s.close()


def test_service_profile_name_and_port():
    # port fallback classifies an HTTP-labelled Elasticsearch on 9200
    canon, cls = catalog.service_profile("http", 9200)
    assert canon == "elasticsearch" and cls
    # name match wins
    assert catalog.service_profile("mysql", 3306)[0] == "mysql"
    # plain web app is excluded from the service matrix
    assert catalog.service_profile("https", 443) == (None, set())
    # longest-key match: tftp, not ftp
    assert catalog._match_name("tftp") == "tftp"


class FakeSend:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    async def __call__(self, method, url, *, headers=None, content=None, profile=None):
        self.calls.append(url)
        return self.responder(url)


def _target_with_apis(s):
    t = Target(name="t", authorized=True)
    s.add(t)
    s.flush()
    h = Host(target_id=t.id, hostname="box.htb", ip="10.10.10.9")
    s.add(h)
    s.flush()
    # ES (http-labelled, port-profiled), Docker, Kubernetes
    s.add(Service(host_id=h.id, port=9200, name="http", is_http=True))
    s.add(Service(host_id=h.id, port=2375, name="docker", is_http=False))
    s.add(Service(host_id=h.id, port=6443, name="https", is_http=True))
    s.commit()
    sm.generate_service_cells(s, t.id)
    return t


async def test_probe_sets_unauth_and_negative(session):
    t = _target_with_apis(session)

    def responder(url):
        if ":9200/" in url:
            return httpx.Response(200, text='{"indices":1}')  # open ES
        if ":2375/" in url:
            return httpx.Response(200, text='{"Version":"24.0"}')  # open docker
        if ":6443/" in url:
            return httpx.Response(403, text="forbidden")  # k8s anonymous denied
        return httpx.Response(500)

    out = await probes.probe_services(session, t.id, FakeSend(responder))
    assert out["updated"] == 2  # ES + docker open; k8s denied

    unauth = session.query(ServiceVulnClass).filter_by(key="unauth_access").first()
    cells = {
        svc.port: session.query(ServiceCell)
        .filter_by(service_id=svc.id, service_vuln_class_id=unauth.id)
        .first()
        for svc in session.query(Service).all()
    }
    assert cells[9200].status == "candidate"
    assert cells[2375].status == "candidate"
    assert cells[6443].status == "tested_negative"
