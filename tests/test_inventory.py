import pytest

from chain import db
from chain.models import Endpoint, Host
from chain.recon import inventory


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'inv.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    from chain.models import Target

    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_normalize_path():
    assert inventory.normalize_path("") == "/"
    assert inventory.normalize_path("admin") == "/admin"
    assert inventory.normalize_path("/a//b/") == "/a/b"
    assert inventory.normalize_path("/x?y=1#z") == "/x"
    assert inventory.normalize_path("/") == "/"


def test_host_upsert_dedupes_by_ip(session):
    tid = _target(session)
    h1 = inventory.upsert_host(session, tid, ip="1.2.3.4", hostname="a.com")
    h2 = inventory.upsert_host(session, tid, ip="1.2.3.4", os_guess="Linux")
    session.commit()
    assert h1.id == h2.id
    assert session.query(Host).count() == 1
    assert h2.os_guess == "Linux"  # enriched on second pass


def test_endpoint_upsert_dedupes_by_method_path(session):
    tid = _target(session)
    h = inventory.upsert_host(session, tid, hostname="a.com")
    inventory.upsert_endpoint(session, tid, method="GET", path="/users/", host_id=h.id)
    inventory.upsert_endpoint(session, tid, method="GET", path="/users", host_id=h.id)  # same after norm
    inventory.upsert_endpoint(session, tid, method="POST", path="/users", host_id=h.id)  # distinct method
    session.commit()
    assert session.query(Endpoint).count() == 2


def test_endpoint_param_merge(session):
    tid = _target(session)
    h = inventory.upsert_host(session, tid, hostname="a.com")
    inventory.upsert_endpoint(session, tid, method="GET", path="/s", host_id=h.id, params=["q"])
    ep = inventory.upsert_endpoint(
        session, tid, method="GET", path="/s", host_id=h.id, params=["page"]
    )
    session.commit()
    import json

    assert sorted(json.loads(ep.params_json)) == ["page", "q"]


def test_service_upsert_dedupes(session):
    tid = _target(session)
    h = inventory.upsert_host(session, tid, hostname="a.com")
    inventory.upsert_service(session, h, port=443, name="https", is_http=True)
    inventory.upsert_service(session, h, port=443, version="1.1")
    session.commit()
    assert len(h.services) == 1
    assert h.services[0].version == "1.1"
    assert h.services[0].is_http is True


def test_nmap_ingest_bridges_http_service_to_endpoint(session):
    """A detected HTTP service must seed a root endpoint, even without httpx."""
    from chain.recon.catalog import ingest_nmap

    tid = _target(session)
    records = [
        {
            "ip": "10.10.11.42",
            "hostname": "box",
            "services": [
                {"port": 22, "name": "ssh", "is_http": False},
                {"port": 8080, "name": "http-alt", "is_http": True},
            ],
        }
    ]
    ingest_nmap(session, tid, records, "box")
    session.commit()
    eps = session.query(Endpoint).all()
    # only the HTTP service becomes an endpoint; ssh does not
    assert len(eps) == 1
    assert eps[0].method == "GET" and eps[0].path == "/" and eps[0].source == "nmap"
