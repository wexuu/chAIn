import json

import pytest

from chain import db
from chain.models import Host, Service, ServiceCell, Target
from chain.services import catalog
from chain.services import matrix as sm
from chain.services.catalog import seed_service_classes


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'svc.db'}")
    s = db.session()
    seed_service_classes(s)
    yield s
    s.close()


def _host_with_services(s):
    t = Target(name="t")
    s.add(t)
    s.flush()
    h = Host(target_id=t.id, hostname="box.htb", ip="10.10.10.10")
    s.add(h)
    s.flush()
    s.add(Service(host_id=h.id, port=27017, proto="tcp", name="mongodb", version="4.0", is_http=False))
    s.add(Service(host_id=h.id, port=6379, proto="tcp", name="redis", is_http=False,
                  scripts_json=json.dumps({"redis-info": "redis_version:6.0\nrole:master"})))
    s.add(Service(host_id=h.id, port=22, proto="tcp", name="ssh", product="OpenSSH", version="8.2", is_http=False))
    s.add(Service(host_id=h.id, port=443, proto="tcp", name="https", is_http=True))  # web, excluded
    s.commit()
    return t.id


def test_catalog_applicability():
    assert catalog.applicable_classes("mongodb") == {"unauth_access", "version_cve", "misconfig", "dangerous_exposure"}
    assert catalog.applicable_classes("ssh") == {"unauth_access", "version_cve", "misconfig"}
    assert catalog.applicable_classes("http") == set()  # web isn't a service-matrix row
    assert catalog.applicable_classes("redis")  # redis is a catalog service


def test_generate_service_cells(session):
    tid = _host_with_services(session)
    created = sm.generate_service_cells(session, tid)
    # mongodb(4) + redis(4) + ssh(3) = 11; the https service is excluded
    assert created == 11
    # version_cve cell for ssh records the version in scope_note
    ssh = session.query(Service).filter_by(name="ssh").first()
    from chain.models import ServiceVulnClass

    vcve = session.query(ServiceVulnClass).filter_by(key="version_cve").first()
    cell = session.query(ServiceCell).filter_by(service_id=ssh.id, service_vuln_class_id=vcve.id).first()
    assert cell.scope_note and "8.2" in cell.scope_note


def test_analyze_sets_unauth_from_nse(session):
    tid = _host_with_services(session)
    sm.generate_service_cells(session, tid)
    touched = sm.analyze_services(session, tid)
    assert touched >= 1
    redis = session.query(Service).filter_by(name="redis").first()
    from chain.models import ServiceVulnClass

    unauth = session.query(ServiceVulnClass).filter_by(key="unauth_access").first()
    cell = session.query(ServiceCell).filter_by(service_id=redis.id, service_vuln_class_id=unauth.id).first()
    assert cell.status == "candidate"
    assert "Redis" in cell.reason


def test_service_matrix_shape(session):
    tid = _host_with_services(session)
    sm.generate_service_cells(session, tid)
    m = sm.get_service_matrix(session, tid)
    assert len(m["columns"]) == 4
    names = {row["service"] for row in m["services"]}
    assert names == {"mongodb", "redis", "ssh"}  # no web service


def test_service_cell_reason_required(session):
    tid = _host_with_services(session)
    sm.generate_service_cells(session, tid)
    cell = session.query(ServiceCell).first()
    with pytest.raises(Exception):
        sm.set_service_cell_status(session, cell.id, "tested_negative")
    ok = sm.set_service_cell_status(session, cell.id, "tested_negative", reason="auth required, creds unknown")
    assert ok.status == "tested_negative"
