import pytest
from fastapi.testclient import TestClient

from chain import db
from chain.matrix import cells as mc
from chain.models import Target
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'exapi.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def _target_with_matrix(client):
    s = db.session()
    try:
        t = Target(name="lab", authorized=True)
        s.add(t)
        s.flush()
        h = upsert_host(s, t.id, hostname="example.com")
        upsert_endpoint(s, t.id, method="GET", path="/x", host_id=h.id)
        s.commit()
        mc.generate_cells(s, t.id)
        return t.id
    finally:
        s.close()


def test_create_finding_derives_score(client):
    tid = _target_with_matrix(client)
    r = client.post(
        f"/targets/{tid}/findings",
        json={
            "title": "RCE",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "endpoints": ["POST /x"],
        },
    )
    assert r.status_code == 201
    assert r.json()["cvss_score"] == 9.8
    assert r.json()["severity"] == "Critical"


def test_bad_cvss_rejected(client):
    tid = _target_with_matrix(client)
    r = client.post(f"/targets/{tid}/findings", json={"title": "x", "cvss_vector": "nonsense"})
    assert r.status_code == 422


def test_export_json_and_md(client):
    tid = _target_with_matrix(client)
    j = client.get(f"/targets/{tid}/export")
    assert j.status_code == 200
    assert "coverage_annex" in j.json()

    m = client.get(f"/targets/{tid}/export", params={"format": "md"})
    assert m.status_code == 200
    assert "# chAIn report" in m.text
