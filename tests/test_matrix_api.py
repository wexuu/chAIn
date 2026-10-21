import pytest
from fastapi.testclient import TestClient

from chain import db
from chain.models import Target
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'mapi.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def _target_with_surface(client):
    s = db.session()
    try:
        t = Target(name="lab")
        s.add(t)
        s.flush()
        h = upsert_host(s, t.id, hostname="example.com")
        upsert_endpoint(s, t.id, method="GET", path="/search", host_id=h.id, params=["q"])
        s.commit()
        return t.id
    finally:
        s.close()


def test_generate_and_fetch_matrix(client):
    tid = _target_with_surface(client)
    r = client.post(f"/targets/{tid}/matrix/generate")
    assert r.status_code == 201
    assert r.json()["created"] > 0

    m = client.get(f"/targets/{tid}/matrix").json()
    assert len(m["columns"]) == 13
    assert len(m["endpoints"]) == 1
    assert m["summary"]["coverage_pct"] == 0.0


def test_patch_cell_requires_reason(client):
    tid = _target_with_surface(client)
    client.post(f"/targets/{tid}/matrix/generate")
    m = client.get(f"/targets/{tid}/matrix").json()
    cell_id = m["endpoints"][0]["cells"][0]["id"]

    bad = client.patch(f"/cells/{cell_id}", json={"status": "tested_negative"})
    assert bad.status_code == 422

    good = client.patch(
        f"/cells/{cell_id}",
        json={"status": "tested_negative", "reason": "encoded at the API boundary"},
    )
    assert good.status_code == 200
    assert good.json()["status"] == "tested_negative"


def test_patch_cell_bad_status(client):
    tid = _target_with_surface(client)
    client.post(f"/targets/{tid}/matrix/generate")
    m = client.get(f"/targets/{tid}/matrix").json()
    cell_id = m["endpoints"][0]["cells"][0]["id"]
    r = client.patch(f"/cells/{cell_id}", json={"status": "nope"})
    assert r.status_code == 422
