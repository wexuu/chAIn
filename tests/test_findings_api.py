import pytest
from fastapi.testclient import TestClient

from chain import db
from chain.matrix import cells as mc
from chain.models import CoverageCell, Target, VulnClass
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'fapi.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def _confirmed_cell(client):
    s = db.session()
    try:
        t = Target(name="lab")
        s.add(t)
        s.flush()
        h = upsert_host(s, t.id, hostname="example.com")
        upsert_endpoint(s, t.id, method="GET", path="/x", host_id=h.id)
        s.commit()
        mc.generate_cells(s, t.id)
        cell = (
            s.query(CoverageCell)
            .join(VulnClass, CoverageCell.vuln_class_id == VulnClass.id)
            .filter(VulnClass.key == "method_tampering")
            .first()
        )
        mc.set_status(s, cell.id, "confirmed")
        return cell.id
    finally:
        s.close()


def test_promote_cell_endpoint(client):
    cid = _confirmed_cell(client)
    r = client.post(f"/cells/{cid}/promote-finding")
    assert r.status_code == 201
    assert r.json()["severity"]


def test_promote_unconfirmed_conflicts(client):
    s = db.session()
    try:
        from chain.models import Target

        t = Target(name="z")
        s.add(t)
        s.flush()
        h = upsert_host(s, t.id, hostname="e.com")
        upsert_endpoint(s, t.id, method="GET", path="/y", host_id=h.id)
        s.commit()
        mc.generate_cells(s, t.id)
        cell = s.query(CoverageCell).first()
        cid = cell.id
    finally:
        s.close()
    r = client.post(f"/cells/{cid}/promote-finding")
    assert r.status_code == 409  # untested cell can't be promoted


def test_promote_missing_404(client):
    r = client.post("/cells/99999/promote-finding")
    assert r.status_code == 404
