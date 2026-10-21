import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'api.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def _authorized_target(client):
    tid = client.post("/targets", json={"name": "lab"}).json()["id"]
    client.post(f"/targets/{tid}/scope", json={"kind": "host", "value": "example.com", "allow": True})
    client.post(f"/targets/{tid}/authorize", json={"note": "RoE on file"})
    return tid


def test_recon_requires_authorization(client):
    tid = client.post("/targets", json={"name": "unauth"}).json()["id"]
    r = client.post(f"/targets/{tid}/recon", json={"tier": "quick", "host": "example.com"})
    assert r.status_code == 403


def test_recon_creates_job_and_tasks(client):
    tid = _authorized_target(client)
    r = client.post(f"/targets/{tid}/recon", json={"tier": "quick", "host": "example.com"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "pending"
    keys = {t["key"] for t in body["tasks"]}
    assert "nmap_quick" in keys and "httpx_probe" in keys

    # Everything selected -> nothing is a coverage gap yet.
    cov = client.get(f"/targets/{tid}/recon-coverage").json()
    assert cov["flagged_gaps"] == []


def test_coverage_flags_deselected_high_importance(client):
    tid = _authorized_target(client)
    # Deselect the high-importance nmap_quick; it should surface as a gap.
    client.post(
        f"/targets/{tid}/recon",
        json={"tier": "quick", "host": "example.com", "keys": ["httpx_probe"]},
    )
    cov = client.get(f"/targets/{tid}/recon-coverage").json()
    assert any(g["key"] == "nmap_quick" and g["status"] == "not_run" for g in cov["flagged_gaps"])


def test_recon_bad_tier(client):
    tid = _authorized_target(client)
    r = client.post(f"/targets/{tid}/recon", json={"tier": "bogus", "host": "example.com"})
    assert r.status_code == 422


def test_selected_keys_subset(client):
    tid = _authorized_target(client)
    r = client.post(
        f"/targets/{tid}/recon",
        json={"tier": "quick", "host": "example.com", "keys": ["nmap_quick"]},
    )
    tasks = {t["key"]: t["selected"] for t in r.json()["tasks"]}
    assert tasks["nmap_quick"] is True
    assert tasks["httpx_probe"] is False
