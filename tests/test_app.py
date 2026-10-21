import httpx
import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'test.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_target_scope_authorize_flow(client):
    r = client.post("/targets", json={"name": "lab-box"})
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["authorized"] is False

    r = client.post(
        f"/targets/{tid}/scope", json={"kind": "host", "value": "example.com", "allow": True}
    )
    assert r.status_code == 201

    r = client.get(f"/targets/{tid}/scope")
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.post(f"/targets/{tid}/authorize", json={"note": "engagement #42, written RoE"})
    assert r.status_code == 200
    assert r.json()["authorized"] is True


def test_bad_scope_kind_rejected(client):
    tid = client.post("/targets", json={"name": "b"}).json()["id"]
    r = client.post(f"/targets/{tid}/scope", json={"kind": "bogus", "value": "x"})
    assert r.status_code == 422


def test_duplicate_target_conflict(client):
    assert client.post("/targets", json={"name": "dup"}).status_code == 201
    assert client.post("/targets", json={"name": "dup"}).status_code == 409
