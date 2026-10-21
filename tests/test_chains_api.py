import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'chapi.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def _target(client):
    return client.post("/targets", json={"name": "lab"}).json()["id"]


def test_hypothesis_lifecycle(client):
    tid = _target(client)
    r = client.post(
        f"/targets/{tid}/hypotheses",
        json={"title": "IDOR -> account takeover", "member_cells": [1, 2]},
    )
    assert r.status_code == 201
    hid = r.json()["id"]
    assert r.json()["status"] == "proposed"

    assert client.post(f"/hypotheses/{hid}/promote", json={"to": "validated"}).status_code == 200
    assert client.post(f"/hypotheses/{hid}/promote", json={"to": "confirmed"}).status_code == 200
    # illegal now
    bad = client.post(f"/hypotheses/{hid}/promote", json={"to": "validated"})
    assert bad.status_code == 409


def test_illegal_jump_conflict(client):
    tid = _target(client)
    hid = client.post(f"/targets/{tid}/hypotheses", json={"title": "x"}).json()["id"]
    r = client.post(f"/hypotheses/{hid}/promote", json={"to": "confirmed"})
    assert r.status_code == 409


def test_edges(client):
    tid = _target(client)
    r = client.post(
        f"/targets/{tid}/edges",
        json={"kind": "source_to_sink", "from_ref": "cell:1", "to_ref": "cell:9"},
    )
    assert r.status_code == 201
    assert len(client.get(f"/targets/{tid}/edges").json()) == 1
