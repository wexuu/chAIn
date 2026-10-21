import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'t.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def test_create_with_address_autoscopes(client):
    t = client.post("/targets", json={"name": "box", "address": "10.10.11.9"}).json()
    rules = {(r["kind"], r["value"]) for r in client.get(f"/targets/{t['id']}/scope").json()}
    assert ("host", "10.10.11.9") in rules
    assert ("cidr", "10.10.11.9/32") in rules  # overrides the private-range block


def test_archive_restore_hides_and_shows(client):
    t = client.post("/targets", json={"name": "box"}).json()
    client.post(f"/targets/{t['id']}/archive")
    assert client.get("/targets/list").json() == []
    assert [x["name"] for x in client.get("/targets/list?archived=true").json()] == ["box"]
    client.post(f"/targets/{t['id']}/restore")
    assert [x["name"] for x in client.get("/targets/list").json()] == ["box"]


def test_delete_cascades(client):
    t = client.post("/targets", json={"name": "box", "address": "10.10.11.9"}).json()
    client.post(f"/targets/{t['id']}/endpoints", json={"method": "GET", "path": "/a"})
    assert client.delete(f"/targets/{t['id']}").status_code == 200
    assert client.get("/targets/list").json() == []
    assert client.get(f"/targets/{t['id']}/inventory").status_code == 404
    assert client.delete(f"/targets/{t['id']}").status_code == 404  # already gone


def test_manual_endpoint_keeps_field_names_not_request(client):
    t = client.post("/targets", json={"name": "box", "address": "box.htb"}).json()
    client.post(
        f"/targets/{t['id']}/endpoints",
        json={"method": "POST", "path": "/login?next=/home", "body_fields": ["user", "pass"]},
    )
    ep = client.get(f"/targets/{t['id']}/inventory").json()["endpoints"][0]
    assert ep["path"] == "/login"
    assert ep["params"] == ["next"]
    assert sorted(ep["body_fields"]) == ["pass", "user"]
