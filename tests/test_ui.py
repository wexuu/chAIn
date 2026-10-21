import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'ui.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def test_index_redirects_to_app(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (307, 308)
    assert r.headers["location"] == "/app/"


def test_targets_list(client):
    assert client.get("/targets/list").json() == []
    client.post("/targets", json={"name": "lab"})
    lst = client.get("/targets/list").json()
    assert len(lst) == 1 and lst[0]["name"] == "lab"
