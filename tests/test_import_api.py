import json

import pytest
from fastapi.testclient import TestClient

from chain import db


@pytest.fixture()
def client(tmp_path):
    db.init(f"sqlite:///{tmp_path/'impapi.db'}")
    from chain.app import app

    with TestClient(app) as c:
        yield c


def test_import_openapi_via_api(client):
    tid = client.post("/targets", json={"name": "lab"}).json()["id"]
    spec = json.dumps(
        {"openapi": "3.0.0", "servers": [{"url": "https://api.x.com"}],
         "paths": {"/a": {"get": {}}, "/b": {"post": {}}}}
    )
    r = client.post(f"/targets/{tid}/import", json={"format": "openapi", "content": spec})
    assert r.status_code == 201
    assert r.json()["endpoints_created"] == 2
    inv = client.get(f"/targets/{tid}/inventory").json()
    assert len(inv["endpoints"]) == 2


def test_import_bad_format(client):
    tid = client.post("/targets", json={"name": "lab"}).json()["id"]
    r = client.post(f"/targets/{tid}/import", json={"format": "burp", "content": "{}"})
    assert r.status_code == 422
