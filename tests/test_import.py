import json

import pytest

from chain import db
from chain.import_ import import_surface
from chain.import_.har import parse_har
from chain.import_.openapi import parse_openapi
from chain.models import Endpoint, Target

OPENAPI_JSON = json.dumps(
    {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users": {
                "get": {"parameters": [{"name": "page", "in": "query"}]},
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"name": {}, "role": {}}}
                            }
                        }
                    }
                },
            },
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path"}],
                "get": {},
            },
        },
    }
)

HAR = json.dumps(
    {
        "log": {
            "entries": [
                {"request": {"method": "GET", "url": "https://app.example.com/search?q=1&page=2"}},
                {
                    "request": {
                        "method": "POST",
                        "url": "https://app.example.com/login",
                        "postData": {"text": "{\"user\":\"a\",\"pass\":\"b\"}"},
                    }
                },
                {"request": {"method": "GET", "url": "https://app.example.com/search?q=9"}},  # dup path
            ]
        }
    }
)


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'imp.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_parse_openapi():
    hosts, ops = parse_openapi(OPENAPI_JSON)
    assert hosts == ["api.example.com"]
    by = {(o["method"], o["path"]): o for o in ops}
    assert ("GET", "/users") in by and ("POST", "/users") in by
    assert by[("GET", "/users")]["params"] == ["page"]
    assert by[("POST", "/users")]["body_fields"] == ["name", "role"]
    assert by[("GET", "/users/{id}")]["params"] == ["id"]  # path-level param inherited


def test_parse_openapi_yaml():
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(OPENAPI_JSON)  # dict path
    hosts, ops = parse_openapi(spec)
    assert hosts == ["api.example.com"]
    assert len(ops) == 3


def test_parse_har():
    hosts, ops = parse_har(HAR)
    assert hosts == ["app.example.com"]
    login = [o for o in ops if o["path"] == "/login"][0]
    assert sorted(login["body_fields"]) == ["pass", "user"]
    search = [o for o in ops if o["path"] == "/search"][0]
    assert "q" in search["params"]


def test_import_openapi_then_har_dedupes(session):
    tid = _target(session)
    r1 = import_surface(session, tid, "openapi", OPENAPI_JSON)
    assert r1["endpoints_created"] == 3
    # HAR adds app.example.com endpoints (different host) — all new
    r2 = import_surface(session, tid, "har", HAR)
    assert r2["endpoints_created"] == 2  # /search dedupes to one row, /login new
    # /search appears twice in HAR but dedupes to one row
    assert session.query(Endpoint).filter_by(path="/search").count() == 1
    total = session.query(Endpoint).count()
    assert total == 3 + 2  # 3 openapi + (/search, /login)


def test_bad_format(session):
    tid = _target(session)
    with pytest.raises(ValueError):
        import_surface(session, tid, "burp", "{}")
