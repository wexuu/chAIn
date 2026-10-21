import datetime as dt

import pytest

from chain import db, evidence, ops
from chain.firewall import apply_ruleset, generate_ruleset
from chain.models import Evidence, Target


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'ops.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_preflight_reports_tools():
    pf = ops.tool_preflight()
    assert "tools" in pf and "nmap" in pf["tools"]
    assert isinstance(pf["missing"], list)
    assert pf["firewall_apply_enabled"] is False  # default off


def test_firewall_apply_disabled_by_default(monkeypatch):
    # Even if nft existed, apply is gated off by config -> never shells out.
    result = apply_ruleset(generate_ruleset(["1.2.3.4"]), nft_path="nft")
    assert result["applied"] is False
    assert "disabled-by-config" in result["reason"]


def test_reap_evidence_removes_expired(session, tmp_path):
    tid = _target(session)
    ev_old = evidence.store_blob(session, tid, "response", "old", evidence_dir=str(tmp_path))
    ev_keep = evidence.store_blob(session, tid, "response", "keep", evidence_dir=str(tmp_path))
    # one already expired, one far in the future
    ev_old.retain_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    ev_keep.retain_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    session.commit()

    reaped = ops.reap_evidence(session)
    assert reaped == 1
    assert session.query(Evidence).count() == 1
    import os

    assert not os.path.exists(ev_old.path)


def test_optional_token_auth(monkeypatch, tmp_path):
    from dataclasses import replace

    from fastapi.testclient import TestClient

    import chain.app as app_mod
    from chain.config import settings as real

    db.init(f"sqlite:///{tmp_path/'auth.db'}")
    monkeypatch.setattr(app_mod, "settings", replace(real, ui_auth_token="s3cret"))
    with TestClient(app_mod.app) as c:
        assert c.get("/health").status_code == 200  # exempt
        assert c.get("/targets/list").status_code == 401  # protected, no token
        assert c.get("/targets/list", headers={"X-Chain-Token": "s3cret"}).status_code == 200
        assert c.get("/targets/list", params={"token": "s3cret"}).status_code == 200
