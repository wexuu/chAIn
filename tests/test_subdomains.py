import json

import pytest

from chain import db
from chain.models import Host, ScopeRule, Target
from chain.recon import subdomains
from chain.recon.inventory import upsert_subdomain


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'sub.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_approve_creates_host_scope_and_firewall(session):
    tid = _target(session)
    sub = upsert_subdomain(session, tid, name="api.example.com")
    session.commit()

    result = subdomains.approve_subdomain(
        session, sub.id, resolver=lambda name: ["93.184.216.34"]
    )

    session.refresh(sub)
    assert sub.status == "approved"
    assert json.loads(sub.resolved_ips_json) == ["93.184.216.34"]
    # host created
    assert session.query(Host).filter_by(target_id=tid, hostname="api.example.com").count() == 1
    # allow scope rule added
    assert (
        session.query(ScopeRule)
        .filter_by(target_id=tid, kind="host", value="api.example.com", allow=True)
        .count()
        == 1
    )
    # firewall allow-set now includes the resolved IP
    assert "93.184.216.34" in result["allowed_ips"]
    assert "ip daddr 93.184.216.34 accept" in result["ruleset"]


def test_unapproved_subdomain_not_in_firewall(session):
    tid = _target(session)
    upsert_subdomain(session, tid, name="found-only.example.com")
    session.commit()
    result = subdomains.regenerate_firewall(session, tid)
    assert result["allowed_ips"] == []  # nothing approved -> nothing allowed


def test_exclude_subdomain(session):
    tid = _target(session)
    sub = upsert_subdomain(session, tid, name="x.example.com")
    session.commit()
    subdomains.exclude_subdomain(session, sub.id)
    session.refresh(sub)
    assert sub.status == "excluded"
