import json

import pytest

from chain import db, findings
from chain.chains import graph
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import seed_vuln_classes
from chain.models import Attempt, CoverageCell, Finding, Request, Target, VulnClass
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'f.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


def _sqli_cell(s):
    t = Target(name="t")
    s.add(t)
    s.flush()
    h = upsert_host(s, t.id, hostname="example.com")
    ep = upsert_endpoint(s, t.id, method="GET", path="/items", host_id=h.id, params=["id"])
    s.commit()
    mc.generate_cells(s, t.id)
    cell = (
        s.query(CoverageCell)
        .join(VulnClass, CoverageCell.vuln_class_id == VulnClass.id)
        .filter(VulnClass.key == "sqli")
        .first()
    )
    return t, ep, cell


def test_promote_confirmed_cell(session):
    t, ep, cell = _sqli_cell(session)
    # attach an attempt with evidence, then confirm
    req = Request(target_id=t.id, endpoint_id=ep.id, method="GET", url="https://example.com/items")
    session.add(req)
    session.flush()
    session.add(Attempt(cell_id=cell.id, request_id=req.id, evidence_ref="/ev/x.bin", verdict="x"))
    mc.set_status(session, cell.id, "confirmed")

    f = findings.promote_cell(session, cell.id)
    assert f.severity == "Critical" and f.cvss_score == 9.8  # sqli suggested vector
    assert "SQL injection" in f.title and "/items" in f.title
    assert json.loads(f.endpoints_json) == ["GET /items"]
    assert json.loads(f.evidence_refs_json) == ["/ev/x.bin"]
    assert session.query(Finding).count() == 1


def test_promote_requires_confirmed(session):
    t, ep, cell = _sqli_cell(session)
    with pytest.raises(ValueError):
        findings.promote_cell(session, cell.id)  # still untested
    mc.set_status(session, cell.id, "candidate")
    with pytest.raises(ValueError):
        findings.promote_cell(session, cell.id)  # candidate isn't confirmed either


def test_promote_confirmed_hypothesis(session):
    t, ep, cell = _sqli_cell(session)
    mc.set_status(session, cell.id, "confirmed")
    h = graph.create_hypothesis(session, t.id, "idor -> account takeover", member_cells=[cell.id])
    graph.set_status(session, h.id, "validated")
    graph.set_status(session, h.id, "confirmed")

    f = findings.promote_hypothesis(session, h.id)
    assert f.title == "idor -> account takeover"
    assert "GET /items" in json.loads(f.endpoints_json)
    assert f.cvss_score is not None


def test_promote_missing(session):
    with pytest.raises(ValueError):
        findings.promote_cell(session, 9999)
