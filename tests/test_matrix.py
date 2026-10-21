import pytest

from chain import db
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import VULN_CLASSES, seed_vuln_classes
from chain.models import CoverageCell, Endpoint, Target, VulnClass
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'m.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


def _target_with_endpoints(s):
    t = Target(name="t")
    s.add(t)
    s.flush()
    h = upsert_host(s, t.id, hostname="example.com")
    # one endpoint with params, one without
    upsert_endpoint(s, t.id, method="GET", path="/search", host_id=h.id, params=["q", "page"])
    upsert_endpoint(s, t.id, method="GET", path="/health", host_id=h.id)
    s.commit()
    return t.id


def test_seed_is_idempotent(session):
    before = session.query(VulnClass).count()
    assert before == len(VULN_CLASSES)
    assert seed_vuln_classes(session) == 0  # nothing new
    assert session.query(VulnClass).count() == before


def test_generate_cells_param_specific_expansion(session):
    tid = _target_with_endpoints(session)
    mc.generate_cells(session, tid)

    n_classes = session.query(VulnClass).count()
    n_param_specific = session.query(VulnClass).filter_by(param_specific=True).count()
    n_flat = n_classes - n_param_specific

    # /search has 2 params -> each param_specific class yields 2 cells; flat classes yield 1.
    search = session.query(Endpoint).filter_by(path="/search").first()
    search_cells = session.query(CoverageCell).filter_by(endpoint_id=search.id).count()
    assert search_cells == n_param_specific * 2 + n_flat

    # /health has no params -> param_specific classes become a single not_applicable cell.
    health = session.query(Endpoint).filter_by(path="/health").first()
    na = (
        session.query(CoverageCell)
        .filter_by(endpoint_id=health.id, status="not_applicable")
        .count()
    )
    assert na == n_param_specific


def test_generate_is_idempotent(session):
    tid = _target_with_endpoints(session)
    first = mc.generate_cells(session, tid)
    second = mc.generate_cells(session, tid)
    assert first > 0
    assert second == 0  # nothing new on a re-generate


def test_empty_cell_is_untested_not_pass(session):
    tid = _target_with_endpoints(session)
    mc.generate_cells(session, tid)
    search = session.query(Endpoint).filter_by(path="/search").first()
    sqli_cells = (
        session.query(CoverageCell)
        .join(VulnClass, CoverageCell.vuln_class_id == VulnClass.id)
        .filter(CoverageCell.endpoint_id == search.id, VulnClass.key == "sqli")
        .all()
    )
    assert len(sqli_cells) == 2  # per-param
    assert all(c.status == "untested" for c in sqli_cells)


def test_status_edit_requires_reason(session):
    tid = _target_with_endpoints(session)
    mc.generate_cells(session, tid)
    cell = session.query(CoverageCell).first()

    with pytest.raises(mc.ReasonRequired):
        mc.set_status(session, cell.id, "tested_negative")
    with pytest.raises(mc.ReasonRequired):
        mc.set_status(session, cell.id, "not_applicable", reason="   ")
    with pytest.raises(mc.InvalidStatus):
        mc.set_status(session, cell.id, "bogus")

    ok = mc.set_status(session, cell.id, "tested_negative", reason="output HTML-encoded at the API")
    assert ok.status == "tested_negative"
    # candidate/confirmed don't require a reason
    ok2 = mc.set_status(session, cell.id, "candidate")
    assert ok2.status == "candidate"


def test_matrix_summary_coverage(session):
    tid = _target_with_endpoints(session)
    mc.generate_cells(session, tid)
    m = mc.get_matrix(session, tid)
    assert m["summary"]["total_cells"] > 0
    assert m["summary"]["coverage_pct"] == 0.0  # nothing tested yet
    # confirm one cell -> coverage rises
    cell = session.query(CoverageCell).filter_by(status="untested").first()
    mc.set_status(session, cell.id, "confirmed")
    m2 = mc.get_matrix(session, tid)
    assert m2["summary"]["covered"] == 1
    assert m2["summary"]["coverage_pct"] > 0.0
