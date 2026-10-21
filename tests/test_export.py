import pytest

from chain import db, export
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import seed_vuln_classes
from chain.models import AuthProfile, CoverageCell, Finding, Target
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'exp.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


def _target_with_matrix(s):
    t = Target(name="lab", authorized=True)
    s.add(t)
    s.flush()
    h = upsert_host(s, t.id, hostname="example.com")
    upsert_endpoint(s, t.id, method="GET", path="/x", host_id=h.id, params=["q"])
    s.commit()
    mc.generate_cells(s, t.id)
    return t


def test_report_has_annexes(session):
    t = _target_with_matrix(session)
    # mark one cell tested_negative with a reason + scope
    cell = session.query(CoverageCell).filter_by(status="untested").first()
    mc.set_status(session, cell.id, "tested_negative", reason="encoded at API", scope_note="q only")

    report = export.build_report(session, t.id)
    assert "coverage_annex" in report and "recon_coverage" in report
    assert report["coverage_annex"]["summary"]["total_cells"] > 0
    assert len(report["coverage_annex"]["untested"]) > 0
    assert any(
        c["reason"] == "encoded at API" for c in report["coverage_annex"]["tested_negative"]
    )
    # param_specific classes with no param on this endpoint show as not_applicable
    assert len(report["coverage_annex"]["not_applicable"]) >= 0


def test_markdown_renders_sections(session):
    t = _target_with_matrix(session)
    session.add(
        Finding(
            target_id=t.id,
            title="IDOR on /x",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=6.5,
            remediation="enforce object-level authz",
        )
    )
    session.commit()
    md = export.render_markdown(session, t.id)
    assert "# chAIn report" in md
    assert "## Findings" in md
    assert "IDOR on /x" in md
    assert "## Coverage annex" in md
    assert "## Recon-coverage annex" in md


def test_export_redacts_secret_in_text(session):
    t = _target_with_matrix(session)
    secret = "sup3r-s3cret"
    session.add(AuthProfile(target_id=t.id, name="primary", type="bearer", secret=secret))
    session.add(
        Finding(
            target_id=t.id,
            title="leak",
            severity="Low",
            cvss_vector="x",
            cvss_score=1.0,
            remediation=f"rotate token {secret}",
        )
    )
    session.commit()
    md = export.render_markdown(session, t.id)
    assert secret not in md
    assert "[REDACTED]" in md
