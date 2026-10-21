import json

import pytest

from chain import db
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import seed_vuln_classes
from chain.mcp import tools
from chain.models import (
    Attempt,
    AuditLog,
    AuthProfile,
    CoverageCell,
    Hypothesis,
    Request,
    Target,
)
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'mcp.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


def _surface(s):
    t = Target(name="t", authorized=True)
    s.add(t)
    s.flush()
    h = upsert_host(s, t.id, hostname="example.com")
    ep = upsert_endpoint(s, t.id, method="GET", path="/x", host_id=h.id, params=["q"])
    s.commit()
    mc.generate_cells(s, t.id)
    return t, ep


def test_generate_rows_and_matrix(session):
    t, ep = _surface(session)
    # cells already generated above; regenerate yields 0 new
    out = tools.generate_rows(session, t.id)
    assert out["created"] == 0
    m = tools.get_matrix(session, t.id)
    assert len(m["columns"]) == 13


def test_propose_chain_lands_proposed_from_agent(session):
    t, _ = _surface(session)
    out = tools.propose_chain(session, t.id, "idor -> takeover", member_cells=[1])
    assert out["status"] == "proposed"
    assert out["origin"] == "agent:mcp"
    hyp = session.query(Hypothesis).first()
    assert hyp.origin == "agent:mcp" and hyp.status == "proposed"


def test_suggest_candidate_only_sets_candidate(session):
    t, ep = _surface(session)
    cell = session.query(CoverageCell).first()
    out = tools.suggest_candidate(session, cell.id, "reflected marker seen")
    assert out["status"] == "candidate"
    session.refresh(cell)
    assert cell.status == "candidate"
    assert cell.reason.startswith("[agent]")


def test_enrich_endpoint_merges_params(session):
    t, ep = _surface(session)
    out = tools.enrich_endpoint(session, ep.id, params=["page"])
    assert sorted(out["params"]) == ["page", "q"]


def test_writes_are_audited_as_agent(session):
    t, ep = _surface(session)
    tools.propose_chain(session, t.id, "c")
    tools.suggest_candidate(session, session.query(CoverageCell).first().id, "x")
    agent_actions = session.query(AuditLog).filter_by(actor="agent:mcp").count()
    assert agent_actions >= 2


def test_get_cell_redacts_secrets(session):
    t, ep = _surface(session)
    secret = "s3cr3t-token"
    session.add(AuthProfile(target_id=t.id, name="primary", type="bearer", secret=secret))
    cell = session.query(CoverageCell).first()
    req = Request(
        target_id=t.id,
        endpoint_id=ep.id,
        method="GET",
        url=f"https://example.com/x?token={secret}",
        headers_json=json.dumps({"Authorization": f"Bearer {secret}", "Accept": "*/*"}),
    )
    session.add(req)
    session.flush()
    session.add(Attempt(cell_id=cell.id, request_id=req.id, response_status=200, verdict="x"))
    session.commit()

    out = tools.get_cell(session, cell.id)
    att = out["attempts"][0]
    assert secret not in att["url"]  # secret scrubbed from the URL
    assert att["headers"]["Authorization"] == "[REDACTED]"
    assert att["headers"]["Accept"] == "*/*"  # non-secret header preserved


def test_no_tool_can_confirm_or_promote(session):
    # The public tool surface has no confirm/promote capability.
    names = set(dir(tools))
    assert "confirm_finding" not in names
    assert "promote_chain" not in names
    assert "set_cell_status" not in names


def test_build_server_constructs():
    from chain.mcp.server import build_server

    server = build_server()
    assert server is not None
    assert server.name == "chAIn"
