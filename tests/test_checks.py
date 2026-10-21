import httpx
import pytest

from chain import db
from chain.checks import runner as cr
from chain.matrix import cells as mc
from chain.matrix.vulnclasses import seed_vuln_classes
from chain.models import Attempt, AuthProfile, CoverageCell, Target, VulnClass
from chain.recon.inventory import upsert_endpoint, upsert_host


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'c.db'}")
    s = db.session()
    seed_vuln_classes(s)
    yield s
    s.close()


class FakeSend:
    """send_fn stub; `responder(method, url, profile)` returns an httpx.Response."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    async def __call__(self, method, url, *, headers=None, content=None, profile=None):
        self.calls.append((method, url, getattr(profile, "name", None)))
        return self.responder(method, url, profile)


def _endpoint(s, method="GET", path="/x", params=None):
    t = Target(name="t", authorized=True)
    s.add(t)
    s.flush()
    h = upsert_host(s, t.id, hostname="example.com")
    ep = upsert_endpoint(s, t.id, method=method, path=path, host_id=h.id, params=params)
    s.commit()
    return t, ep


def _cell(s, ep, vc_key, param=None):
    mc.generate_cells(s, ep.target_id)
    q = (
        s.query(CoverageCell)
        .join(VulnClass, CoverageCell.vuln_class_id == VulnClass.id)
        .filter(CoverageCell.endpoint_id == ep.id, VulnClass.key == vc_key)
    )
    if param is not None:
        q = q.filter(CoverageCell.param_name == param)
    return q.first()


async def test_method_tampering_candidate(session, tmp_path):
    t, ep = _endpoint(session)
    cell = _cell(session, ep, "method_tampering")

    def responder(method, url, profile):
        return httpx.Response(200 if method == "OPTIONS" else 405, text="")

    send = FakeSend(responder)
    out = await cr.run_check(session, cell, send_fn=send, evidence_dir=str(tmp_path))
    assert out["status"] == "candidate"
    session.refresh(cell)
    assert cell.status == "candidate"
    # attempts recorded for the alternate methods (HEAD, OPTIONS)
    assert session.query(Attempt).filter_by(cell_id=cell.id).count() == 2


async def test_method_tampering_negative(session, tmp_path):
    t, ep = _endpoint(session)
    cell = _cell(session, ep, "method_tampering")
    send = FakeSend(lambda m, u, p: httpx.Response(405, text=""))
    out = await cr.run_check(session, cell, send_fn=send, evidence_dir=str(tmp_path))
    assert out["status"] == "tested_negative"


async def test_headers_candidate_and_clean(session, tmp_path):
    t, ep = _endpoint(session)
    cell = _cell(session, ep, "headers_cors")

    send_missing = FakeSend(lambda m, u, p: httpx.Response(200, headers={}, text=""))
    out = await cr.run_check(session, cell, send_fn=send_missing, evidence_dir=str(tmp_path))
    assert out["status"] == "candidate"

    # reset and test the clean case
    cell.status = "untested"
    session.commit()
    good_headers = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=63072000",
        "x-frame-options": "DENY",
    }
    send_clean = FakeSend(lambda m, u, p: httpx.Response(200, headers=good_headers, text=""))
    out2 = await cr.run_check(session, cell, send_fn=send_clean, evidence_dir=str(tmp_path))
    assert out2["status"] == "tested_negative"


async def test_reflection_candidate(session, tmp_path):
    t, ep = _endpoint(session, params=["q"])
    cell = _cell(session, ep, "xss", param="q")

    def responder(method, url, profile):
        marker = "chAInRx9z1q"
        return httpx.Response(200, text=f"<p>{marker}</p>" if marker in url else "clean")

    out = await cr.run_check(session, cell, send_fn=FakeSend(responder), evidence_dir=str(tmp_path))
    assert out["status"] == "candidate"


async def test_authz_candidate_with_secondary_profile(session, tmp_path):
    t, ep = _endpoint(session)
    cell = _cell(session, ep, "authz_idor")
    session.add(AuthProfile(target_id=t.id, name="primary", type="bearer", secret="a"))
    session.add(AuthProfile(target_id=t.id, name="victim", type="bearer", secret="b"))
    session.commit()
    profiles = {p.name: p for p in session.query(AuthProfile).all()}

    send = FakeSend(lambda m, u, p: httpx.Response(200, text="secret data"))
    out = await cr.run_check(
        session, cell, send_fn=send, auth_profiles=profiles, evidence_dir=str(tmp_path)
    )
    assert out["status"] == "candidate"
    assert ("GET", "https://example.com/x", "victim") in send.calls


async def test_authz_inconclusive_without_secondary(session, tmp_path):
    t, ep = _endpoint(session)
    cell = _cell(session, ep, "authz_idor")
    out = await cr.run_check(session, cell, send_fn=FakeSend(lambda m, u, p: httpx.Response(200)),
                             evidence_dir=str(tmp_path))
    assert out["status"] is None  # no change to the cell
    session.refresh(cell)
    assert cell.status == "untested"


async def test_mass_assignment_blocked_without_optin(session, tmp_path):
    t, ep = _endpoint(session, method="POST", path="/users", params=["name"])
    cell = _cell(session, ep, "mass_assignment", param="name")
    send = FakeSend(lambda m, u, p: httpx.Response(200, text="chain_injected_role"))
    out = await cr.run_check(session, cell, send_fn=send, evidence_dir=str(tmp_path))
    assert out["ran"] is False and out["skipped"] is True
    assert send.calls == []  # nothing sent
    session.refresh(cell)
    assert cell.status == "untested"


async def test_mass_assignment_runs_with_optin(session, tmp_path):
    t, ep = _endpoint(session, method="POST", path="/users", params=["name"])
    t.destructive_opt_in = True
    session.commit()
    cell = _cell(session, ep, "mass_assignment", param="name")
    send = FakeSend(lambda m, u, p: httpx.Response(201, text='{"chain_injected_role":"admin"}'))
    out = await cr.run_check(session, cell, send_fn=send, evidence_dir=str(tmp_path))
    assert out["status"] == "candidate"
    att = session.query(Attempt).filter_by(cell_id=cell.id).first()
    assert att.destructive is True
