import pytest

from chain import db
from chain.chains import graph
from chain.models import Target


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'ch.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_create_hypothesis_starts_proposed(session):
    tid = _target(session)
    h = graph.create_hypothesis(session, tid, "mass-assign -> stored XSS", member_cells=[1, 2])
    assert h.status == "proposed"
    assert h.origin == "human"


def test_agent_origin_still_proposed(session):
    tid = _target(session)
    h = graph.create_hypothesis(session, tid, "chain", origin="agent:claude")
    assert h.status == "proposed"
    assert h.origin == "agent:claude"


def test_promotion_path(session):
    tid = _target(session)
    h = graph.create_hypothesis(session, tid, "x")
    graph.set_status(session, h.id, "validated")
    graph.set_status(session, h.id, "confirmed")
    session.refresh(h)
    assert h.status == "confirmed"


def test_illegal_transition_rejected(session):
    tid = _target(session)
    h = graph.create_hypothesis(session, tid, "x")
    # cannot jump proposed -> confirmed
    with pytest.raises(graph.InvalidTransition):
        graph.set_status(session, h.id, "confirmed")
    # cannot advance a confirmed hypothesis
    graph.set_status(session, h.id, "validated")
    graph.set_status(session, h.id, "confirmed")
    with pytest.raises(graph.InvalidTransition):
        graph.set_status(session, h.id, "validated")


def test_reject(session):
    tid = _target(session)
    h = graph.create_hypothesis(session, tid, "x")
    graph.set_status(session, h.id, "rejected")
    with pytest.raises(graph.InvalidTransition):
        graph.set_status(session, h.id, "validated")


def test_add_edge(session):
    tid = _target(session)
    e = graph.add_edge(session, tid, kind="source_to_sink", from_ref="cell:1", to_ref="cell:9")
    assert e.id is not None
    with pytest.raises(ValueError):
        graph.add_edge(session, tid, kind="bogus", from_ref="a", to_ref="b")
    assert len(graph.list_edges(session, tid)) == 1
