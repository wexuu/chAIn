import json

import httpx
import pytest

from chain import db
from chain.models import SequenceRun, StepSequence, Target
from chain.sequences import runner as sr


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'seq.db'}")
    s = db.session()
    yield s
    s.close()


def test_substitute():
    assert sr.substitute("/orders/{{oid}}", {"oid": "42"}) == "/orders/42"
    assert sr.substitute({"X": "{{tok}}"}, {"tok": "abc"}) == {"X": "abc"}
    assert sr.substitute("/no/vars", {}) == "/no/vars"


def test_extract_json_regex_header():
    resp = httpx.Response(200, json={"data": {"id": 7}}, headers={"X-Token": "zzz"})
    assert sr.extract({"kind": "json", "expr": "data.id"}, resp) == "7"
    assert sr.extract({"kind": "header", "expr": "X-Token"}, resp) == "zzz"
    resp2 = httpx.Response(200, text="order=99;")
    assert sr.extract({"kind": "regex", "expr": r"order=(\d+)"}, resp2) == "99"
    assert sr.extract({"kind": "json", "expr": "missing.key"}, resp) is None


class FakeSend:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    async def __call__(self, method, url, *, headers=None, content=None, profile=None):
        self.calls.append((method, url))
        return self.responder(method, url)


def _seq(s, steps):
    t = Target(name="t")
    s.add(t)
    s.flush()
    seq = StepSequence(target_id=t.id, name="flow", steps_json=json.dumps(steps))
    s.add(seq)
    s.commit()
    return seq


async def test_capture_flows_between_steps(session):
    steps = [
        {
            "name": "create order",
            "method": "POST",
            "path": "/orders",
            "body": {"item": "x"},
            "captures": [{"name": "oid", "kind": "json", "expr": "id"}],
        },
        {"name": "read as victim", "method": "GET", "path": "/orders/{{oid}}"},
    ]
    seq = _seq(session, steps)

    def responder(method, url):
        if url.endswith("/orders"):
            return httpx.Response(201, json={"id": 42})
        return httpx.Response(200, json={"owner": "victim"})

    send = FakeSend(responder)
    run = await sr.run_sequence(session, seq, send_fn=send, host="box.htb")
    assert run.status == "done"
    # step 2's URL carried the captured id
    assert send.calls[1] == ("GET", "https://box.htb/orders/42")
    results = json.loads(run.results_json)
    assert results["vars"]["oid"] == "42"
    assert session.query(SequenceRun).count() == 1


async def test_run_records_error_and_stops(session):
    seq = _seq(session, [{"method": "GET", "path": "/a"}, {"method": "GET", "path": "/b"}])

    def responder(method, url):
        if url.endswith("/a"):
            raise RuntimeError("boom")
        return httpx.Response(200)

    run = await sr.run_sequence(session, seq, send_fn=FakeSend(responder), host="h")
    assert run.status == "error"
    results = json.loads(run.results_json)
    assert "error" in results["steps"][0]
    assert len(results["steps"]) == 1  # stopped after the failing step
