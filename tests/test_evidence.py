import pytest

from chain import db, evidence
from chain.models import Evidence, Target


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path/'e.db'}")
    s = db.session()
    yield s
    s.close()


def _target(s):
    t = Target(name="t")
    s.add(t)
    s.commit()
    return t.id


def test_store_blob_writes_file_and_row(session, tmp_path):
    tid = _target(session)
    ev = evidence.store_blob(session, tid, "response", "hello world", evidence_dir=str(tmp_path / "ev"))
    session.commit()
    assert ev.size_bytes == 11
    assert ev.truncated is False
    import os

    assert os.path.exists(ev.path)
    assert session.query(Evidence).count() == 1


def test_store_blob_truncates_over_cap(session, tmp_path):
    tid = _target(session)
    big = "A" * 100
    ev = evidence.store_blob(
        session, tid, "response", big, evidence_dir=str(tmp_path / "ev"), max_bytes=10
    )
    assert ev.truncated is True
    assert ev.size_bytes == 10


def test_store_blob_dedupes_identical_content(session, tmp_path):
    tid = _target(session)
    d = str(tmp_path / "ev")
    e1 = evidence.store_blob(session, tid, "response", "same", evidence_dir=d)
    e2 = evidence.store_blob(session, tid, "response", "same", evidence_dir=d)
    assert e1.sha256 == e2.sha256
    assert e1.path == e2.path  # same file on disk, reused
