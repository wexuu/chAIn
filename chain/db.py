"""SQLite engine/session wiring. Source of truth; stored unencrypted on the
trusted VM (markdown/JSON are exports, built later).
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base


def make_engine(url: str | None = None) -> Engine:
    url = url or f"sqlite:///{settings.db_path}"
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, echo=False, future=True, connect_args=connect_args)


_engine: Engine | None = None
_Session: sessionmaker | None = None


def init(url: str | None = None) -> Engine:
    """Create the engine, build the schema, and prepare the session factory."""
    global _engine, _Session
    _engine = make_engine(url)
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
    return _engine


def ensure(url: str | None = None) -> Engine:
    """Initialize once; a no-op if already initialized (lets tests inject a DB)."""
    if _Session is None:
        init(url)
    assert _engine is not None
    return _engine


def session() -> Session:
    if _Session is None:
        init()
    assert _Session is not None
    return _Session()
