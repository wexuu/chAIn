"""SQLite engine/session wiring. Source of truth; stored unencrypted on the
trusted VM (markdown/JSON are exports, built later).
"""

from __future__ import annotations

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base


def make_engine(url: str | None = None) -> Engine:
    url = url or f"sqlite:///{settings.db_path}"
    is_sqlite = url.startswith("sqlite")
    connect_args = {"check_same_thread": False, "timeout": 30} if is_sqlite else {}
    engine = create_engine(url, echo=False, future=True, connect_args=connect_args)
    if is_sqlite:
        # WAL + busy timeout so the background worker and request threads can
        # write concurrently without "database is locked".
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

    return engine


_engine: Engine | None = None
_Session: sessionmaker | None = None


# Additive column migrations for DBs created before a column existed. SQLite's
# create_all only creates missing tables, never alters existing ones.
_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "targets": [("address", "VARCHAR(255)")],
}


def _migrate(engine: Engine) -> None:
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, cols in _MIGRATIONS.items():
            if table not in tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols:
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def init(url: str | None = None) -> Engine:
    """Create the engine, build the schema, and prepare the session factory."""
    global _engine, _Session
    _engine = make_engine(url)
    Base.metadata.create_all(_engine)
    _migrate(_engine)
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
