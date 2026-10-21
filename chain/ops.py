"""Operational hardening: external-tool preflight and evidence retention reaper."""

from __future__ import annotations

import datetime as dt
import os
import shutil
from typing import Optional

from sqlalchemy.orm import Session

from .config import settings
from .models import Evidence

# External tools chAIn can drive (recon + wrapped checks).
KNOWN_TOOLS = ["nmap", "httpx", "ffuf", "katana", "subfinder", "sqlmap", "dalfox", "nuclei", "nft"]


def tool_preflight() -> dict:
    """Which external tools are installed on this host?"""
    tools = {name: shutil.which(name) is not None for name in KNOWN_TOOLS}
    return {
        "tools": tools,
        "missing": sorted(n for n, present in tools.items() if not present),
        "firewall_apply_enabled": settings.firewall_apply_enabled,
    }


def reap_evidence(session: Session, now: Optional[dt.datetime] = None) -> int:
    """Delete evidence rows (and their files) whose retain_until has passed."""
    now = now or dt.datetime.now(dt.timezone.utc)
    reaped = 0
    rows = session.query(Evidence).filter(Evidence.retain_until.isnot(None)).all()
    for ev in rows:
        ru = ev.retain_until
        if ru is not None and ru.tzinfo is None:
            ru = ru.replace(tzinfo=dt.timezone.utc)
        if ru is not None and ru <= now:
            try:
                if ev.path and os.path.exists(ev.path):
                    os.remove(ev.path)
            except OSError:
                pass
            session.delete(ev)
            reaped += 1
    session.commit()
    return reaped
