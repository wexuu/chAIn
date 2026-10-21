"""Evidence store: blobs on the filesystem behind an Evidence row.

Stored unencrypted on the trusted VM (owner decision); redaction happens only
at external boundaries (MCP reads / exports), not here. Size-capped + truncated.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from typing import Optional

from sqlalchemy.orm import Session

from .config import settings
from .models import Evidence


def store_blob(
    session: Session,
    target_id: int,
    kind: str,
    data,
    *,
    content_type: str = "text/plain",
    evidence_dir: Optional[str] = None,
    max_bytes: Optional[int] = None,
) -> Evidence:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    max_bytes = max_bytes or settings.evidence_max_bytes
    truncated = False
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True

    evidence_dir = evidence_dir or settings.evidence_dir
    target_dir = os.path.join(evidence_dir, str(target_id))
    os.makedirs(target_dir, exist_ok=True)
    sha = hashlib.sha256(data).hexdigest()
    path = os.path.join(target_dir, f"{sha}.bin")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)

    retain_until = None
    if settings.evidence_retention_days:
        retain_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            days=settings.evidence_retention_days
        )

    ev = Evidence(
        target_id=target_id,
        kind=kind,
        storage="fs",
        path=path,
        content_type=content_type,
        size_bytes=len(data),
        sha256=sha,
        truncated=truncated,
        retain_until=retain_until,
    )
    session.add(ev)
    session.flush()
    return ev
