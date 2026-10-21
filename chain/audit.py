"""Audit log helper — every mutation, egress decision, and destructive action."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .models import AuditLog


def record(
    session: Session,
    *,
    action: str,
    actor: str = "human",
    target_id: Optional[int] = None,
    ref: Optional[str] = None,
    egress_decision: Optional[str] = None,
    resolved_ip: Optional[str] = None,
    destructive: bool = False,
) -> AuditLog:
    row = AuditLog(
        action=action,
        actor=actor,
        target_id=target_id,
        ref=ref,
        egress_decision=egress_decision,
        resolved_ip=resolved_ip,
        destructive=destructive,
    )
    session.add(row)
    session.commit()
    return row
