"""Redaction for external boundaries (MCP reads, exports).

Local storage is unencrypted on the trusted VM, but anything leaving the box —
to an agent's model provider, or into a shareable report — gets secrets stripped.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy.orm import Session

from .models import AuthProfile

REDACT_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}
PLACEHOLDER = "[REDACTED]"


def redact_headers(headers: dict) -> dict:
    return {k: (PLACEHOLDER if k.lower() in REDACT_HEADER_NAMES else v) for k, v in headers.items()}


def redact_text(text: str, secrets: Iterable[str]) -> str:
    if not text:
        return text
    for sv in secrets:
        if sv:
            text = text.replace(sv, PLACEHOLDER)
    return text


def target_secrets(session: Session, target_id: int) -> list[str]:
    """Known secret strings for a target (profile tokens/cookies) to scrub from text."""
    out = []
    for p in session.query(AuthProfile).filter_by(target_id=target_id).all():
        if p.secret:
            out.append(p.secret)
    return out
