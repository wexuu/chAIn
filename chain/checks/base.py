"""Shared check scaffolding: context, result, URL/auth helpers, attempt recorder."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from .. import evidence
from ..models import Attempt, AuthProfile, CoverageCell, Endpoint, Host, Request

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# send_fn(method, url, headers=?, content=?, profile=?) -> httpx.Response
SendFn = Callable[..., Awaitable]


class DestructiveBlocked(Exception):
    """Raised when a state-changing check is attempted without destructive opt-in."""


@dataclass
class CheckResult:
    status: Optional[str]  # None = ran but inconclusive (leave cell unchanged)
    reason: str
    scope_note: Optional[str] = None


@dataclass
class CheckContext:
    session: Session
    target: object
    endpoint: Endpoint
    cell: CoverageCell
    send: SendFn
    auth_profiles: dict  # name -> AuthProfile
    destructive_allowed: bool
    evidence_dir: Optional[str] = None


def build_url(session: Session, endpoint: Endpoint, extra_query: Optional[dict] = None) -> str:
    host = None
    if endpoint.host_id:
        h = session.get(Host, endpoint.host_id)
        if h is not None:
            host = h.hostname or h.ip
    host = host or "localhost"
    url = f"https://{host}{endpoint.path}"
    if extra_query:
        url += ("&" if "?" in url else "?") + urlencode(extra_query)
    return url


def apply_auth(headers: dict, profile: Optional[AuthProfile]) -> dict:
    if profile is None:
        return headers
    if profile.type == "bearer" and profile.secret:
        headers["Authorization"] = f"Bearer {profile.secret}"
    elif profile.type == "basic" and profile.secret:
        token = base64.b64encode(profile.secret.encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    elif profile.type == "cookie" and profile.secret:
        headers["Cookie"] = profile.secret
    if profile.headers_json:
        try:
            headers.update(json.loads(profile.headers_json))
        except json.JSONDecodeError:
            pass
    return headers


def record_attempt(
    ctx: CheckContext,
    *,
    method: str,
    url: str,
    req_headers: Optional[dict],
    response,
    auth_profile_id: Optional[int],
    destructive: bool,
    verdict: Optional[str],
) -> Attempt:
    s = ctx.session
    body = response.text if response is not None else ""
    ev = evidence.store_blob(
        s, ctx.target.id, "response", body, evidence_dir=ctx.evidence_dir
    )
    req = Request(
        target_id=ctx.target.id,
        endpoint_id=ctx.cell.endpoint_id,
        method=method,
        url=url,
        headers_json=json.dumps(req_headers or {}),
        auth_profile_id=auth_profile_id,
    )
    s.add(req)
    s.flush()
    att = Attempt(
        cell_id=ctx.cell.id,
        request_id=req.id,
        auth_profile_id=auth_profile_id,
        response_status=(response.status_code if response is not None else None),
        response_ref=str(ev.id),
        verdict=verdict,
        destructive=destructive,
        evidence_ref=ev.path,
    )
    s.add(att)
    s.flush()
    return att
