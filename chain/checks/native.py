"""The five native probes. Each returns a CheckResult; state-changing probes
raise DestructiveBlocked unless the target opted in.
"""

from __future__ import annotations

import json

from .base import (
    SAFE_METHODS,
    STATE_METHODS,
    CheckContext,
    CheckResult,
    DestructiveBlocked,
    build_url,
    record_attempt,
)

_SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "x-frame-options",
)
_REFLECTION_MARKER = "chAInRx9z1q"


async def method_tampering(ctx: CheckContext) -> CheckResult:
    url = build_url(ctx.session, ctx.endpoint)
    base_method = ctx.endpoint.method.upper()
    methods = list(SAFE_METHODS) + (list(STATE_METHODS) if ctx.destructive_allowed else [])
    tried = []
    candidate = False
    for m in methods:
        if m == base_method:
            continue
        resp = await ctx.send(m, url)
        destructive = m in STATE_METHODS
        hit = resp.status_code in (200, 201, 202, 204)
        record_attempt(
            ctx,
            method=m,
            url=url,
            req_headers=None,
            response=resp,
            auth_profile_id=None,
            destructive=destructive,
            verdict=("accepted" if hit else None),
        )
        tried.append(f"{m}->{resp.status_code}")
        if hit:
            candidate = True
    summary = ", ".join(tried) if tried else "no alternate methods tried"
    if candidate:
        return CheckResult("candidate", f"unexpected method accepted ({summary})", scope_note=summary)
    return CheckResult("tested_negative", f"no unexpected method accepted ({summary})", scope_note=summary)


async def headers_cors(ctx: CheckContext) -> CheckResult:
    url = build_url(ctx.session, ctx.endpoint)
    resp = await ctx.send("GET", url)
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in _SECURITY_HEADERS if h not in hdrs]
    issues = list(missing)
    if hdrs.get("access-control-allow-origin") == "*" and hdrs.get(
        "access-control-allow-credentials", ""
    ).lower() == "true":
        issues.append("ACAO:* with credentials")
    record_attempt(
        ctx,
        method="GET",
        url=url,
        req_headers=None,
        response=resp,
        auth_profile_id=None,
        destructive=False,
        verdict=("issues" if issues else "clean"),
    )
    note = f"missing/weak: {', '.join(issues)}" if issues else "all checked headers present; CORS ok"
    if issues:
        return CheckResult("candidate", note, scope_note=note)
    return CheckResult("tested_negative", note, scope_note=note)


async def reflection(ctx: CheckContext) -> CheckResult:
    param = ctx.cell.param_name
    method = ctx.endpoint.method.upper()
    destructive = method not in SAFE_METHODS
    if destructive and not ctx.destructive_allowed:
        raise DestructiveBlocked(f"{method} is state-changing; reflection probe needs destructive opt-in")
    extra = {param: _REFLECTION_MARKER} if param else None
    url = build_url(ctx.session, ctx.endpoint, extra_query=extra)
    resp = await ctx.send(method, url)
    reflected = _REFLECTION_MARKER in (resp.text or "")
    record_attempt(
        ctx,
        method=method,
        url=url,
        req_headers=None,
        response=resp,
        auth_profile_id=None,
        destructive=destructive,
        verdict=("reflected" if reflected else None),
    )
    tag = f"param '{param}'" if param else "request"
    if reflected:
        return CheckResult("candidate", f"{tag} reflected unencoded in response")
    return CheckResult("tested_negative", f"{tag} marker not reflected")


async def authz_idor(ctx: CheckContext) -> CheckResult:
    others = [(n, p) for n, p in ctx.auth_profiles.items() if n != "primary"]
    if not others:
        return CheckResult(None, "no secondary auth profile to replay as (add one to test)")
    method = ctx.endpoint.method.upper()
    destructive = method not in SAFE_METHODS
    if destructive and not ctx.destructive_allowed:
        raise DestructiveBlocked(f"{method} replay is state-changing; needs destructive opt-in")
    name, profile = others[0]
    url = build_url(ctx.session, ctx.endpoint)
    resp = await ctx.send(method, url, profile=profile)
    record_attempt(
        ctx,
        method=method,
        url=url,
        req_headers=None,
        response=resp,
        auth_profile_id=profile.id,
        destructive=destructive,
        verdict=("reachable" if resp.status_code in (200, 201) else None),
    )
    if resp.status_code in (200, 201):
        return CheckResult("candidate", f"resource reachable as '{name}' (status {resp.status_code})")
    return CheckResult("tested_negative", f"not reachable as '{name}' (status {resp.status_code})")


async def mass_assignment(ctx: CheckContext) -> CheckResult:
    if not ctx.destructive_allowed:
        raise DestructiveBlocked("mass-assignment sends a write; requires destructive opt-in")
    method = ctx.endpoint.method.upper()
    if method not in STATE_METHODS:
        method = "POST"
    url = build_url(ctx.session, ctx.endpoint)
    injected = "chain_injected_role"
    body = json.dumps({injected: "admin"}).encode()
    resp = await ctx.send(method, url, headers={"Content-Type": "application/json"}, content=body)
    accepted = resp.status_code in (200, 201) and injected in (resp.text or "")
    record_attempt(
        ctx,
        method=method,
        url=url,
        req_headers={"Content-Type": "application/json"},
        response=resp,
        auth_profile_id=None,
        destructive=True,
        verdict=("accepted" if accepted else None),
    )
    if accepted:
        return CheckResult("candidate", f"injected field '{injected}' echoed back (status {resp.status_code})")
    return CheckResult("tested_negative", f"injected field not reflected (status {resp.status_code})")
