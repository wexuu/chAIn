"""Egress chokepoint — the enforcement half of the safety core.

Every NATIVE outbound request goes through send():
  1. Resolve the hostname ONCE, collecting all A + AAAA records.
  2. Validate EVERY resolved address against the ScopePolicy (scope + default
     block-set). If any address fails, refuse — this blocks the "in-scope A +
     out-of-scope AAAA" and split-horizon tricks.
  3. Connect to the PINNED validated IP (correct Host header + TLS SNI). We never
     re-resolve at connect time, which kills the DNS-rebinding TOCTOU.
  4. Redirects are NOT auto-followed; each 3xx Location is re-run through the
     whole check (bounded hops).

Resolver, HTTP client, rate limiter, and audit sink are injected for testing.
Recon/wrapped tools (nmap/ffuf/...) do NOT pass through here — they are gated at
launch + a default-deny firewall (see firewall.py); the plan is explicit on that.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Awaitable, Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .scope import ScopePolicy

REDIRECT_CODES = {301, 302, 303, 307, 308}


class EgressBlocked(Exception):
    def __init__(self, reason: str, ip: Optional[str] = None):
        super().__init__(reason)
        self.reason = reason
        self.ip = ip


async def default_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def _authority(parts) -> str:
    host = parts.hostname or ""
    return f"{host}:{parts.port}" if parts.port else host


async def send(
    *,
    policy: ScopePolicy,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    content: Optional[bytes] = None,
    client: httpx.AsyncClient,
    resolver: Callable[[str], Awaitable[list[str]]] = default_resolver,
    rate_limiter=None,
    audit: Optional[Callable[[dict], None]] = None,
    max_hops: int = 5,
    _hops: Optional[int] = None,
) -> httpx.Response:
    if _hops is None:
        _hops = max_hops

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise EgressBlocked(f"bad-scheme:{parts.scheme}")
    host = parts.hostname
    if not host:
        raise EgressBlocked("no-host")
    path = parts.path or "/"

    ips = await resolver(host)
    if not ips:
        raise EgressBlocked("no-addresses")

    # Validate every resolved address — not just the one we'll use.
    for ip in ips:
        decision = policy.check(host, ip, path)
        if not decision.allowed:
            if audit:
                audit(
                    {
                        "action": "egress",
                        "egress_decision": "blocked",
                        "resolved_ip": ip,
                        "host": host,
                        "url": url,
                        "reason": decision.reason,
                    }
                )
            raise EgressBlocked(decision.reason, ip)

    pinned = ips[0]
    ip_host = f"[{pinned}]" if ":" in pinned else pinned
    netloc = f"{ip_host}:{parts.port}" if parts.port else ip_host
    pinned_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))

    req_headers = dict(headers or {})
    req_headers["Host"] = _authority(parts)  # preserve the real authority

    async def _do() -> httpx.Response:
        req = client.build_request(method, pinned_url, headers=req_headers, content=content)
        if parts.scheme == "https":
            req.extensions["sni_hostname"] = host  # TLS SNI uses the real hostname
        return await client.send(req, follow_redirects=False)

    if rate_limiter is not None:
        async with rate_limiter.slot():
            resp = await _do()
    else:
        resp = await _do()

    if audit:
        audit(
            {
                "action": "egress",
                "egress_decision": "allowed",
                "resolved_ip": pinned,
                "host": host,
                "url": url,
            }
        )

    if resp.status_code in REDIRECT_CODES and _hops > 0:
        location = resp.headers.get("location")
        if location:
            await resp.aread()
            new_url = urljoin(url, location)  # resolve against the logical (hostname) URL
            new_method = "GET" if resp.status_code == 303 else method
            new_content = None if resp.status_code == 303 else content
            return await send(
                policy=policy,
                method=new_method,
                url=new_url,
                headers=headers,
                content=new_content,
                client=client,
                resolver=resolver,
                rate_limiter=rate_limiter,
                audit=audit,
                max_hops=max_hops,
                _hops=_hops - 1,
            )
    return resp
