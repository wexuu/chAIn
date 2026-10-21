"""HAR parser → (hosts, operations) from recorded request traffic."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit


def _body_fields(request: dict) -> list[str]:
    pd = request.get("postData")
    if not isinstance(pd, dict):
        return []
    if pd.get("params"):
        return [p.get("name") for p in pd["params"] if isinstance(p, dict) and p.get("name")]
    text = pd.get("text")
    if text:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return list(obj.keys())
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def parse_har(har) -> tuple[list[str], list[dict]]:
    doc = har if isinstance(har, dict) else json.loads(har)
    entries = (doc.get("log") or {}).get("entries", []) if isinstance(doc, dict) else []

    hosts: list[str] = []
    ops: list[dict] = []
    for entry in entries:
        req = entry.get("request", {}) if isinstance(entry, dict) else {}
        url = req.get("url", "")
        parts = urlsplit(url)
        if parts.hostname and parts.hostname not in hosts:
            hosts.append(parts.hostname)
        params = [q.get("name") for q in req.get("queryString", []) if isinstance(q, dict) and q.get("name")]
        if not params and parts.query:
            params = list(parse_qs(parts.query).keys())
        ops.append(
            {
                "method": (req.get("method") or "GET").upper(),
                "path": parts.path or "/",
                "params": sorted(set(p for p in params if p)),
                "body_fields": sorted(set(_body_fields(req))),
            }
        )
    return hosts, ops
