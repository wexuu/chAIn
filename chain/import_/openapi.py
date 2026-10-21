"""OpenAPI/Swagger parser → (hosts, operations). JSON natively; YAML if pyyaml."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _load(spec):
    if isinstance(spec, dict):
        return spec
    s = spec.strip()
    if s.startswith("{"):
        return json.loads(s)
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ValueError("YAML OpenAPI spec requires pyyaml") from exc
    return yaml.safe_load(s)


def _params(plist) -> list[str]:
    out = []
    for p in plist or []:
        if isinstance(p, dict) and p.get("in") in ("query", "path") and p.get("name"):
            out.append(p["name"])
    return out


def _body_fields(request_body) -> list[str]:
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content", {})
    for ct in ("application/json", "application/x-www-form-urlencoded"):
        schema = content.get(ct, {}).get("schema", {})
        props = schema.get("properties")
        if isinstance(props, dict):
            return list(props.keys())
    return []


def parse_openapi(spec) -> tuple[list[str], list[dict]]:
    doc = _load(spec)
    if not isinstance(doc, dict):
        raise ValueError("not an OpenAPI document")

    hosts = []
    for srv in doc.get("servers", []) or []:
        host = urlsplit(srv.get("url", "")).hostname
        if host and host not in hosts:
            hosts.append(host)
    # Swagger 2.0 fallback
    if not hosts and doc.get("host"):
        hosts.append(str(doc["host"]).split(":")[0])

    ops = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        base = _params(item.get("parameters", []))
        for method, op in item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            params = base + _params(op.get("parameters", []))
            ops.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "params": sorted(set(params)),
                    "body_fields": sorted(set(_body_fields(op.get("requestBody")))),
                }
            )
    return hosts, ops
