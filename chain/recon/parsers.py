"""Deterministic parsers for recon tool output → normalized records.

Pure functions, tolerant of partial/garbage output (return [] on parse error).
These are the source of truth; agent enrichment layers on top later.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

_HTTP_SERVICE_NAMES = {"http", "https", "http-alt", "http-proxy", "https-alt", "ssl/http"}


def _is_http(service_name: str | None, port: int) -> bool:
    n = (service_name or "").lower()
    if n in _HTTP_SERVICE_NAMES or "http" in n:
        return True
    return port in (80, 443, 8080, 8443, 8000, 8888)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Return [{ip, hostname, os_guess, services:[{port,proto,name,product,version,banner,is_http}]}]."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts = []
    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        os_guess = None
        osm = host.find("os/osmatch")
        if osm is not None:
            os_guess = osm.get("name")
        services = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            try:
                portid = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            services.append(
                {
                    "port": portid,
                    "proto": proto,
                    "name": name,
                    "product": product,
                    "version": version,
                    "banner": None,
                    "is_http": _is_http(name, portid),
                }
            )
        hosts.append({"ip": ip, "hostname": hostname, "os_guess": os_guess, "services": services})
    return hosts


def parse_httpx_jsonl(text: str) -> list[dict]:
    """ProjectDiscovery httpx -json (one JSON object per line)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or ""
        parts = urlsplit(url) if url else None
        port = obj.get("port")
        try:
            port = int(port) if port is not None else (parts.port if parts else None)
        except (TypeError, ValueError):
            port = None
        scheme = obj.get("scheme") or (parts.scheme if parts else None)
        if port is None:
            port = 443 if scheme == "https" else 80
        out.append(
            {
                "url": url,
                "host": obj.get("host") or (parts.hostname if parts else None),
                "input_host": parts.hostname if parts else None,
                "port": port,
                "scheme": scheme,
                "status": obj.get("status_code"),
                "webserver": obj.get("webserver"),
                "tech": obj.get("tech") or [],
                "title": obj.get("title"),
            }
        )
    return out


def parse_ffuf_json(text: str) -> list[dict]:
    """ffuf -json (object with a 'results' array) or NDJSON of result objects."""
    results = []
    text = text.strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        raw = obj.get("results", []) if isinstance(obj, dict) else obj
    except json.JSONDecodeError:
        raw = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for r in raw:
        url = r.get("url", "")
        path = urlsplit(url).path or "/"
        results.append({"path": path, "status": r.get("status"), "length": r.get("length"), "url": url})
    return results


def parse_katana_jsonl(text: str) -> list[dict]:
    """katana -jsonl: one object per line with a request {method, endpoint}."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        req = obj.get("request", obj)
        endpoint = req.get("endpoint") or req.get("url") or obj.get("endpoint")
        if not endpoint:
            continue
        parts = urlsplit(endpoint)
        out.append(
            {
                "method": (req.get("method") or "GET").upper(),
                "path": parts.path or "/",
                "query": parts.query,
                "host": parts.hostname,
                "url": endpoint,
            }
        )
    return out


def parse_subfinder(text: str) -> list[str]:
    """subfinder -silent: one subdomain per line."""
    seen = []
    for line in text.splitlines():
        name = line.strip().lower()
        if name and name not in seen:
            seen.append(name)
    return seen
