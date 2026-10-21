"""Recon task catalog + ingest functions.

Each ReconSpec bundles how to launch a tool, parse its output, and merge the
result into the inventory. Tiers: `quick` (fast, start-poking) and `thorough`
(deep, async). Importance drives the "not run but could yield" flagging.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs

from sqlalchemy.orm import Session

from . import parsers
from .inventory import upsert_endpoint, upsert_host, upsert_service, upsert_subdomain


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# --- ingest functions -------------------------------------------------------


def ingest_nmap(session: Session, target_id: int, records: list, host: str) -> None:
    for rec in records:
        h = upsert_host(
            session,
            target_id,
            ip=rec.get("ip"),
            hostname=rec.get("hostname") or host,
            os_guess=rec.get("os_guess"),
        )
        for svc in rec.get("services", []):
            upsert_service(
                session,
                h,
                port=svc["port"],
                proto=svc.get("proto", "tcp"),
                name=svc.get("name"),
                product=svc.get("product"),
                version=svc.get("version"),
                banner=svc.get("banner"),
                is_http=svc.get("is_http", False),
            )


def ingest_httpx(session: Session, target_id: int, records: list, host: str) -> None:
    for rec in records:
        rec_host = rec.get("host")
        ip = rec_host if _is_ip(rec_host) else None
        hostname = rec.get("input_host") or (None if _is_ip(rec_host) else rec_host) or host
        h = upsert_host(session, target_id, ip=ip, hostname=hostname)
        upsert_service(
            session,
            h,
            port=rec["port"],
            proto="tcp",
            name=rec.get("scheme"),
            product=rec.get("webserver"),
            is_http=True,
        )
        upsert_endpoint(session, target_id, method="GET", path="/", host_id=h.id, source="recon")


def ingest_ffuf(session: Session, target_id: int, records: list, host: str) -> None:
    h = upsert_host(session, target_id, hostname=host)
    for rec in records:
        upsert_endpoint(
            session, target_id, method="GET", path=rec["path"], host_id=h.id, source="ffuf"
        )


def ingest_katana(session: Session, target_id: int, records: list, host: str) -> None:
    h = upsert_host(session, target_id, hostname=host)
    for rec in records:
        params = sorted(parse_qs(rec.get("query") or "").keys()) or None
        upsert_endpoint(
            session,
            target_id,
            method=rec.get("method", "GET"),
            path=rec["path"],
            host_id=h.id,
            source="crawl",
            params=params,
        )


def ingest_subfinder(session: Session, target_id: int, records: list, host: str) -> None:
    for name in records:
        upsert_subdomain(session, target_id, name=name, source="passive")


# --- the catalog ------------------------------------------------------------


@dataclass
class ReconSpec:
    key: str
    label: str
    tier: str  # quick | thorough
    importance: str  # high | med | low
    could_yield: str
    tool: str
    build_argv: Callable[[str], list[str]]
    parse: Callable[[str], list]
    ingest: Callable[[Session, int, list, str], None]
    timeout: float = 300.0
    default_selected: bool = True


FFUF_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

_SPECS = [
    ReconSpec(
        key="nmap_quick",
        label="nmap quick (top 1000 TCP)",
        tier="quick",
        importance="high",
        could_yield="open ports + service versions on the common 1000 TCP ports",
        tool="nmap",
        build_argv=lambda h: ["nmap", "-Pn", "-sV", "--top-ports", "1000", "-oX", "-", h],
        parse=parsers.parse_nmap_xml,
        ingest=ingest_nmap,
        timeout=600.0,
    ),
    ReconSpec(
        key="httpx_probe",
        label="httpx web probe",
        tier="quick",
        importance="high",
        could_yield="live web services, tech fingerprint, titles",
        tool="httpx",
        build_argv=lambda h: ["httpx", "-json", "-silent", "-u", h],
        parse=parsers.parse_httpx_jsonl,
        ingest=ingest_httpx,
        timeout=180.0,
    ),
    ReconSpec(
        key="subfinder_passive",
        label="subfinder (passive subdomains)",
        tier="quick",
        importance="med",
        could_yield="passively-discovered subdomains (candidates you approve)",
        tool="subfinder",
        build_argv=lambda h: ["subfinder", "-d", h, "-silent"],
        parse=parsers.parse_subfinder,
        ingest=ingest_subfinder,
        timeout=180.0,
    ),
    ReconSpec(
        key="nmap_full",
        label="nmap full (all 65535 TCP + scripts)",
        tier="thorough",
        importance="high",
        could_yield="ports the top-1000 scan missed + default-script findings",
        tool="nmap",
        build_argv=lambda h: ["nmap", "-Pn", "-p-", "-sV", "-sC", "-oX", "-", h],
        parse=parsers.parse_nmap_xml,
        ingest=ingest_nmap,
        timeout=3600.0,
    ),
    ReconSpec(
        key="nmap_udp",
        label="nmap UDP (top 100)",
        tier="thorough",
        importance="med",
        could_yield="UDP services (DNS/SNMP/...) that TCP-only scans never see",
        tool="nmap",
        build_argv=lambda h: ["nmap", "-Pn", "-sU", "--top-ports", "100", "-oX", "-", h],
        parse=parsers.parse_nmap_xml,
        ingest=ingest_nmap,
        timeout=3600.0,
    ),
    ReconSpec(
        key="ffuf_dir",
        label="ffuf content discovery",
        tier="thorough",
        importance="high",
        could_yield="hidden directories/files not linked anywhere",
        tool="ffuf",
        # -r (follow redirects) intentionally omitted per the egress scope policy.
        build_argv=lambda h: ["ffuf", "-u", f"https://{h}/FUZZ", "-w", FFUF_WORDLIST, "-json"],
        parse=parsers.parse_ffuf_json,
        ingest=ingest_ffuf,
        timeout=1200.0,
    ),
    ReconSpec(
        key="katana_crawl",
        label="katana crawl",
        tier="thorough",
        importance="high",
        could_yield="crawled endpoints + query parameters (matrix rows)",
        tool="katana",
        build_argv=lambda h: ["katana", "-u", f"https://{h}", "-jsonl", "-silent"],
        parse=parsers.parse_katana_jsonl,
        ingest=ingest_katana,
        timeout=1200.0,
    ),
]

CATALOG: dict[str, ReconSpec] = {s.key: s for s in _SPECS}
