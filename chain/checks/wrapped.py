"""Wrapped-tool adapters: build the external invocation + parse its output into
a verdict. Pure functions (tested on fixtures; no tools needed).

Tool set (v2): sqlmap (SQLi), dalfox (XSS), nuclei (ssti/cmdi/path-traversal via
tags). All run as external processes, launch-gated + firewall-backed — they do
NOT pass through the egress chokepoint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

from .base import build_url


@dataclass
class Adapter:
    tool: str
    build_argv: Callable  # (url, param|None) -> list[str]
    parse: Callable[[str], tuple[str, str]]  # stdout -> (verdict, reason)


# --- parsers ---------------------------------------------------------------


def parse_sqlmap(stdout: str) -> tuple[str, str]:
    low = stdout.lower()
    negative = "do not appear to be injectable" in low
    positive = (
        "is vulnerable" in low
        or "sqlmap identified the following injection point" in low
        or ("parameter:" in low and "type:" in low)
    )
    if positive and not negative:
        return "candidate", "sqlmap reported an injection point"
    return "tested_negative", "sqlmap: no injection reported"


def parse_dalfox(stdout: str) -> tuple[str, str]:
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if "[POC]" in line or '"type":"V"' in line:
                return "candidate", "dalfox PoC"
            continue
        if isinstance(obj, dict) and obj.get("type") in ("V", "POC", "G"):
            return "candidate", f"dalfox: {obj.get('type')} {obj.get('evidence','')[:80]}"
    return "tested_negative", "dalfox: no XSS PoC"


def parse_nuclei(stdout: str) -> tuple[str, str]:
    hits = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = obj.get("template-id") or obj.get("templateID")
        sev = (obj.get("info", {}) or {}).get("severity")
        if tid:
            hits.append(f"{tid}({sev})" if sev else tid)
    if hits:
        return "candidate", "nuclei matched: " + ", ".join(hits[:5])
    return "tested_negative", "nuclei: no template match"


# --- adapters per vuln class -----------------------------------------------


def _sqlmap_argv(url, param):
    argv = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1", "--technique=BEUST"]
    if param:
        argv += ["-p", param]
    return argv


def _dalfox_argv(url, param):
    argv = ["dalfox", "url", url, "--format", "json", "--silence"]
    if param:
        argv += ["--param", param]
    return argv


def _nuclei_argv(tags):
    def build(url, param):
        return ["nuclei", "-u", url, "-tags", tags, "-jsonl", "-silent"]

    return build


ADAPTERS: dict[str, Adapter] = {
    "sqli": Adapter("sqlmap", _sqlmap_argv, parse_sqlmap),
    "xss": Adapter("dalfox", _dalfox_argv, parse_dalfox),
    "ssti": Adapter("nuclei", _nuclei_argv("ssti"), parse_nuclei),
    "cmdi": Adapter("nuclei", _nuclei_argv("rce,cmdi"), parse_nuclei),
    "path_traversal": Adapter("nuclei", _nuclei_argv("lfi,fileupload"), parse_nuclei),
}


def adapter_for(vuln_class_key: str) -> Optional[Adapter]:
    return ADAPTERS.get(vuln_class_key)


def cell_target_url(session, endpoint, param: Optional[str]) -> str:
    """URL for the tool: include a seed value for the param so the tool has an input."""
    extra = {param: "1"} if param else None
    return build_url(session, endpoint, extra_query=extra)
