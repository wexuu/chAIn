"""Scope engine — the decision half of the safety core.

Two independent jobs:
  1. classify_ip(): is an address in the default-block set (SSRF-to-internal
     guard)? Applies to every resolved address before any connection.
  2. ScopePolicy.check(): does the target's allow-list permit (host, ip, path)?
     Precedence is **deny-overrides-allow** and **most-specific-wins**; an
     explicit `allow` CIDR can override the default-block set (operator knows
     they're testing an internal range).

Pure stdlib (ipaddress) — no network, fully unit-testable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlsplit

_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 shared address space


def classify_ip(ip_str: str) -> Optional[str]:
    """Return a block reason for internal/dangerous addresses, else None.

    Covers loopback, private (RFC1918 + ULA fc00::/7), link-local (incl. the
    cloud-metadata 169.254.169.254 and fe80::/10), CGNAT, multicast, reserved,
    unspecified, and IPv4-mapped IPv6 (::ffff:10.x unwrapped and re-checked).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid-ip"

    # Unwrap IPv4-mapped IPv6 so ::ffff:10.0.0.1 is judged as 10.0.0.1.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return classify_ip(str(ip.ipv4_mapped)) or "ipv4-mapped"

    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:  # 169.254/16 (incl. metadata) and fe80::/10
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:  # RFC1918 and ULA fc00::/7
        return "private"
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat"
    if ip.is_reserved:
        return "reserved"
    return None


@dataclass
class Rule:
    kind: str  # host | cidr | url_prefix
    value: str
    allow: bool = True


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched: Optional[Rule] = None


def _host_match(value: str, host: Optional[str]) -> bool:
    v = (value or "").lower()
    h = (host or "").lower()
    if v.startswith("*."):
        base = v[2:]
        return h == base or h.endswith("." + base)
    return h == v


def _cidr_match(value: str, ip: Optional[str]) -> bool:
    if ip is None:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False


def _path_of(value: str) -> str:
    return urlsplit(value).path or "/" if "://" in value else (value or "/")


def _path_match(value: str, path: Optional[str]) -> bool:
    return (path or "/").startswith(_path_of(value))


def _specificity(rule: Rule) -> int:
    if rule.kind == "host":
        v = (rule.value or "").lower()
        return 5000 + len(v) if v.startswith("*.") else 10000
    if rule.kind == "cidr":
        try:
            return ipaddress.ip_network(rule.value, strict=False).prefixlen
        except ValueError:
            return 0
    return 0


class ScopePolicy:
    """Evaluates a target's scope rules for a single (host, ip, path)."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def check(self, host: Optional[str], ip: Optional[str], path: str = "/") -> Decision:
        # 1) host/ip scope — the egress-critical gate.
        hostip = [r for r in self.rules if r.kind in ("host", "cidr")]
        matches = [
            r
            for r in hostip
            if (r.kind == "host" and _host_match(r.value, host))
            or (r.kind == "cidr" and _cidr_match(r.value, ip))
        ]
        if not matches:
            return Decision(False, "out-of-scope")

        top_spec = max(_specificity(r) for r in matches)
        top = [r for r in matches if _specificity(r) == top_spec]
        denies = [r for r in top if not r.allow]
        if denies:  # deny overrides allow at equal specificity
            return Decision(False, "denied-by-rule", denies[0])

        # 2) default-block set on the resolved IP, unless an explicit allow CIDR covers it.
        if ip is not None:
            reason = classify_ip(ip)
            if reason:
                override = any(
                    r.allow and r.kind == "cidr" and _cidr_match(r.value, ip)
                    for r in self.rules
                )
                if not override:
                    return Decision(False, f"blocked-ip:{reason}")

        # 3) optional path scope (url_prefix) for native requests.
        url_rules = [r for r in self.rules if r.kind == "url_prefix"]
        if url_rules:
            path_denies = [r for r in url_rules if not r.allow and _path_match(r.value, path)]
            if path_denies:
                return Decision(False, "denied-path", path_denies[0])
            allows = [r for r in url_rules if r.allow]
            if allows and not any(_path_match(r.value, path) for r in allows):
                return Decision(False, "out-of-scope-path")

        return Decision(True, "allowed", top[0])


def policy_from_rules(rules: Iterable) -> ScopePolicy:
    """Build a ScopePolicy from ORM ScopeRule rows (or any obj with kind/value/allow)."""
    return ScopePolicy(Rule(kind=r.kind, value=r.value, allow=r.allow) for r in rules)
