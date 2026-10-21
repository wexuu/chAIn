"""Default-deny egress firewall generator (nftables).

The chokepoint (egress.py) only governs chAIn's own native requests. Recon and
wrapped tools (nmap/ffuf/katana/sqlmap/...) make their own connections, so the
per-packet backstop is a default-deny nftables ruleset whose allow-set is
derived from the scope allow-list and regenerated whenever scope changes
(e.g. a subdomain is approved).

generate_ruleset() is pure/testable. apply_ruleset() shells out to `nft` only
when it exists; otherwise it is a dry run (as on non-VM dev machines).
"""

from __future__ import annotations

from typing import Iterable

_TEMPLATE = """#!/usr/sbin/nft -f
# chAIn egress allow-list — generated, do not hand-edit.
# Default-deny: only established/related, loopback, and in-scope destinations leave.
table inet chain_egress {{
    chain output {{
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        oif "lo" accept
{rules}
    }}
}}
"""


def generate_ruleset(allowed_ips: Iterable[str]) -> str:
    lines = []
    for ip in sorted(set(allowed_ips)):
        family = "ip6" if ":" in ip else "ip"
        lines.append(f"        {family} daddr {ip} accept")
    return _TEMPLATE.format(rules="\n".join(lines))


def apply_ruleset(ruleset: str, nft_path: str = "nft") -> dict:
    import os
    import shutil
    import subprocess
    import tempfile

    if shutil.which(nft_path) is None:
        return {"applied": False, "dry_run": True, "reason": "nft-not-found"}

    tmp = tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False)
    try:
        tmp.write(ruleset)
        tmp.close()
        subprocess.run([nft_path, "-f", tmp.name], check=True, capture_output=True)
        return {"applied": True, "dry_run": False}
    finally:
        os.unlink(tmp.name)
