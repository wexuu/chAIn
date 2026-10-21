"""Curated-core vuln-class columns, each mapped to OWASP WSTG (v4.2) IDs.

Kept scannable (not the full WSTG checklist). `param_specific` classes spawn one
cell per parameter; the rest get a single cell per endpoint. Exact WSTG IDs are
representative and pinned from checklist.json at build time.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from ..models import VulnClass

# (key, label, [wstg ids], param_specific)
VULN_CLASSES = [
    ("method_tampering", "HTTP method tampering", ["WSTG-CONF-06"], False),
    # Resource/request-level (replay as another user), not per-parameter.
    ("authz_idor", "Authorization / IDOR / BOLA", ["WSTG-ATHZ-01", "WSTG-ATHZ-02", "WSTG-ATHZ-04"], False),
    ("sqli", "SQL injection", ["WSTG-INPV-05"], True),
    ("ssti", "Server-side template injection", ["WSTG-INPV-18"], True),
    ("cmdi", "OS command injection", ["WSTG-INPV-12"], True),
    ("path_traversal", "Path traversal / file inclusion", ["WSTG-ATHZ-01", "WSTG-INPV-11"], True),
    ("xss", "XSS / HTML injection", ["WSTG-INPV-01", "WSTG-INPV-02"], True),
    ("mass_assignment", "Mass assignment", ["OWASP-API6"], True),
    ("business_logic", "Business logic", ["WSTG-BUSL-01"], False),
    ("csrf", "CSRF", ["WSTG-SESS-05"], False),
    ("rate_limiting", "Rate limiting / anti-automation", ["WSTG-BUSL-05", "OWASP-API4"], False),
    ("info_disclosure", "Information disclosure", ["WSTG-INFO-02", "WSTG-ERRH-01"], False),
    ("headers_cors", "Security headers / CSP / CORS", ["WSTG-CONF-07", "WSTG-CLNT-07"], False),
]


def seed_vuln_classes(session: Session) -> int:
    """Insert any missing vuln classes. Idempotent."""
    added = 0
    for key, label, wstg, param_specific in VULN_CLASSES:
        existing = session.query(VulnClass).filter_by(key=key).first()
        if existing is None:
            session.add(
                VulnClass(
                    key=key,
                    label=label,
                    wstg_ids_json=json.dumps(wstg),
                    param_specific=param_specific,
                )
            )
            added += 1
    session.commit()
    return added
