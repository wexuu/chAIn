"""Report export — JSON + Markdown, with the coverage and recon-coverage annexes.

This is an external boundary, so secrets are redacted. The coverage annex makes
"what I did and did NOT test" explicit (untested = to-do, N/A + reason, and what
each tested-negative cell actually exercised).
"""

from __future__ import annotations

import datetime as dt
import json

from sqlalchemy.orm import Session

from . import redact
from .matrix import cells as matrix_cells
from .models import Finding, Target, VulnClass
from .recon.inventory import recon_coverage

SAMPLED_SCOPE_CAVEAT = (
    "A 'tested-negative' cell reflects only the inputs/paths actually exercised "
    "(see scope); it is not proof the whole class is absent."
)


def build_report(session: Session, target_id: int) -> dict:
    target = session.get(Target, target_id)
    if target is None:
        raise ValueError("target not found")
    vc = {v.id: v.key for v in session.query(VulnClass).all()}

    matrix = matrix_cells.get_matrix(session, target_id)
    untested, not_applicable, tested_negative = [], [], []
    for ep in matrix["endpoints"]:
        for cell in ep["cells"]:
            ref = {
                "endpoint": f"{ep['method']} {ep['path']}",
                "vuln_class": cell["vuln_class"],
                "param": cell["param_name"],
            }
            if cell["status"] == "untested":
                untested.append(ref)
            elif cell["status"] == "not_applicable":
                not_applicable.append({**ref, "reason": cell["reason"]})
            elif cell["status"] == "tested_negative":
                tested_negative.append(
                    {**ref, "reason": cell["reason"], "scope": cell["scope_note"]}
                )

    findings = []
    for f in session.query(Finding).filter_by(target_id=target_id).all():
        findings.append(
            {
                "title": f.title,
                "vuln_class": vc.get(f.vuln_class_id),
                "severity": f.severity,
                "cvss_vector": f.cvss_vector,
                "cvss_score": f.cvss_score,
                "endpoints": json.loads(f.endpoints_json) if f.endpoints_json else [],
                "remediation": f.remediation,
                "status": f.status,
            }
        )

    return {
        "target": {"id": target.id, "name": target.name, "authorized": target.authorized},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "findings": findings,
        "coverage_annex": {
            "summary": matrix["summary"],
            "caveat": SAMPLED_SCOPE_CAVEAT,
            "untested": untested,
            "not_applicable": not_applicable,
            "tested_negative": tested_negative,
        },
        "recon_coverage": recon_coverage(session, target_id),
    }


def render_markdown(session: Session, target_id: int) -> str:
    report = build_report(session, target_id)
    t = report["target"]
    lines = [
        f"# chAIn report — {t['name']}",
        "",
        f"_Generated {report['generated_at']}_ · authorized: {t['authorized']}",
        "",
        "## Findings",
        "",
    ]
    if report["findings"]:
        for f in report["findings"]:
            lines.append(f"### {f['title']}  ({f['severity']} / CVSS {f['cvss_score']})")
            lines.append(f"- Class: {f['vuln_class']}")
            lines.append(f"- Endpoints: {', '.join(f['endpoints']) or '—'}")
            lines.append(f"- CVSS vector: `{f['cvss_vector']}`")
            lines.append(f"- Remediation: {f['remediation'] or '—'}")
            lines.append("")
    else:
        lines.append("_No findings recorded._\n")

    cov = report["coverage_annex"]
    s = cov["summary"]
    lines += [
        "## Coverage annex",
        "",
        f"Coverage: **{s['coverage_pct']}%** ({s['covered']}/{s['applicable']} applicable cells). "
        f"_{cov['caveat']}_",
        "",
        f"- Untested (to-do): {len(cov['untested'])}",
        f"- Not applicable: {len(cov['not_applicable'])}",
        f"- Tested-negative: {len(cov['tested_negative'])}",
        "",
    ]
    if cov["tested_negative"]:
        lines.append("### Tested-negative (with reason)")
        for c in cov["tested_negative"]:
            scope = f" — scope: {c['scope']}" if c.get("scope") else ""
            lines.append(f"- {c['endpoint']} · {c['vuln_class']}: {c['reason']}{scope}")
        lines.append("")

    rc = report["recon_coverage"]
    lines += ["## Recon-coverage annex", ""]
    for task in rc["tasks"]:
        lines.append(f"- `{task['key']}` ({task['importance']}): {task['status']}")
    if rc["flagged_gaps"]:
        lines.append("")
        lines.append("**Flagged gaps (high-importance, not run):**")
        for g in rc["flagged_gaps"]:
            lines.append(f"- `{g['key']}` — {g['could_yield']}")

    md = "\n".join(lines) + "\n"
    return redact.redact_text(md, redact.target_secrets(session, target_id))
