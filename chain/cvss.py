"""CVSS 3.1 base-score calculator. Score is DERIVED from the vector (never
free-typed), so severity stays defensible in a report.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class InvalidVector(ValueError):
    pass


def parse_vector(vector: str) -> dict:
    metrics = {}
    for part in vector.strip().split("/"):
        if not part or part.upper().startswith("CVSS:"):
            continue
        if ":" not in part:
            raise InvalidVector(f"bad metric segment: {part!r}")
        k, v = part.split(":", 1)
        metrics[k.upper()] = v.upper()
    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise InvalidVector(f"missing metrics: {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(vector: str) -> tuple[float, str]:
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        ui = _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise InvalidVector(f"invalid metric value: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0, severity(0.0)
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    score = _roundup(min(raw, 10.0))
    return score, severity(score)
