"""Sequence runner: substitute {{vars}}, send each step through the chokepoint,
capture values from responses into vars for later steps.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from sqlalchemy.orm import Session

from ..models import SequenceRun, StepSequence

_VAR = re.compile(r"\{\{(\w+)\}\}")


def substitute(value, vars_: dict):
    """Replace {{name}} in a string (recursively in dict/list) using vars_."""
    if isinstance(value, str):
        return _VAR.sub(lambda m: str(vars_.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: substitute(v, vars_) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, vars_) for v in value]
    return value


def _json_path(obj, expr: str):
    cur = obj
    for part in expr.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def extract(capture: dict, response) -> Optional[str]:
    kind = capture.get("kind")
    expr = capture.get("expr", "")
    try:
        if kind == "json":
            val = _json_path(response.json(), expr)
            return None if val is None else str(val)
        if kind == "regex":
            m = re.search(expr, response.text or "")
            if not m:
                return None
            return m.group(1) if m.groups() else m.group(0)
        if kind == "header":
            return response.headers.get(expr)
    except Exception:  # noqa: BLE001 — a bad capture must not crash the run
        return None
    return None


async def run_sequence(
    session: Session,
    seq: StepSequence,
    *,
    send_fn,
    auth_profiles: Optional[dict] = None,
    host: str = "localhost",
) -> SequenceRun:
    auth_profiles = auth_profiles or {}
    steps = json.loads(seq.steps_json)
    vars_: dict = {}
    results = []
    status = "done"

    for idx, step in enumerate(steps):
        method = (step.get("method") or "GET").upper()
        path = substitute(step.get("path", "/"), vars_)
        url = path if path.startswith("http") else f"https://{host}{path}"
        headers = substitute(step.get("headers") or {}, vars_)
        body = step.get("body")
        content = None
        if body is not None:
            body = substitute(body, vars_)
            content = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        profile = auth_profiles.get(step.get("auth_profile"))

        step_result = {"step": idx, "name": step.get("name"), "method": method, "path": path}
        try:
            resp = await send_fn(method, url, headers=headers, content=content, profile=profile)
            step_result["status"] = resp.status_code
            captured = {}
            for cap in step.get("captures") or []:
                val = extract(cap, resp)
                if val is not None and cap.get("name"):
                    vars_[cap["name"]] = val
                    captured[cap["name"]] = val
            step_result["captured"] = captured
        except Exception as exc:  # noqa: BLE001
            step_result["error"] = f"{type(exc).__name__}: {exc}"
            status = "error"
            results.append(step_result)
            break
        results.append(step_result)

    run = SequenceRun(
        sequence_id=seq.id,
        target_id=seq.target_id,
        status=status,
        results_json=json.dumps({"vars": vars_, "steps": results}),
    )
    session.add(run)
    session.commit()
    return run
