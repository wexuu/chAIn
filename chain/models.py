"""SQLAlchemy models. Phase 0 lands the scope/auth/audit core; later phases add
the inventory, matrix, chains, and evidence tables defined in the plan.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)

    # Authorization is an ATTESTATION, not verification — see the plan.
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    authorized_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Destructive (state-changing) checks are off unless explicitly opted in.
    destructive_opt_in: Mapped[bool] = mapped_column(Boolean, default=False)

    # Per-target egress throttles.
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=5.0)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=4)

    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    kind: Mapped[str] = mapped_column(String(16))  # host | cidr | url_prefix
    value: Mapped[str] = mapped_column(String(512))
    allow: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="scope_rules")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[Optional[int]] = mapped_column(ForeignKey("targets.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), default="human")
    action: Mapped[str] = mapped_column(String(128))
    ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    egress_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    resolved_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


# --- Phase 1: recon / inventory ---------------------------------------------


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    os_guess: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)

    services: Mapped[list["Service"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_http: Mapped[bool] = mapped_column(Boolean, default=False)
    scripts_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship(back_populates="services")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    name: Mapped[str] = mapped_column(String(255))
    resolved_ips_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="passive")  # passive | active
    # found | approved | excluded | scanning | done
    status: Mapped[str] = mapped_column(String(16), default="found")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(16), default="recon")
    params_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_fields_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ReconJob(Base):
    __tablename__ = "recon_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    tier: Mapped[str] = mapped_column(String(16))  # quick | thorough
    # pending | running | done | error | cancelled
    status: Mapped[str] = mapped_column(String(16), default="pending")
    target_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tasks: Mapped[list["ReconTask"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class ReconTask(Base):
    __tablename__ = "recon_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("recon_jobs.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    key: Mapped[str] = mapped_column(String(64))
    tier: Mapped[str] = mapped_column(String(16))
    selected: Mapped[bool] = mapped_column(Boolean, default=True)
    # not_run | queued | running | done | skipped | error
    status: Mapped[str] = mapped_column(String(16), default="not_run")
    importance: Mapped[str] = mapped_column(String(8), default="med")  # high | med | low
    could_yield: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    job: Mapped["ReconJob"] = relationship(back_populates="tasks")


# --- Phase 2: coverage matrix -----------------------------------------------


class VulnClass(Base):
    __tablename__ = "vuln_classes"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(255))
    wstg_ids_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    param_specific: Mapped[bool] = mapped_column(Boolean, default=False)


class CoverageCell(Base):
    __tablename__ = "coverage_cells"

    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"))
    vuln_class_id: Mapped[int] = mapped_column(ForeignKey("vuln_classes.id"))
    param_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # untested | candidate | confirmed | tested_negative | not_applicable | reviewed
    status: Mapped[str] = mapped_column(String(16), default="untested")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # What scope/paths a 'tested' cell actually exercised (so green != class-wide safe).
    scope_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tested_scope_derived: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


# --- Phase 3: auth profiles, requests, attempts, evidence -------------------


class AuthProfile(Base):
    __tablename__ = "auth_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(16), default="none")  # none|bearer|cookie|header|basic
    secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # plaintext (trusted VM)
    headers_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    last_verified_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    liveness_probe: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    kind: Mapped[str] = mapped_column(String(16))  # request | response | tool_output
    storage: Mapped[str] = mapped_column(String(8), default="fs")
    path: Mapped[str] = mapped_column(Text)
    content_type: Mapped[str] = mapped_column(String(128), default="text/plain")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    retain_until: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)


class Request(Base):
    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    endpoint_id: Mapped[Optional[int]] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(Text)
    headers_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth_profile_id: Mapped[Optional[int]] = mapped_column(ForeignKey("auth_profiles.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class Attempt(Base):
    __tablename__ = "attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    cell_id: Mapped[int] = mapped_column(ForeignKey("coverage_cells.id"))
    request_id: Mapped[int] = mapped_column(ForeignKey("requests.id"))
    auth_profile_id: Mapped[Optional[int]] = mapped_column(ForeignKey("auth_profiles.id"), nullable=True)
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


# --- Phase 4: chains + findings ---------------------------------------------


class Edge(Base):
    __tablename__ = "edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    kind: Mapped[str] = mapped_column(String(24))  # source_to_sink | precondition
    from_ref: Mapped[str] = mapped_column(String(128))  # e.g. "cell:12" / "endpoint:3"
    to_ref: Mapped[str] = mapped_column(String(128))
    evidence_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    title: Mapped[str] = mapped_column(String(512))
    # proposed | validated | confirmed | rejected
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    origin: Mapped[str] = mapped_column(String(64), default="human")  # human | agent:<name>
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    member_cells_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    member_findings_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    title: Mapped[str] = mapped_column(String(512))
    vuln_class_id: Mapped[Optional[int]] = mapped_column(ForeignKey("vuln_classes.id"), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    endpoints_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    repro_request_id: Mapped[Optional[int]] = mapped_column(ForeignKey("requests.id"), nullable=True)
    evidence_refs_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


# --- v2: async wrapped check jobs -------------------------------------------


class CheckJob(Base):
    __tablename__ = "check_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tasks: Mapped[list["CheckTask"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class CheckTask(Base):
    __tablename__ = "check_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("check_jobs.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    cell_id: Mapped[int] = mapped_column(ForeignKey("coverage_cells.id"))
    tool: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    job: Mapped["CheckJob"] = relationship(back_populates="tasks")


# --- v2: service matrix (non-web services) ----------------------------------


class ServiceVulnClass(Base):
    __tablename__ = "service_vuln_classes"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(255))


class ServiceCell(Base):
    __tablename__ = "service_cells"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    service_vuln_class_id: Mapped[int] = mapped_column(ForeignKey("service_vuln_classes.id"))
    status: Mapped[str] = mapped_column(String(16), default="untested")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scope_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


# --- v2: step sequences (stateful multi-step flows) -------------------------


class StepSequence(Base):
    __tablename__ = "step_sequences"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    name: Mapped[str] = mapped_column(String(255))
    # [{name, method, path, headers, body, auth_profile, captures:[{name,kind,expr}]}]
    steps_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class SequenceRun(Base):
    __tablename__ = "sequence_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    sequence_id: Mapped[int] = mapped_column(ForeignKey("step_sequences.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|done|error
    results_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
