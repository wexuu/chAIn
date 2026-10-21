"""Runtime settings. Plain defaults with env overrides — no secrets, no encryption.

Per owner decision the VM is trusted and the network path is trusted (localhost
bind reached over an SSH tunnel), so nothing here configures TLS or at-rest
encryption.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ[key])
    except (KeyError, ValueError):
        return default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    # Bound to loopback only; reached from the main box via an SSH tunnel.
    bind_host: str = os.environ.get("CHAIN_BIND_HOST", "127.0.0.1")
    bind_port: int = _env_int("CHAIN_BIND_PORT", 8787)

    db_path: str = os.environ.get("CHAIN_DB", "chain.db")
    evidence_dir: str = os.environ.get("CHAIN_EVIDENCE_DIR", "evidence")

    # Default per-target egress throttles (overridable per Target).
    default_rate_rps: float = _env_float("CHAIN_RATE_RPS", 5.0)
    default_concurrency: int = _env_int("CHAIN_CONCURRENCY", 4)

    # Redirect hops the egress chokepoint will follow (each re-validated).
    max_redirect_hops: int = _env_int("CHAIN_MAX_REDIRECT_HOPS", 5)

    # Per-evidence-blob size cap (bytes); larger blobs are truncated + flagged.
    evidence_max_bytes: int = _env_int("CHAIN_EVIDENCE_MAX_BYTES", 5 * 1024 * 1024)

    # nftables firewall: generator is always available, but rules are only ever
    # written to the machine when this is explicitly enabled. Default OFF.
    firewall_apply_enabled: bool = os.environ.get("CHAIN_FIREWALL_APPLY", "").lower() in ("1", "true", "yes")

    # Evidence retention: None = keep until manually purged; else days before reap.
    evidence_retention_days: int | None = (
        _env_int("CHAIN_EVIDENCE_RETENTION_DAYS", 0) or None
    )

    # Optional UI/API token auth. None (default) = open (trusted network).
    ui_auth_token: str | None = os.environ.get("CHAIN_UI_TOKEN") or None


settings = Settings()
