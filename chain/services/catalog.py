"""Service-check columns, the core HTB service catalog, and NSE-script rules."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import ServiceVulnClass

# (key, label)
SERVICE_CLASSES = [
    ("unauth_access", "Unauthenticated access"),
    ("version_cve", "Known-vuln version / CVE"),
    ("misconfig", "Misconfiguration"),
    ("dangerous_exposure", "Dangerous exposure"),
]

_ALL = {"unauth_access", "version_cve", "misconfig", "dangerous_exposure"}
_NO_EXPOSURE = {"unauth_access", "version_cve", "misconfig"}

# service-name keyword -> applicable class keys. Data stores / brokers also get
# dangerous_exposure (being reachable at all is a finding).
SERVICE_CATALOG = {
    "mysql": _ALL, "postgresql": _ALL, "ms-sql": _ALL, "mssql": _ALL,
    "mongodb": _ALL, "mongod": _ALL, "redis": _ALL,
    "kafka": _ALL, "amqp": _ALL, "rabbitmq": _ALL,
    "ssh": _NO_EXPOSURE, "ftp": _ALL, "smb": _NO_EXPOSURE, "microsoft-ds": _NO_EXPOSURE,
    "netbios-ssn": _NO_EXPOSURE, "ldap": _NO_EXPOSURE, "snmp": _ALL,
    "ms-wbt-server": _NO_EXPOSURE, "rdp": _NO_EXPOSURE, "telnet": _ALL,
}

# NSE script id substring -> (service keyword or None=any, class, verdict, reason)
SCRIPT_RULES = [
    ("ftp-anon", "ftp", "unauth_access", "candidate", "anonymous FTP login allowed"),
    ("redis-info", "redis", "unauth_access", "candidate", "unauthenticated Redis (INFO succeeded)"),
    ("mongodb-databases", "mongo", "unauth_access", "candidate", "unauthenticated MongoDB (listed databases)"),
    ("mongodb-info", "mongo", "unauth_access", "candidate", "unauthenticated MongoDB"),
    ("snmp-info", "snmp", "unauth_access", "candidate", "SNMP readable with default community"),
    ("ldap-rootdse", "ldap", "unauth_access", "candidate", "anonymous LDAP rootDSE readable"),
    ("smb-security-mode", "smb", "misconfig", "candidate", "SMB signing not required"),
    ("ssl-poodle", None, "misconfig", "candidate", "SSL/TLS POODLE"),
]


# Safe (non-brute) empty/default-password NSE scripts for the gated default-cred pass.
# Research: only these are lockout-safe empty-password checks; postgres/telnet have
# only brute scripts, so they get no default-cred signal. ms-sql can trip lockout
# (SQL Server 2005+), which is why the whole pass is gated behind destructive opt-in.
DEFAULT_CRED_SCRIPTS = ["mysql-empty-password", "ms-sql-empty-password"]

# (script id substring, service keyword, reason) -> sets the unauth_access cell.
DEFAULT_CRED_RULES = [
    ("mysql-empty-password", "mysql", "MySQL root/anonymous account has an empty password"),
    ("ms-sql-empty-password", "ms-sql", "MSSQL sa account has a blank password"),
]
_CRED_NEGATIVE = ("no accounts", "not vulnerable", "failed", "error", "no result")


def applicable_classes(service_name: str | None) -> set[str]:
    n = (service_name or "").lower()
    for key, classes in SERVICE_CATALOG.items():
        if key in n:
            return set(classes)
    return set()


def seed_service_classes(session: Session) -> int:
    added = 0
    for key, label in SERVICE_CLASSES:
        if session.query(ServiceVulnClass).filter_by(key=key).first() is None:
            session.add(ServiceVulnClass(key=key, label=label))
            added += 1
    session.commit()
    return added
