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
    # core (v2)
    "mysql": _ALL, "postgresql": _ALL, "ms-sql": _ALL, "mssql": _ALL,
    "mongodb": _ALL, "mongod": _ALL, "redis": _ALL,
    "kafka": _ALL, "amqp": _ALL, "rabbitmq": _ALL,
    "ssh": _NO_EXPOSURE, "ftp": _ALL, "smb": _NO_EXPOSURE, "microsoft-ds": _NO_EXPOSURE,
    "netbios-ssn": _NO_EXPOSURE, "ldap": _NO_EXPOSURE, "snmp": _ALL,
    "ms-wbt-server": _NO_EXPOSURE, "rdp": _NO_EXPOSURE, "telnet": _ALL,
    # long-tail (v3)
    "elasticsearch": _ALL, "memcached": _ALL, "docker": _ALL,
    "kubernetes": _ALL, "kubelet": _ALL, "nfs": _ALL, "rsync": _ALL,
    "vnc": _NO_EXPOSURE, "ipmi": _NO_EXPOSURE, "smtp": _NO_EXPOSURE, "dns": _NO_EXPOSURE,
    "mqtt": _ALL, "cassandra": _ALL, "winrm": _NO_EXPOSURE, "tftp": _ALL,
    "ntp": _NO_EXPOSURE, "kerberos": _NO_EXPOSURE, "pop3": _NO_EXPOSURE,
    "imap": _NO_EXPOSURE, "msrpc": _NO_EXPOSURE,
}

# Port -> canonical service, for when nmap's service name is generic (e.g. "http"
# on 9200/2375/6443) or missing. Used only as a fallback after name matching.
PORT_CANON = {
    3306: "mysql", 5432: "postgresql", 1433: "ms-sql", 27017: "mongodb", 6379: "redis",
    9092: "kafka", 5672: "amqp", 22: "ssh", 21: "ftp", 445: "smb", 139: "smb",
    389: "ldap", 161: "snmp", 3389: "rdp", 23: "telnet",
    9200: "elasticsearch", 11211: "memcached", 2375: "docker", 2376: "docker",
    6443: "kubernetes", 10250: "kubelet", 2049: "nfs", 873: "rsync", 5900: "vnc",
    623: "ipmi", 25: "smtp", 587: "smtp", 53: "dns", 1883: "mqtt", 9042: "cassandra",
    9160: "cassandra", 5985: "winrm", 5986: "winrm", 69: "tftp", 123: "ntp", 88: "kerberos",
    110: "pop3", 143: "imap", 135: "msrpc",
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
    # long-tail (v3) — fire when the matching NSE script is present
    ("memcached-info", "memcached", "unauth_access", "candidate", "unauthenticated Memcached (stats readable)"),
    ("nfs-showmount", "nfs", "unauth_access", "candidate", "NFS exports listable/world-readable"),
    ("rsync-list-modules", "rsync", "unauth_access", "candidate", "anonymous rsync modules listable"),
    ("realvnc-auth-bypass", "vnc", "unauth_access", "candidate", "RealVNC auth bypass (CVE-2006-2369)"),
    ("vnc-info", "vnc", "misconfig", "candidate", "VNC security types exposed"),
    ("ipmi-cipher-zero", "ipmi", "unauth_access", "candidate", "IPMI cipher-zero auth bypass"),
    ("smtp-open-relay", "smtp", "misconfig", "candidate", "SMTP open relay"),
    ("dns-zone-transfer", "dns", "misconfig", "candidate", "DNS zone transfer (AXFR) allowed"),
    ("mqtt-subscribe", "mqtt", "unauth_access", "candidate", "unauthenticated MQTT subscribe"),
    ("cassandra-info", "cassandra", "unauth_access", "candidate", "Cassandra reachable without auth"),
    ("tftp-enum", "tftp", "unauth_access", "candidate", "TFTP files enumerable"),
    ("ntp-monlist", "ntp", "misconfig", "candidate", "NTP monlist (info leak / amplification)"),
    ("krb5-enum-users", "kerberos", "unauth_access", "candidate", "Kerberos user enumeration possible"),
    ("msrpc-enum", "msrpc", "unauth_access", "candidate", "MSRPC endpoint-mapper enumeration"),
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


def _match_name(service_name: str | None) -> str | None:
    n = (service_name or "").lower()
    for key in sorted(SERVICE_CATALOG, key=len, reverse=True):  # longest first: 'tftp' before 'ftp'
        if key in n:
            return key
    return None


def applicable_classes(service_name: str | None) -> set[str]:
    key = _match_name(service_name)
    return set(SERVICE_CATALOG.get(key, set())) if key else set()


def service_profile(service_name: str | None, port: int | None) -> tuple[str | None, set[str]]:
    """Return (canonical_service, applicable_classes), matching by name then by
    port. Lets HTTP-fronted services (Elasticsearch/Docker/K8s on 9200/2375/6443)
    into the service matrix even when nmap labels them 'http'."""
    key = _match_name(service_name)
    if key:
        return key, set(SERVICE_CATALOG[key])
    if port is not None and port in PORT_CANON:
        key = PORT_CANON[port]
        return key, set(SERVICE_CATALOG.get(key, set()))
    return None, set()


def seed_service_classes(session: Session) -> int:
    added = 0
    for key, label in SERVICE_CLASSES:
        if session.query(ServiceVulnClass).filter_by(key=key).first() is None:
            session.add(ServiceVulnClass(key=key, label=label))
            added += 1
    session.commit()
    return added
