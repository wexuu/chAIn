"""Native checks — API-shaped probes run through the egress chokepoint.

Native-first (method tampering, authz/IDOR replay, headers/CSP/CORS, reflection,
mass assignment). Deep classes (SQLi/SSTI/...) are left to wrapped tools later;
their cells stay honestly `untested` until covered.
"""
