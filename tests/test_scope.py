from chain.scope import Rule, ScopePolicy, classify_ip


def test_classify_blocks_internal_and_metadata():
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("10.0.0.5") == "private"
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("169.254.169.254") == "link-local"  # cloud metadata
    assert classify_ip("100.64.1.1") == "cgnat"
    assert classify_ip("0.0.0.0") == "unspecified"
    assert classify_ip("::1") == "loopback"
    assert classify_ip("fe80::1") == "link-local"
    assert classify_ip("fc00::1") == "private"  # ULA
    assert classify_ip("::ffff:10.0.0.1") == "private"  # IPv4-mapped unwrapped


def test_classify_allows_public():
    assert classify_ip("93.184.216.34") is None
    assert classify_ip("2606:2800:220:1::1") is None


def test_host_rule_allows_matching_host_public_ip():
    p = ScopePolicy([Rule("host", "example.com", True)])
    assert p.check("example.com", "93.184.216.34", "/").allowed is True
    assert p.check("evil.com", "93.184.216.34", "/").allowed is False  # out of scope


def test_host_allowed_but_resolves_internal_is_blocked():
    # Rebinding/SSRF guard: host is allowed, but the resolved IP is internal.
    p = ScopePolicy([Rule("host", "example.com", True)])
    d = p.check("example.com", "10.0.0.5", "/")
    assert d.allowed is False and d.reason.startswith("blocked-ip")


def test_explicit_cidr_allow_overrides_block_set():
    p = ScopePolicy([Rule("host", "box.local", True), Rule("cidr", "10.0.0.0/24", True)])
    assert p.check("box.local", "10.0.0.5", "/").allowed is True


def test_deny_overrides_allow_at_equal_specificity():
    p = ScopePolicy([Rule("host", "example.com", True), Rule("host", "example.com", False)])
    assert p.check("example.com", "93.184.216.34", "/").allowed is False


def test_most_specific_wins():
    # A /32 deny beats a broad /8 allow for that address.
    p = ScopePolicy([Rule("cidr", "93.0.0.0/8", True), Rule("cidr", "93.184.216.34/32", False)])
    assert p.check(None, "93.184.216.34", "/").allowed is False
    assert p.check(None, "93.1.1.1", "/").allowed is True


def test_url_prefix_path_scope():
    p = ScopePolicy([Rule("host", "api.example.com", True), Rule("url_prefix", "/v1", True)])
    assert p.check("api.example.com", "93.184.216.34", "/v1/users").allowed is True
    assert p.check("api.example.com", "93.184.216.34", "/admin").allowed is False


def test_url_prefix_deny_path():
    p = ScopePolicy([Rule("host", "api.example.com", True), Rule("url_prefix", "/internal", False)])
    assert p.check("api.example.com", "93.184.216.34", "/internal/x").allowed is False
    assert p.check("api.example.com", "93.184.216.34", "/public").allowed is True


def test_wildcard_host():
    p = ScopePolicy([Rule("host", "*.example.com", True)])
    assert p.check("api.example.com", "93.184.216.34", "/").allowed is True
    assert p.check("example.com", "93.184.216.34", "/").allowed is True
    assert p.check("example.org", "93.184.216.34", "/").allowed is False
