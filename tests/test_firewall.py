from chain.firewall import apply_ruleset, generate_ruleset


def test_ruleset_is_default_deny_with_allow_entries():
    rs = generate_ruleset(["93.184.216.34", "2606:2800:220:1::1", "93.184.216.34"])
    assert "policy drop;" in rs
    assert 'oif "lo" accept' in rs
    assert "ip daddr 93.184.216.34 accept" in rs
    assert "ip6 daddr 2606:2800:220:1::1 accept" in rs
    # dedup: the IPv4 entry appears exactly once
    assert rs.count("ip daddr 93.184.216.34 accept") == 1


def test_out_of_scope_ip_is_not_in_ruleset():
    rs = generate_ruleset(["93.184.216.34"])
    assert "10.0.0.5" not in rs


def test_apply_is_dry_run_without_nft():
    # No nft binary on a dev box -> dry run, never raises.
    result = apply_ruleset(generate_ruleset(["93.184.216.34"]), nft_path="definitely-not-nft")
    assert result["applied"] is False
    assert result["dry_run"] is True
