import httpx
import pytest

from chain import egress
from chain.scope import Rule, ScopePolicy


def mk_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def resolver_for(mapping):
    async def _resolve(host):
        return mapping[host]

    return _resolve


async def test_pins_validated_ip_and_preserves_host():
    seen = {}

    def handler(request):
        seen["url_host"] = request.url.host
        seen["host_header"] = request.headers.get("host")
        return httpx.Response(200, text="ok")

    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(handler)
    resp = await egress.send(
        policy=policy,
        method="GET",
        url="https://example.com/path",
        client=client,
        resolver=resolver_for({"example.com": ["93.184.216.34"]}),
    )
    await client.aclose()
    assert resp.status_code == 200
    assert seen["url_host"] == "93.184.216.34"  # connected to the pinned IP
    assert seen["host_header"] == "example.com"  # original authority preserved


async def test_blocks_when_any_resolved_address_out_of_scope():
    # in-scope A record + internal second address -> refuse (rebinding/split-horizon guard)
    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(lambda r: httpx.Response(200))
    with pytest.raises(egress.EgressBlocked):
        await egress.send(
            policy=policy,
            method="GET",
            url="https://example.com/",
            client=client,
            resolver=resolver_for({"example.com": ["93.184.216.34", "10.0.0.5"]}),
        )
    await client.aclose()


async def test_blocks_out_of_scope_ipv6_aaaa():
    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(lambda r: httpx.Response(200))
    with pytest.raises(egress.EgressBlocked):
        await egress.send(
            policy=policy,
            method="GET",
            url="https://example.com/",
            client=client,
            resolver=resolver_for({"example.com": ["93.184.216.34", "::1"]}),
        )
    await client.aclose()


async def test_redirect_to_out_of_scope_is_blocked():
    def handler(request):
        if request.headers.get("host") == "example.com":
            return httpx.Response(302, headers={"location": "https://evil.com/"})
        return httpx.Response(200)

    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(handler)
    with pytest.raises(egress.EgressBlocked):
        await egress.send(
            policy=policy,
            method="GET",
            url="https://example.com/",
            client=client,
            resolver=resolver_for(
                {"example.com": ["93.184.216.34"], "evil.com": ["93.184.216.34"]}
            ),
        )
    await client.aclose()


async def test_redirect_in_scope_is_followed():
    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        return httpx.Response(200, text="final")

    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(handler)
    resp = await egress.send(
        policy=policy,
        method="GET",
        url="https://example.com/a",
        client=client,
        resolver=resolver_for({"example.com": ["93.184.216.34"]}),
    )
    await client.aclose()
    assert resp.status_code == 200
    assert resp.text == "final"


async def test_redirect_hop_limit():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(302, headers={"location": "/loop"})

    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(handler)
    resp = await egress.send(
        policy=policy,
        method="GET",
        url="https://example.com/loop",
        client=client,
        resolver=resolver_for({"example.com": ["93.184.216.34"]}),
        max_hops=3,
    )
    await client.aclose()
    assert resp.status_code == 302
    assert calls["n"] == 4  # initial + 3 followed hops, then stop


async def test_out_of_scope_host_blocked_before_connect():
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200)

    policy = ScopePolicy([Rule("host", "example.com", True)])
    client = mk_client(handler)
    with pytest.raises(egress.EgressBlocked):
        await egress.send(
            policy=policy,
            method="GET",
            url="https://other.com/",
            client=client,
            resolver=resolver_for({"other.com": ["93.184.216.34"]}),
        )
    await client.aclose()
    assert called["n"] == 0  # never dialled
