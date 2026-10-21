import asyncio

import pytest

from chain.ratelimit import RateLimiter


async def test_token_bucket_delays_second_request():
    t = {"v": 0.0}

    def clock():
        return t["v"]

    async def sleep(d):
        t["v"] += d  # fake sleep advances the virtual clock

    rl = RateLimiter(rps=10, concurrency=5, burst=1, clock=clock, sleep=sleep)
    await rl._take()  # consumes the single burst token, no wait
    start = t["v"]
    await rl._take()  # empty bucket -> must wait 1/rps = 0.1s
    assert t["v"] - start == pytest.approx(0.1, rel=0.2)


async def test_concurrency_cap_is_enforced():
    rl = RateLimiter(rps=1000, concurrency=2)  # rps high so no token stalls
    current = 0
    peak = 0

    async def job():
        nonlocal current, peak
        async with rl.slot():
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.01)
            current -= 1

    await asyncio.gather(*[job() for _ in range(8)])
    assert peak <= 2
