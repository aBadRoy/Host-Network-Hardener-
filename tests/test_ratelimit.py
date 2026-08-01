"""Tests for the global rate limiter."""

import time

from hardener.ratelimit import RateLimiter


def test_disabled_limiter_does_not_block():
    limiter = RateLimiter(0)
    start = time.time()
    for _ in range(10):
        limiter.acquire()
    assert time.time() - start < 0.5


def test_limiter_enforces_interval():
    limiter = RateLimiter(100)  # 10ms between probes
    start = time.time()
    for _ in range(5):
        limiter.acquire()
    elapsed = time.time() - start
    assert elapsed >= 0.04  # 4 intervals x 10ms


def test_limiter_tracks_sent():
    limiter = RateLimiter(0)
    for _ in range(7):
        limiter.acquire()
    assert limiter.sent == 7


def test_enabled_property():
    assert RateLimiter(0).enabled is False
    assert RateLimiter(50).enabled is True
