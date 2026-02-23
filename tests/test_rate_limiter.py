"""Tests for BlackRoad Rate Limiter"""
import time
import pytest
from rate_limiter import (
    RateLimiter, Strategy, RateLimit, RateLimitResult,
    FixedWindowLimiter, SlidingWindowLimiter, TokenBucketLimiter, LeakyBucketLimiter,
)
import sqlite3


@pytest.fixture
def limiter():
    return RateLimiter(":memory:")


class TestFixedWindow:
    def test_allows_within_limit(self, limiter):
        for _ in range(5):
            result = limiter.check("user:1", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
            assert result.allowed is True

    def test_blocks_when_exceeded(self, limiter):
        for _ in range(3):
            limiter.check("user:fw", limit=3, window=60.0, strategy=Strategy.FIXED_WINDOW)
        result = limiter.check("user:fw", limit=3, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert result.allowed is False

    def test_remaining_decrements(self, limiter):
        r1 = limiter.check("fw:rem", limit=5, window=60.0, strategy=Strategy.FIXED_WINDOW)
        r2 = limiter.check("fw:rem", limit=5, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert r2.remaining < r1.remaining

    def test_reset_clears_count(self, limiter):
        for _ in range(3):
            limiter.check("fw:reset", limit=3, window=60.0, strategy=Strategy.FIXED_WINDOW)
        limiter.reset("fw:reset", Strategy.FIXED_WINDOW)
        result = limiter.check("fw:reset", limit=3, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert result.allowed is True

    def test_result_has_strategy(self, limiter):
        result = limiter.check("fw:strat", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert result.strategy == "fixed_window"


class TestSlidingWindow:
    def test_allows_within_limit(self, limiter):
        for _ in range(5):
            result = limiter.check("sw:user", limit=10, window=60.0, strategy=Strategy.SLIDING_WINDOW)
            assert result.allowed is True

    def test_blocks_when_exceeded(self, limiter):
        for _ in range(3):
            limiter.check("sw:block", limit=3, window=60.0, strategy=Strategy.SLIDING_WINDOW)
        result = limiter.check("sw:block", limit=3, window=60.0, strategy=Strategy.SLIDING_WINDOW)
        assert result.allowed is False

    def test_result_strategy(self, limiter):
        result = limiter.check("sw:strat", limit=10, window=60.0, strategy=Strategy.SLIDING_WINDOW)
        assert result.strategy == "sliding_window"


class TestTokenBucket:
    def test_allows_burst(self, limiter):
        results = [
            limiter.check("tb:user", limit=10, window=60.0, strategy=Strategy.TOKEN_BUCKET, burst_size=5)
            for _ in range(5)
        ]
        assert all(r.allowed for r in results)

    def test_blocks_when_tokens_exhausted(self, limiter):
        for _ in range(5):
            limiter.check("tb:exhaust", limit=10, window=60.0, strategy=Strategy.TOKEN_BUCKET, burst_size=5)
        result = limiter.check("tb:exhaust", limit=10, window=60.0, strategy=Strategy.TOKEN_BUCKET, burst_size=5)
        assert result.allowed is False

    def test_result_strategy(self, limiter):
        result = limiter.check("tb:strat", limit=10, window=60.0, strategy=Strategy.TOKEN_BUCKET)
        assert result.strategy == "token_bucket"

    def test_consume_multiple_tokens(self, limiter):
        result = limiter.consume("tb:multi", tokens=3, strategy=Strategy.TOKEN_BUCKET, limit=10, window=60.0, burst_size=10)
        assert result.allowed is True


class TestLeakyBucket:
    def test_allows_within_capacity(self, limiter):
        for _ in range(3):
            result = limiter.check("lb:user", limit=10, window=60.0, strategy=Strategy.LEAKY_BUCKET, burst_size=5)
            assert result.allowed is True

    def test_blocks_when_full(self, limiter):
        for _ in range(5):
            limiter.check("lb:full", limit=5, window=60.0, strategy=Strategy.LEAKY_BUCKET, burst_size=5)
        result = limiter.check("lb:full", limit=5, window=60.0, strategy=Strategy.LEAKY_BUCKET, burst_size=5)
        assert result.allowed is False

    def test_result_strategy(self, limiter):
        result = limiter.check("lb:strat", limit=10, window=60.0, strategy=Strategy.LEAKY_BUCKET)
        assert result.strategy == "leaky_bucket"


class TestStats:
    def test_stats_after_calls(self, limiter):
        limiter.check("stats:user", limit=10, window=60.0)
        limiter.check("stats:user", limit=10, window=60.0)
        stats = limiter.get_stats("stats:user")
        assert stats["total_calls"] == 2
        assert stats["allowed"] == 2

    def test_stats_blocked_calls(self, limiter):
        for _ in range(3):
            limiter.check("stats:block", limit=2, window=60.0)
        stats = limiter.get_stats("stats:block")
        assert stats["blocked"] >= 1

    def test_block_rate(self, limiter):
        limiter.check("stats:rate", limit=1, window=60.0)
        limiter.check("stats:rate", limit=1, window=60.0)
        stats = limiter.get_stats("stats:rate")
        assert stats["block_rate"] > 0

    def test_empty_stats(self, limiter):
        stats = limiter.get_stats("nonexistent:key")
        assert stats["total_calls"] == 0


class TestPeek:
    def test_peek_returns_remaining(self, limiter):
        remaining = limiter.peek("peek:user", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert remaining == 10

    def test_peek_after_calls(self, limiter):
        limiter.check("peek:used", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
        limiter.check("peek:used", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
        remaining = limiter.peek("peek:used", limit=10, window=60.0, strategy=Strategy.FIXED_WINDOW)
        assert remaining == 8


class TestRateLimitResult:
    def test_to_dict(self):
        r = RateLimitResult(allowed=True, remaining=5, reset_at=time.time() + 60, strategy="fixed_window", key="x")
        d = r.to_dict()
        assert d["allowed"] is True
        assert d["remaining"] == 5

    def test_result_has_reset_at(self, limiter):
        result = limiter.check("x", limit=10, window=60.0)
        assert result.reset_at > time.time()


class TestDecorator:
    def test_decorator_allows_call(self, limiter):
        @limiter.rate_limit_decorator("deco:svc", limit=10, window=60.0)
        def my_func():
            return "ok"
        assert my_func() == "ok"

    def test_decorator_raises_on_exceeded(self, limiter):
        @limiter.rate_limit_decorator("deco:blocked", limit=2, window=60.0)
        def my_func():
            return "ok"
        my_func()
        my_func()
        with pytest.raises(RuntimeError):
            my_func()
