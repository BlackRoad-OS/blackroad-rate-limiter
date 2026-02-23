"""Tests for blackroad-rate-limiter."""
import os
import time
import tempfile
import pytest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from module import (
    check_rate_limit, reset_limit, set_custom_limit, get_stats,
    cleanup_expired, list_keys, get_violations, create_token_bucket,
    init_db, TokenBucket, RateLimit,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_rate_limiter.db")


class TestCheckRateLimit:
    def test_allows_requests_within_limit(self, db_path):
        allowed, remaining, retry_after = check_rate_limit("user:1", limit=5, window=60, db_path=db_path)
        assert allowed is True
        assert remaining == 4
        assert retry_after == 0.0

    def test_counts_down_remaining(self, db_path):
        for i in range(4):
            allowed, remaining, _ = check_rate_limit("user:2", limit=5, window=60, db_path=db_path)
            assert allowed is True
            assert remaining == 4 - i - 1

    def test_blocks_when_limit_exceeded(self, db_path):
        for _ in range(5):
            check_rate_limit("user:3", limit=5, window=60, db_path=db_path)
        allowed, remaining, retry_after = check_rate_limit("user:3", limit=5, window=60, db_path=db_path)
        assert allowed is False
        assert remaining == 0
        assert retry_after > 0

    def test_different_keys_are_independent(self, db_path):
        for _ in range(5):
            check_rate_limit("user:4", limit=5, window=60, db_path=db_path)
        # user:4 is exhausted, user:5 is fresh
        allowed_4, _, _ = check_rate_limit("user:4", limit=5, window=60, db_path=db_path)
        allowed_5, remaining_5, _ = check_rate_limit("user:5", limit=5, window=60, db_path=db_path)
        assert allowed_4 is False
        assert allowed_5 is True
        assert remaining_5 == 4

    def test_returns_retry_after_positive_when_blocked(self, db_path):
        for _ in range(3):
            check_rate_limit("user:6", limit=3, window=10, db_path=db_path)
        _, _, retry_after = check_rate_limit("user:6", limit=3, window=10, db_path=db_path)
        assert 0 < retry_after <= 10

    def test_violation_recorded_on_block(self, db_path):
        for _ in range(3):
            check_rate_limit("user:7", limit=3, window=60, db_path=db_path)
        check_rate_limit("user:7", limit=3, window=60, db_path=db_path)
        viols = get_violations("user:7", db_path=db_path)
        assert len(viols) >= 1
        assert viols[0]["key"] == "user:7"


class TestResetLimit:
    def test_reset_clears_count(self, db_path):
        for _ in range(5):
            check_rate_limit("user:r1", limit=5, window=60, db_path=db_path)
        reset_limit("user:r1", db_path=db_path)
        allowed, remaining, _ = check_rate_limit("user:r1", limit=5, window=60, db_path=db_path)
        assert allowed is True
        assert remaining == 4

    def test_reset_clears_violations(self, db_path):
        for _ in range(6):
            check_rate_limit("user:r2", limit=5, window=60, db_path=db_path)
        reset_limit("user:r2", db_path=db_path)
        viols = get_violations("user:r2", db_path=db_path)
        assert viols == []

    def test_reset_nonexistent_key_is_noop(self, db_path):
        # Should not raise
        reset_limit("nonexistent:key", db_path=db_path)


class TestSetCustomLimit:
    def test_custom_limit_overrides_default(self, db_path):
        set_custom_limit("ip:1.2.3.4", limit=2, window=60, db_path=db_path)
        check_rate_limit("ip:1.2.3.4", db_path=db_path)
        check_rate_limit("ip:1.2.3.4", db_path=db_path)
        allowed, _, _ = check_rate_limit("ip:1.2.3.4", db_path=db_path)
        assert allowed is False

    def test_custom_limit_appears_in_list(self, db_path):
        set_custom_limit("svc:alpha", limit=50, window=30, db_path=db_path)
        keys = list_keys(db_path=db_path)
        found = [k for k in keys if k["key"] == "svc:alpha"]
        assert len(found) == 1
        assert found[0]["limit_count"] == 50
        assert found[0]["window_secs"] == 30


class TestGetStats:
    def test_stats_returns_expected_fields(self, db_path):
        check_rate_limit("stats:1", limit=10, window=60, db_path=db_path)
        stats = get_stats("stats:1", db_path=db_path)
        expected = {
            "key", "current_count", "limit", "window_secs",
            "remaining", "utilization_pct", "requests_last_hour",
            "total_violations", "violations_last_hour", "reset_at",
        }
        assert expected.issubset(stats.keys())

    def test_stats_utilization_calculated_correctly(self, db_path):
        set_custom_limit("stats:2", limit=10, window=60, db_path=db_path)
        for _ in range(5):
            check_rate_limit("stats:2", db_path=db_path)
        stats = get_stats("stats:2", db_path=db_path)
        assert stats["current_count"] == 5
        assert stats["utilization_pct"] == 50.0
        assert stats["remaining"] == 5

    def test_stats_violation_count(self, db_path):
        set_custom_limit("stats:3", limit=2, window=60, db_path=db_path)
        for _ in range(4):
            check_rate_limit("stats:3", db_path=db_path)
        stats = get_stats("stats:3", db_path=db_path)
        assert stats["total_violations"] >= 2


class TestCleanupExpired:
    def test_cleanup_returns_integer(self, db_path):
        check_rate_limit("clean:1", limit=100, window=60, db_path=db_path)
        result = cleanup_expired(db_path=db_path)
        assert isinstance(result, int)
        assert result >= 0

    def test_cleanup_on_empty_db(self, db_path):
        init_db(db_path)
        result = cleanup_expired(db_path=db_path)
        assert result == 0


class TestTokenBucket:
    def test_consume_within_capacity(self):
        bucket = create_token_bucket("svc", capacity=10, refill_rate=1.0)
        assert bucket.consume(5) is True
        assert bucket.available() == pytest.approx(5.0, abs=0.1)

    def test_consume_exceeds_capacity(self):
        bucket = create_token_bucket("svc", capacity=3, refill_rate=1.0)
        assert bucket.consume(3) is True
        assert bucket.consume(1) is False

    def test_refill_over_time(self):
        bucket = TokenBucket(key="svc", capacity=10, refill_rate=10.0, tokens=0.0)
        bucket.last_refill = time.time() - 1.0   # simulate 1 s elapsed
        assert bucket.available() >= 9.9

    def test_time_until_available(self):
        bucket = TokenBucket(key="svc", capacity=10, refill_rate=2.0, tokens=0.0)
        wait = bucket.time_until_available(4)
        assert wait == pytest.approx(2.0, abs=0.1)

    def test_to_dict_contains_fields(self):
        bucket = create_token_bucket("svc", capacity=5, refill_rate=1.0)
        d = bucket.to_dict()
        assert {"key", "capacity", "refill_rate", "tokens", "last_refill"} == set(d.keys())


class TestRateLimitDataclass:
    def test_is_exceeded_false_when_under(self):
        rl = RateLimit(key="x", limit=10, window_secs=60, count=5)
        assert rl.is_exceeded() is False

    def test_is_exceeded_true_when_at_limit(self):
        rl = RateLimit(key="x", limit=10, window_secs=60, count=10)
        assert rl.is_exceeded() is True

    def test_remaining_calculated(self):
        rl = RateLimit(key="x", limit=10, window_secs=60, count=3)
        assert rl.remaining() == 7

    def test_to_dict_has_expected_keys(self):
        rl = RateLimit(key="x", limit=10, window_secs=60)
        d = rl.to_dict()
        assert "key" in d and "remaining" in d and "seconds_until_reset" in d


class TestListKeys:
    def test_empty_db_returns_empty_list(self, db_path):
        init_db(db_path)
        assert list_keys(db_path=db_path) == []

    def test_after_check_key_appears(self, db_path):
        check_rate_limit("tracked:key", limit=10, window=60, db_path=db_path)
        keys = list_keys(db_path=db_path)
        names = [k["key"] for k in keys]
        assert "tracked:key" in names
