"""
BlackRoad Rate Limiter - Multi-strategy rate limiting with SQLite backend
"""
from __future__ import annotations
import time
import json
import sqlite3
import threading
import logging
import functools
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class Strategy(Enum):
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimit:
    key: str
    limit: int
    window_sec: float
    strategy: Strategy = Strategy.FIXED_WINDOW
    burst_size: Optional[int] = None

    def effective_burst(self) -> int:
        return self.burst_size if self.burst_size is not None else self.limit


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_at: float
    retry_after: float = 0.0
    strategy: str = ""
    key: str = ""

    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "retry_after": self.retry_after,
            "strategy": self.strategy,
            "key": self.key,
        }


class FixedWindowLimiter:
    """Count requests per fixed time window."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_sec: float) -> RateLimitResult:
        now = time.time()
        window_start = int(now / window_sec) * window_sec
        window_end = window_start + window_sec
        window_key = f"{key}:{int(window_start)}"

        with self._lock:
            row = self.conn.execute(
                "SELECT count FROM fw_windows WHERE window_key=?", (window_key,)
            ).fetchone()
            count = row[0] if row else 0

            if count >= limit:
                return RateLimitResult(
                    allowed=False, remaining=0,
                    reset_at=window_end,
                    retry_after=window_end - now,
                    strategy="fixed_window", key=key,
                )

            if row:
                self.conn.execute("UPDATE fw_windows SET count=count+1 WHERE window_key=?", (window_key,))
            else:
                self.conn.execute(
                    "INSERT INTO fw_windows (window_key, count, expires_at) VALUES (?,?,?)",
                    (window_key, 1, window_end),
                )
            self.conn.commit()
            return RateLimitResult(
                allowed=True, remaining=limit - count - 1,
                reset_at=window_end, strategy="fixed_window", key=key,
            )

    def reset(self, key: str):
        with self._lock:
            self.conn.execute("DELETE FROM fw_windows WHERE window_key LIKE ?", (f"{key}:%",))
            self.conn.commit()

    def peek(self, key: str, limit: int, window_sec: float) -> int:
        now = time.time()
        window_start = int(now / window_sec) * window_sec
        window_key = f"{key}:{int(window_start)}"
        row = self.conn.execute("SELECT count FROM fw_windows WHERE window_key=?", (window_key,)).fetchone()
        count = row[0] if row else 0
        return max(0, limit - count)


class SlidingWindowLimiter:
    """Log-based sliding window: count timestamps within rolling window."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_sec: float) -> RateLimitResult:
        now = time.time()
        cutoff = now - window_sec

        with self._lock:
            # Purge old entries
            self.conn.execute(
                "DELETE FROM sw_log WHERE key=? AND timestamp<?", (key, cutoff)
            )
            count = self.conn.execute(
                "SELECT COUNT(*) FROM sw_log WHERE key=?", (key,)
            ).fetchone()[0]

            if count >= limit:
                oldest = self.conn.execute(
                    "SELECT MIN(timestamp) FROM sw_log WHERE key=?", (key,)
                ).fetchone()[0]
                retry_after = max(0.0, (oldest + window_sec) - now) if oldest else window_sec
                return RateLimitResult(
                    allowed=False, remaining=0,
                    reset_at=now + retry_after,
                    retry_after=retry_after,
                    strategy="sliding_window", key=key,
                )
            self.conn.execute(
                "INSERT INTO sw_log (key, timestamp) VALUES (?,?)", (key, now)
            )
            self.conn.commit()
            return RateLimitResult(
                allowed=True, remaining=limit - count - 1,
                reset_at=now + window_sec,
                strategy="sliding_window", key=key,
            )

    def reset(self, key: str):
        with self._lock:
            self.conn.execute("DELETE FROM sw_log WHERE key=?", (key,))
            self.conn.commit()

    def peek(self, key: str, limit: int, window_sec: float) -> int:
        now = time.time()
        cutoff = now - window_sec
        count = self.conn.execute(
            "SELECT COUNT(*) FROM sw_log WHERE key=? AND timestamp>=?", (key, cutoff)
        ).fetchone()[0]
        return max(0, limit - count)


class TokenBucketLimiter:
    """Refill tokens at rate r/sec, allow burst up to capacity."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()

    def _get_or_create(self, key: str, capacity: int, rate: float) -> Dict:
        row = self.conn.execute(
            "SELECT tokens, last_refill FROM tb_state WHERE key=?", (key,)
        ).fetchone()
        now = time.time()
        if not row:
            self.conn.execute(
                "INSERT INTO tb_state (key, tokens, capacity, rate, last_refill) VALUES (?,?,?,?,?)",
                (key, capacity, capacity, rate, now),
            )
            self.conn.commit()
            return {"tokens": capacity, "capacity": capacity, "rate": rate, "last_refill": now}
        tokens, last_refill = row[0], row[1]
        elapsed = now - last_refill
        new_tokens = min(capacity, tokens + elapsed * rate)
        return {"tokens": new_tokens, "capacity": capacity, "rate": rate, "last_refill": now}

    def check(self, key: str, limit: int, window_sec: float, burst: int, tokens_requested: int = 1) -> RateLimitResult:
        rate = limit / window_sec
        now = time.time()

        with self._lock:
            state = self._get_or_create(key, burst, rate)
            tokens = state["tokens"]

            if tokens >= tokens_requested:
                new_tokens = tokens - tokens_requested
                self.conn.execute(
                    "INSERT OR REPLACE INTO tb_state (key, tokens, capacity, rate, last_refill) VALUES (?,?,?,?,?)",
                    (key, new_tokens, burst, rate, now),
                )
                self.conn.commit()
                return RateLimitResult(
                    allowed=True,
                    remaining=int(new_tokens),
                    reset_at=now + (tokens_requested / rate) if rate > 0 else now,
                    strategy="token_bucket", key=key,
                )
            else:
                deficit = tokens_requested - tokens
                retry_after = deficit / rate if rate > 0 else window_sec
                return RateLimitResult(
                    allowed=False, remaining=0,
                    reset_at=now + retry_after,
                    retry_after=retry_after,
                    strategy="token_bucket", key=key,
                )

    def reset(self, key: str):
        with self._lock:
            self.conn.execute("DELETE FROM tb_state WHERE key=?", (key,))
            self.conn.commit()

    def peek(self, key: str, limit: int, window_sec: float, burst: int) -> int:
        rate = limit / window_sec
        row = self.conn.execute("SELECT tokens, last_refill, capacity FROM tb_state WHERE key=?", (key,)).fetchone()
        if not row:
            return burst
        tokens, last_refill, capacity = row
        elapsed = time.time() - last_refill
        return min(capacity, int(tokens + elapsed * rate))


class LeakyBucketLimiter:
    """Queue drains at a fixed rate; requests are accepted up to queue capacity."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_sec: float, burst: int) -> RateLimitResult:
        rate = limit / window_sec  # drain rate (requests/sec)
        now = time.time()

        with self._lock:
            row = self.conn.execute(
                "SELECT queue_size, last_leak FROM lb_state WHERE key=?", (key,)
            ).fetchone()

            if row:
                queue_size, last_leak = row[0], row[1]
                elapsed = now - last_leak
                leaked = int(elapsed * rate)
                queue_size = max(0, queue_size - leaked)
                last_leak = now
            else:
                queue_size = 0
                last_leak = now

            if queue_size >= burst:
                wait_time = (queue_size - burst + 1) / rate if rate > 0 else window_sec
                self.conn.execute(
                    "INSERT OR REPLACE INTO lb_state (key, queue_size, last_leak) VALUES (?,?,?)",
                    (key, queue_size, last_leak),
                )
                self.conn.commit()
                return RateLimitResult(
                    allowed=False, remaining=0,
                    reset_at=now + wait_time,
                    retry_after=wait_time,
                    strategy="leaky_bucket", key=key,
                )

            queue_size += 1
            self.conn.execute(
                "INSERT OR REPLACE INTO lb_state (key, queue_size, last_leak) VALUES (?,?,?)",
                (key, queue_size, last_leak),
            )
            self.conn.commit()
            return RateLimitResult(
                allowed=True, remaining=burst - queue_size,
                reset_at=now + (queue_size / rate) if rate > 0 else now,
                strategy="leaky_bucket", key=key,
            )

    def reset(self, key: str):
        with self._lock:
            self.conn.execute("DELETE FROM lb_state WHERE key=?", (key,))
            self.conn.commit()

    def peek(self, key: str, burst: int, limit: int, window_sec: float) -> int:
        rate = limit / window_sec
        row = self.conn.execute("SELECT queue_size, last_leak FROM lb_state WHERE key=?", (key,)).fetchone()
        if not row:
            return burst
        queue_size, last_leak = row
        elapsed = time.time() - last_leak
        effective = max(0, queue_size - int(elapsed * rate))
        return max(0, burst - effective)


class RateLimiter:
    """Unified rate limiter with multiple strategies and SQLite backend."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._fixed = FixedWindowLimiter(self.conn)
        self._sliding = SlidingWindowLimiter(self.conn)
        self._token = TokenBucketLimiter(self.conn)
        self._leaky = LeakyBucketLimiter(self.conn)
        self._stats_lock = threading.Lock()

    def _init_db(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS fw_windows (
                window_key TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sw_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sw_key_ts ON sw_log(key, timestamp);
            CREATE TABLE IF NOT EXISTS tb_state (
                key TEXT PRIMARY KEY,
                tokens REAL NOT NULL,
                capacity INTEGER NOT NULL,
                rate REAL NOT NULL,
                last_refill REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lb_state (
                key TEXT PRIMARY KEY,
                queue_size INTEGER NOT NULL DEFAULT 0,
                last_leak REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY,
                total_calls INTEGER NOT NULL DEFAULT 0,
                allowed_calls INTEGER NOT NULL DEFAULT 0,
                blocked_calls INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def _update_stats(self, key: str, allowed: bool):
        with self._stats_lock:
            row = self.conn.execute("SELECT total_calls, allowed_calls, blocked_calls FROM stats WHERE key=?", (key,)).fetchone()
            now = datetime.utcnow().isoformat()
            if row:
                total, allowed_c, blocked_c = row
                total += 1
                if allowed:
                    allowed_c += 1
                else:
                    blocked_c += 1
                self.conn.execute(
                    "UPDATE stats SET total_calls=?, allowed_calls=?, blocked_calls=?, updated_at=? WHERE key=?",
                    (total, allowed_c, blocked_c, now, key),
                )
            else:
                self.conn.execute(
                    "INSERT INTO stats (key, total_calls, allowed_calls, blocked_calls, updated_at) VALUES (?,?,?,?,?)",
                    (key, 1, 1 if allowed else 0, 0 if allowed else 1, now),
                )
            self.conn.commit()

    def check(
        self,
        key: str,
        limit: int,
        window: float,
        strategy: Strategy = Strategy.FIXED_WINDOW,
        burst_size: Optional[int] = None,
    ) -> RateLimitResult:
        burst = burst_size if burst_size is not None else limit
        if strategy == Strategy.FIXED_WINDOW:
            result = self._fixed.check(key, limit, window)
        elif strategy == Strategy.SLIDING_WINDOW:
            result = self._sliding.check(key, limit, window)
        elif strategy == Strategy.TOKEN_BUCKET:
            result = self._token.check(key, limit, window, burst)
        elif strategy == Strategy.LEAKY_BUCKET:
            result = self._leaky.check(key, limit, window, burst)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")
        self._update_stats(key, result.allowed)
        return result

    def consume(self, key: str, tokens: int = 1, strategy: Strategy = Strategy.TOKEN_BUCKET,
                limit: int = 100, window: float = 60.0, burst_size: Optional[int] = None) -> RateLimitResult:
        burst = burst_size if burst_size is not None else limit
        if strategy == Strategy.TOKEN_BUCKET:
            result = self._token.check(key, limit, window, burst, tokens_requested=tokens)
        else:
            result = self.check(key, limit, window, strategy, burst_size)
        self._update_stats(key, result.allowed)
        return result

    def reset(self, key: str, strategy: Optional[Strategy] = None):
        if strategy is None or strategy == Strategy.FIXED_WINDOW:
            self._fixed.reset(key)
        if strategy is None or strategy == Strategy.SLIDING_WINDOW:
            self._sliding.reset(key)
        if strategy is None or strategy == Strategy.TOKEN_BUCKET:
            self._token.reset(key)
        if strategy is None or strategy == Strategy.LEAKY_BUCKET:
            self._leaky.reset(key)
        with self._stats_lock:
            self.conn.execute("DELETE FROM stats WHERE key=?", (key,))
            self.conn.commit()

    def peek(self, key: str, limit: int, window: float,
             strategy: Strategy = Strategy.FIXED_WINDOW,
             burst_size: Optional[int] = None) -> int:
        burst = burst_size if burst_size is not None else limit
        if strategy == Strategy.FIXED_WINDOW:
            return self._fixed.peek(key, limit, window)
        elif strategy == Strategy.SLIDING_WINDOW:
            return self._sliding.peek(key, limit, window)
        elif strategy == Strategy.TOKEN_BUCKET:
            return self._token.peek(key, limit, window, burst)
        elif strategy == Strategy.LEAKY_BUCKET:
            return self._leaky.peek(key, burst, limit, window)
        return 0

    def get_stats(self, key: str) -> Dict:
        row = self.conn.execute(
            "SELECT total_calls, allowed_calls, blocked_calls FROM stats WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return {"total_calls": 0, "allowed": 0, "blocked": 0, "block_rate": 0.0}
        total, allowed, blocked = row
        return {
            "total_calls": total,
            "allowed": allowed,
            "blocked": blocked,
            "block_rate": round(blocked / total, 4) if total > 0 else 0.0,
        }

    def cleanup_expired(self) -> int:
        now = time.time()
        cur = self.conn.execute("DELETE FROM fw_windows WHERE expires_at<?", (now,))
        self.conn.commit()
        return cur.rowcount

    def rate_limit_decorator(
        self,
        key: str,
        limit: int,
        window: float,
        strategy: Strategy = Strategy.FIXED_WINDOW,
    ):
        """Decorator: raises RuntimeError when rate limit is exceeded."""
        def decorate(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                result = self.check(key, limit, window, strategy)
                if not result.allowed:
                    raise RuntimeError(
                        f"Rate limit exceeded for '{key}'. Retry after {result.retry_after:.2f}s"
                    )
                return fn(*args, **kwargs)
            return wrapper
        return decorate
