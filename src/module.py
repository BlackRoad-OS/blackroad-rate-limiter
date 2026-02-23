#!/usr/bin/env python3
"""BlackRoad Rate Limiter
========================
Sliding window rate limiting with SQLite persistence.
Supports per-key custom limits, violation tracking, and token bucket bursting.
"""

import sqlite3
import time
import argparse
import json
import os
import math
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path

DB_PATH = os.environ.get("RATE_LIMITER_DB", str(Path.home() / ".blackroad" / "rate_limiter.db"))


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class RateLimit:
    """Represents the persisted rate-limit configuration and counter for a key."""
    key: str
    limit: int
    window_secs: int
    count: int = 0
    reset_at: float = field(default_factory=time.time)

    def is_exceeded(self) -> bool:
        return self.count >= self.limit

    def remaining(self) -> int:
        return max(0, self.limit - self.count)

    def seconds_until_reset(self) -> float:
        return max(0.0, self.reset_at - time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "limit": self.limit,
            "window_secs": self.window_secs,
            "count": self.count,
            "reset_at": self.reset_at,
            "remaining": self.remaining(),
            "seconds_until_reset": round(self.seconds_until_reset(), 2),
        }


@dataclass
class TokenBucket:
    """
    Token bucket for burst rate limiting.
    Tokens refill at *refill_rate* tokens/second up to *capacity*.
    """
    key: str
    capacity: int
    refill_rate: float          # tokens per second
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume *tokens*. Returns True if successful."""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def available(self) -> float:
        """Currently available token count (may be fractional)."""
        self._refill()
        return self.tokens

    def time_until_available(self, tokens: int = 1) -> float:
        """Seconds until *tokens* tokens are available."""
        self._refill()
        if self.tokens >= tokens:
            return 0.0
        needed = tokens - self.tokens
        return needed / self.refill_rate if self.refill_rate > 0 else math.inf

    def to_dict(self) -> Dict[str, Any]:
        self._refill()
        return {
            "key": self.key,
            "capacity": self.capacity,
            "refill_rate": self.refill_rate,
            "tokens": round(self.tokens, 3),
            "last_refill": self.last_refill,
        }


@dataclass
class ViolationRecord:
    """A single rate-limit violation log entry."""
    id: Optional[int]
    key: str
    attempted_at: float
    limit_count: int
    window_secs: int
    retry_after: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "attempted_at": self.attempted_at,
            "limit_count": self.limit_count,
            "window_secs": self.window_secs,
            "retry_after": round(self.retry_after, 2),
        }


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _ensure_dir(db_path: str) -> None:
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Return a WAL-mode SQLite connection with row_factory set."""
    _ensure_dir(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    """Create tables and indexes if they do not exist."""
    _ensure_dir(db_path)
    with get_db_connection(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                key            TEXT    PRIMARY KEY,
                limit_count    INTEGER NOT NULL DEFAULT 100,
                window_secs    INTEGER NOT NULL DEFAULT 60,
                count          INTEGER NOT NULL DEFAULT 0,
                reset_at       REAL    NOT NULL,
                created_at     REAL    NOT NULL,
                updated_at     REAL    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS violations (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                key            TEXT    NOT NULL,
                attempted_at   REAL    NOT NULL,
                limit_count    INTEGER NOT NULL,
                window_secs    INTEGER NOT NULL,
                retry_after    REAL    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sliding_window_requests (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key        TEXT    NOT NULL,
                timestamp  REAL    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_swr_key_ts
                ON sliding_window_requests(key, timestamp);
            CREATE INDEX IF NOT EXISTS idx_violations_key_ts
                ON violations(key, attempted_at);
        """)


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def check_rate_limit(
    key: str,
    limit: int = 100,
    window: int = 60,
    db_path: str = DB_PATH,
) -> Tuple[bool, int, float]:
    """
    Sliding-window rate-limit check.

    Parameters
    ----------
    key    : Unique identifier, e.g. "user:42" or "ip:10.0.0.1"
    limit  : Maximum requests allowed in *window* seconds
    window : Window duration in seconds
    db_path: SQLite database path

    Returns
    -------
    (allowed, remaining, retry_after)
        allowed     – True when the request is permitted
        remaining   – Requests still available in the current window
        retry_after – Seconds to wait before retrying (0.0 when allowed)
    """
    init_db(db_path)
    now = time.time()

    with get_db_connection(db_path) as conn:
        # Load custom configuration if present
        custom = conn.execute(
            "SELECT limit_count, window_secs FROM rate_limits WHERE key = ?", (key,)
        ).fetchone()
        if custom:
            limit = custom["limit_count"]
            window = custom["window_secs"]

        window_start = now - window

        # Prune requests outside the sliding window for this key
        conn.execute(
            "DELETE FROM sliding_window_requests WHERE key = ? AND timestamp < ?",
            (key, window_start),
        )

        # Count requests inside the window
        current_count = conn.execute(
            "SELECT COUNT(*) AS cnt "
            "FROM sliding_window_requests WHERE key = ? AND timestamp >= ?",
            (key, window_start),
        ).fetchone()["cnt"]

        if current_count >= limit:
            # Compute retry_after from the oldest request still in the window
            oldest_row = conn.execute(
                "SELECT MIN(timestamp) AS ts "
                "FROM sliding_window_requests WHERE key = ? AND timestamp >= ?",
                (key, window_start),
            ).fetchone()
            oldest_ts = oldest_row["ts"] if oldest_row and oldest_row["ts"] else now
            retry_after = max(0.0, oldest_ts + window - now)

            conn.execute(
                "INSERT INTO violations (key, attempted_at, limit_count, window_secs, retry_after) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, now, limit, window, retry_after),
            )
            conn.execute(
                """
                INSERT INTO rate_limits
                    (key, limit_count, window_secs, count, reset_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    count      = ?,
                    updated_at = excluded.updated_at
                """,
                (key, limit, window, current_count, now + retry_after, now, now, current_count),
            )
            return False, 0, round(retry_after, 4)

        # --- Request allowed ---
        conn.execute(
            "INSERT INTO sliding_window_requests (key, timestamp) VALUES (?, ?)",
            (key, now),
        )
        remaining = limit - current_count - 1
        conn.execute(
            """
            INSERT INTO rate_limits
                (key, limit_count, window_secs, count, reset_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                limit_count = excluded.limit_count,
                window_secs = excluded.window_secs,
                count       = ?,
                reset_at    = excluded.reset_at,
                updated_at  = excluded.updated_at
            """,
            (key, limit, window, current_count + 1, now + window, now, now, current_count + 1),
        )
        return True, remaining, 0.0


def reset_limit(key: str, db_path: str = DB_PATH) -> None:
    """
    Reset the rate limit for *key*: remove all request history, violations,
    and custom configuration.
    """
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        conn.execute("DELETE FROM sliding_window_requests WHERE key = ?", (key,))
        conn.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
        conn.execute("DELETE FROM violations WHERE key = ?", (key,))


def set_custom_limit(key: str, limit: int, window: int, db_path: str = DB_PATH) -> None:
    """Persist a custom rate-limit configuration for *key*."""
    init_db(db_path)
    now = time.time()
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO rate_limits
                (key, limit_count, window_secs, count, reset_at, created_at, updated_at)
            VALUES (?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                limit_count = excluded.limit_count,
                window_secs = excluded.window_secs,
                updated_at  = excluded.updated_at
            """,
            (key, limit, window, now + window, now, now),
        )


def get_stats(key: str, db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Return statistics for *key* covering:
      - current window utilisation
      - request and violation counts over the last hour
      - all-time violation count
    """
    init_db(db_path)
    now = time.time()

    with get_db_connection(db_path) as conn:
        rl = conn.execute(
            "SELECT * FROM rate_limits WHERE key = ?", (key,)
        ).fetchone()
        limit = rl["limit_count"] if rl else 100
        window = rl["window_secs"] if rl else 60
        window_start = now - window

        current = conn.execute(
            "SELECT COUNT(*) AS cnt FROM sliding_window_requests "
            "WHERE key = ? AND timestamp >= ?",
            (key, window_start),
        ).fetchone()["cnt"]

        hour_ago = now - 3600
        req_1h = conn.execute(
            "SELECT COUNT(*) AS cnt FROM sliding_window_requests "
            "WHERE key = ? AND timestamp >= ?",
            (key, hour_ago),
        ).fetchone()["cnt"]

        total_viols = conn.execute(
            "SELECT COUNT(*) AS cnt FROM violations WHERE key = ?", (key,)
        ).fetchone()["cnt"]

        viols_1h = conn.execute(
            "SELECT COUNT(*) AS cnt FROM violations "
            "WHERE key = ? AND attempted_at >= ?",
            (key, hour_ago),
        ).fetchone()["cnt"]

    return {
        "key": key,
        "current_count": current,
        "limit": limit,
        "window_secs": window,
        "remaining": max(0, limit - current),
        "utilization_pct": round(current / limit * 100, 2) if limit else 0,
        "requests_last_hour": req_1h,
        "total_violations": total_viols,
        "violations_last_hour": viols_1h,
        "reset_at": rl["reset_at"] if rl else now + window,
    }


def cleanup_expired(db_path: str = DB_PATH) -> int:
    """
    Purge stale data:
      - sliding_window_requests older than 24 hours
      - violations older than 7 days
    Returns the number of sliding-window rows removed.
    """
    init_db(db_path)
    now = time.time()
    with get_db_connection(db_path) as conn:
        res = conn.execute(
            "DELETE FROM sliding_window_requests WHERE timestamp < ?", (now - 86_400,)
        )
        cleaned = res.rowcount
        conn.execute(
            "DELETE FROM violations WHERE attempted_at < ?", (now - 7 * 86_400,)
        )
    return cleaned


def list_keys(db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Return all tracked keys with their current configuration."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT key, limit_count, window_secs, count, reset_at "
            "FROM rate_limits ORDER BY key"
        ).fetchall()
    return [dict(r) for r in rows]


def get_violations(key: str, limit: int = 20, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Return the most recent violations for *key*, newest first."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM violations WHERE key = ? "
            "ORDER BY attempted_at DESC LIMIT ?",
            (key, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def create_token_bucket(key: str, capacity: int, refill_rate: float) -> TokenBucket:
    """Create a fully-loaded TokenBucket instance."""
    return TokenBucket(
        key=key, capacity=capacity, refill_rate=refill_rate, tokens=float(capacity)
    )


def bulk_check(
    keys: List[str], limit: int = 100, window: int = 60, db_path: str = DB_PATH
) -> Dict[str, bool]:
    """Check multiple keys at once. Returns {key: allowed} mapping."""
    return {k: check_rate_limit(k, limit, window, db_path)[0] for k in keys}


def get_rate_limit_headers(
    key: str, limit: int = 100, window: int = 60, db_path: str = DB_PATH
) -> Dict[str, str]:
    """
    Return HTTP-style rate-limit response headers without consuming a token.
    Useful for probing current state before a request is made.
    """
    stats = get_stats(key, db_path)
    now = time.time()
    reset_after = max(0, int(stats["reset_at"] - now))
    return {
        "X-RateLimit-Limit": str(stats["limit"]),
        "X-RateLimit-Remaining": str(stats["remaining"]),
        "X-RateLimit-Reset": str(int(stats["reset_at"])),
        "X-RateLimit-Window": str(stats["window_secs"]),
        "Retry-After": str(reset_after),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="BlackRoad Rate Limiter – sliding window rate limiting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s check user:42 --limit 10 --window 60\n"
               "  %(prog)s set user:42 10 60\n"
               "  %(prog)s stats user:42\n"
               "  %(prog)s violations user:42\n"
               "  %(prog)s reset user:42\n"
               "  %(prog)s cleanup\n"
               "  %(prog)s list\n",
    )
    parser.add_argument("--db", default=DB_PATH, metavar="PATH", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p = sub.add_parser("check", help="Test whether a key is within its rate limit")
    p.add_argument("key", help="Rate-limit key, e.g. user:42")
    p.add_argument("--limit", type=int, default=100, help="Max requests per window (default 100)")
    p.add_argument("--window", type=int, default=60, help="Window in seconds (default 60)")

    # reset
    p = sub.add_parser("reset", help="Clear all state and history for a key")
    p.add_argument("key")

    # set
    p = sub.add_parser("set", help="Configure a custom limit for a key")
    p.add_argument("key")
    p.add_argument("limit", type=int, help="Max requests")
    p.add_argument("window", type=int, help="Window in seconds")

    # stats
    p = sub.add_parser("stats", help="Show current statistics for a key")
    p.add_argument("key")

    # cleanup
    sub.add_parser("cleanup", help="Remove expired entries from the database")

    # list
    sub.add_parser("list", help="List all tracked keys and their configurations")

    # violations
    p = sub.add_parser("violations", help="Show recent violations for a key")
    p.add_argument("key")
    p.add_argument("--limit", type=int, default=20, dest="max_rows", help="Max rows to return")

    args = parser.parse_args()
    db = args.db

    if args.command == "check":
        allowed, remaining, retry_after = check_rate_limit(
            args.key, args.limit, args.window, db
        )
        print(json.dumps({
            "allowed": allowed,
            "remaining": remaining,
            "retry_after": retry_after,
            "key": args.key,
        }, indent=2))
        raise SystemExit(0 if allowed else 1)

    elif args.command == "reset":
        reset_limit(args.key, db)
        print(f"Reset rate limit for key: {args.key!r}")

    elif args.command == "set":
        set_custom_limit(args.key, args.limit, args.window, db)
        print(f"Custom limit set: {args.key!r} -> {args.limit} req / {args.window}s")

    elif args.command == "stats":
        print(json.dumps(get_stats(args.key, db), indent=2))

    elif args.command == "cleanup":
        n = cleanup_expired(db)
        print(f"Cleaned up {n} expired sliding-window entries")

    elif args.command == "list":
        rows = list_keys(db)
        print(json.dumps(rows, indent=2) if rows else "No keys tracked yet.")

    elif args.command == "violations":
        rows = get_violations(args.key, args.max_rows, db)
        print(json.dumps(rows, indent=2) if rows else f"No violations for key: {args.key!r}")


if __name__ == "__main__":
    main()
