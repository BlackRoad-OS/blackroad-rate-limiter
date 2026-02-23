# blackroad-rate-limiter

Sliding window rate limiting with SQLite persistence for BlackRoad OS.

## Features

- **Sliding window algorithm** — accurate per-key request counting with timestamped entries
- **Token bucket** — burst limiting with configurable capacity and refill rate
- **Per-key custom limits** — override defaults per user, IP, or service
- **Violation tracking** — full log of rate-limit breaches with retry-after times
- **Automatic cleanup** — purge entries older than 24 h / violations older than 7 days
- **SQLite-backed** — zero external dependencies, works anywhere Python runs

## Install

```bash
pip install -e .
```

## Quick Start

```python
from src.module import check_rate_limit, set_custom_limit

# Check / consume one token for key "user:42"
allowed, remaining, retry_after = check_rate_limit("user:42", limit=100, window=60)
if not allowed:
    print(f"Rate limited. Retry after {retry_after:.1f}s")

# Custom limit for a specific key
set_custom_limit("ip:10.0.0.1", limit=10, window=60)
```

## CLI

```bash
python src/module.py check user:42 --limit 100 --window 60
python src/module.py set   user:42 10 60
python src/module.py stats user:42
python src/module.py violations user:42
python src/module.py reset user:42
python src/module.py cleanup
python src/module.py list
```

## API Reference

| Function | Description |
|---|---|
| `check_rate_limit(key, limit, window)` | Returns `(allowed, remaining, retry_after)` |
| `reset_limit(key)` | Clear all state for a key |
| `set_custom_limit(key, limit, window)` | Persist a custom config |
| `get_stats(key)` | Stats dict with utilisation metrics |
| `cleanup_expired()` | Purge stale DB entries |
| `create_token_bucket(key, capacity, rate)` | Build a `TokenBucket` |

## Schema

```sql
rate_limits               -- custom config + counters per key
sliding_window_requests   -- per-request timestamp log
violations                -- blocked request log
```

## Tests

```bash
pytest tests/ -v
```
