# blackroad-rate-limiter

> Multi-strategy rate limiting with SQLite backend — part of the BlackRoad OS developer platform.

## Features

- 🪟 **Fixed Window** — Simple count per time window
- 🌊 **Sliding Window** — Log-based rolling window
- 🪣 **Token Bucket** — Burst-friendly with token refill
- 💧 **Leaky Bucket** — Smooth queue drain rate
- 📊 **Stats** — Per-key call statistics and block rates
- 🔍 **Peek** — Check remaining capacity without consuming
- 🎯 **Decorator API** — `@rate_limit_decorator(key, limit, window)`
- 💾 **SQLite Backend** — Persistent with TTL cleanup

## Quick Start

```python
from rate_limiter import RateLimiter, Strategy

limiter = RateLimiter()

# Fixed window
result = limiter.check("user:123", limit=100, window=60.0, strategy=Strategy.FIXED_WINDOW)
print(result.allowed, result.remaining)

# Token bucket with burst
result = limiter.check("api:key", limit=60, window=60.0, strategy=Strategy.TOKEN_BUCKET, burst_size=10)

# Decorator
@limiter.rate_limit_decorator("my_endpoint", limit=10, window=1.0)
def handle_request():
    return process()

# Stats
print(limiter.get_stats("user:123"))
```

## Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| FixedWindow | Count per time slot | Simple APIs |
| SlidingWindow | Rolling timestamp log | Smooth limits |
| TokenBucket | Refill at rate r/s | Burst traffic |
| LeakyBucket | Fixed drain rate | Smooth output |

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=rate_limiter
```

## License

Proprietary — © BlackRoad OS, Inc.
