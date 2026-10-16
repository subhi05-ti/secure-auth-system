from app.core.rate_limit import InMemoryRateLimiter


def test_rate_limiter_under_limit():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=10)
    allowed, retry_after = limiter._clean_and_check("127.0.0.1")
    assert allowed is True
    assert retry_after == 0

    allowed, retry_after = limiter._clean_and_check("127.0.0.1")
    assert allowed is True

    allowed, retry_after = limiter._clean_and_check("127.0.0.1")
    assert allowed is True

    # 4th request exceeds max_requests of 3
    allowed, retry_after = limiter._clean_and_check("127.0.0.1")
    assert allowed is False
    assert retry_after > 0

    # Different IP should still be allowed
    allowed_other, _ = limiter._clean_and_check("192.168.1.1")
    assert allowed_other is True
