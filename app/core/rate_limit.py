import time
from collections import defaultdict

from fastapi import HTTPException, Request, status

from app.core.config import get_settings

settings = get_settings()


class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter per client IP."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history: dict[str, list[float]] = defaultdict(list)

    def _clean_and_check(self, client_ip: str) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        # Keep only timestamps within window
        recent = [t for t in self.history[client_ip] if t > cutoff]
        self.history[client_ip] = recent

        if len(recent) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - recent[0])) + 1
            return False, max(1, retry_after)

        self.history[client_ip].append(now)
        return True, 0

    async def __call__(self, request: Request) -> None:
        # Determine client IP (handles standard X-Forwarded-For if behind reverse proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        client_ip = (
            forwarded_for.split(",")[0].strip()
            if forwarded_for
            else (request.client.host if request.client else "unknown")
        )

        allowed, retry_after = self._clean_and_check(client_ip)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Too many requests from this IP. Please retry in {retry_after} second(s).",
                headers={"Retry-After": str(retry_after)},
            )


# Pre-configured instances for standard and strict endpoints
global_rate_limiter = InMemoryRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)

auth_strict_rate_limiter = InMemoryRateLimiter(
    max_requests=10,
    window_seconds=60,
)
