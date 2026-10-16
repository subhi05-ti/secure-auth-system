import time
from collections import OrderedDict


class TokenBlacklist:
    """In-memory store for revoked access token JTIs with automatic expiration cleanup."""

    def __init__(self, max_size: int = 10000) -> None:
        self._revoked_jtis: OrderedDict[str, float] = OrderedDict()
        self._max_size = max_size

    def revoke(self, jti: str, exp_timestamp: float) -> None:
        """Add a token JTI to the revocation blacklist until its expiration."""
        self._cleanup()
        self._revoked_jtis[jti] = exp_timestamp
        if len(self._revoked_jtis) > self._max_size:
            self._revoked_jtis.popitem(last=False)

    def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked."""
        self._cleanup()
        return jti in self._revoked_jtis

    def _cleanup(self) -> None:
        """Purge expired tokens from the blacklist."""
        now = time.time()
        expired = [jti for jti, exp in self._revoked_jtis.items() if exp < now]
        for jti in expired:
            self._revoked_jtis.pop(jti, None)


# Global singleton instance
token_blacklist = TokenBlacklist()
