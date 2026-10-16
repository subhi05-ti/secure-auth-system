import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import get_settings

settings = get_settings()


class JWTError(Exception):
    """Base exception for JWT-related errors."""


class TokenExpiredError(JWTError):
    """Raised when a JWT has expired."""


class TokenInvalidError(JWTError):
    """Raised when a JWT is malformed, has an invalid signature, or wrong type."""


def create_access_token(
    subject: str,
    email: str,
    is_superuser: bool = False,
    additional_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> tuple[str, int]:
    """Create a signed JWT access token. Returns (token_string, expires_in_seconds)."""
    now = datetime.now(UTC)
    delta = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    expire = now + delta

    payload: dict[str, Any] = {
        "sub": subject,
        "email": email,
        "jti": str(uuid.uuid4()),
        "is_superuser": is_superuser,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if additional_claims:
        payload.update(additional_claims)

    encoded = jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return encoded, int(delta.total_seconds())


def create_refresh_token(
    subject: str,
    email: str,
    expires_delta: timedelta | None = None,
) -> tuple[str, str, datetime]:
    """Create a signed JWT refresh token with unique JTI. Returns (token_string, jti, expire_datetime)."""
    now = datetime.now(UTC)
    delta = expires_delta or timedelta(days=settings.refresh_token_expire_days)
    expire = now + delta
    token_jti = str(uuid.uuid4())

    payload: dict[str, Any] = {
        "sub": subject,
        "email": email,
        "jti": token_jti,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    encoded = jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return encoded, token_jti, expire


def decode_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    """Decode and validate a signed JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
    except ExpiredSignatureError as exc:
        raise TokenExpiredError("Token has expired.") from exc
    except InvalidTokenError as exc:
        raise TokenInvalidError("Invalid token format or signature.") from exc

    token_type = payload.get("type")
    if expected_type and token_type != expected_type:
        raise TokenInvalidError(f"Expected token type '{expected_type}', got '{token_type}'.")

    return payload
