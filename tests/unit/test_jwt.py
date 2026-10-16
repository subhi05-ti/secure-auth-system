from datetime import timedelta

import pytest

from app.auth.jwt import (
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    create_refresh_token,
    decode_token,
)


def test_create_and_decode_access_token():
    subject = "123e4567-e89b-12d3-a456-426614174000"
    email = "user@example.com"

    token, expires_in = create_access_token(
        subject=subject,
        email=email,
        is_superuser=False,
    )

    assert isinstance(token, str)
    assert expires_in > 0

    payload = decode_token(token, expected_type="access")
    assert payload["sub"] == subject
    assert payload["email"] == email
    assert payload["type"] == "access"
    assert payload["is_superuser"] is False


def test_create_and_decode_refresh_token():
    subject = "123e4567-e89b-12d3-a456-426614174000"
    email = "user@example.com"

    token, jti, _expire_dt = create_refresh_token(subject=subject, email=email)

    assert isinstance(token, str)
    assert isinstance(jti, str)
    assert len(jti) > 10

    payload = decode_token(token, expected_type="refresh")
    assert payload["sub"] == subject
    assert payload["email"] == email
    assert payload["jti"] == jti
    assert payload["type"] == "refresh"


def test_token_type_mismatch_error():
    token, _ = create_access_token(
        subject="sub123",
        email="test@example.com",
    )

    with pytest.raises(TokenInvalidError, match="Expected token type 'refresh', got 'access'"):
        decode_token(token, expected_type="refresh")


def test_expired_token_error():
    token, _ = create_access_token(
        subject="sub123",
        email="test@example.com",
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )

    with pytest.raises(TokenExpiredError):
        decode_token(token, expected_type="access")


def test_tampered_token_error():
    token, _ = create_access_token(
        subject="sub123",
        email="test@example.com",
    )
    tampered = token[:-4] + "abcd"

    with pytest.raises(TokenInvalidError):
        decode_token(tampered)
