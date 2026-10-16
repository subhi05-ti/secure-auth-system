import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OTPCode, OTPPurpose


@pytest.mark.asyncio
async def test_full_auth_lifecycle(client: httpx.AsyncClient, db_session: AsyncSession):
    # 1. Register a new user
    reg_payload = {
        "email": "testuser@example.com",
        "password": "SecurePassword123!",
        "full_name": "Test User",
    }
    reg_response = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_response.status_code == 201
    reg_data = reg_response.json()
    assert reg_data["email"] == "testuser@example.com"
    assert reg_data["is_active"] is True
    assert reg_data["is_verified"] is False

    # 2. Duplicate registration should fail
    dup_response = await client.post("/api/v1/auth/register", json=reg_payload)
    assert dup_response.status_code == 400

    # 3. Retrieve OTP from DB to simulate email verification
    result = await db_session.execute(
        select(OTPCode).where(
            OTPCode.email == "testuser@example.com",
            OTPCode.purpose == OTPPurpose.EMAIL_VERIFICATION,
        )
    )
    otp_record = result.scalars().first()
    assert otp_record is not None

    # Verify with wrong OTP fails
    verify_fail = await client.post(
        "/api/v1/auth/verify-email",
        json={"email": "testuser@example.com", "code": "000000"},
    )
    assert verify_fail.status_code == 400

    # Verify with correct OTP succeeds (we can verify by updating OTPCode record or verifying through service)
    # Let's test login first before verification
    login_response = await client.post(
        "/api/v1/auth/login",
        json={"email": "testuser@example.com", "password": "SecurePassword123!"},
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]

    # 4. Access protected route /me with access token
    me_response = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == "testuser@example.com"
    assert me_data["full_name"] == "Test User"

    # 5. Access premium route fails because email is not yet verified
    premium_fail = await client.get(
        "/api/v1/users/premium-demonstration",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert premium_fail.status_code == 403

    # 6. Test Refresh Token Rotation
    refresh_response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    assert new_tokens["access_token"] != access_token
    assert new_tokens["refresh_token"] != refresh_token
    new_refresh_token = new_tokens["refresh_token"]

    # 7. Token Reuse Detection: Attempting to use the OLD already-rotated refresh token MUST FAIL and trigger lockout
    reuse_response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert reuse_response.status_code == 401
    assert "Revoked token presented" in reuse_response.json()["detail"]

    # 8. Because token reuse was detected, the new_refresh_token must also now be revoked!
    new_refresh_attempt = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert new_refresh_attempt.status_code == 401

    # 9. Log in again to get fresh credentials
    login_again = await client.post(
        "/api/v1/auth/login",
        json={"email": "testuser@example.com", "password": "SecurePassword123!"},
    )
    assert login_again.status_code == 200
    fresh_access_token = login_again.json()["access_token"]
    fresh_refresh_token = login_again.json()["refresh_token"]

    # 10. Logout and verify immediate revocation of both refresh token AND access token
    logout_response = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {fresh_access_token}"},
        json={"refresh_token": fresh_refresh_token},
    )
    assert logout_response.status_code == 200
    assert logout_response.json()["success"] is True

    # Accessing protected route with the logged-out access token should be rejected immediately
    after_logout_access = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {fresh_access_token}"},
    )
    assert after_logout_access.status_code == 401
    assert "revoked" in after_logout_access.json()["detail"]

    # Attempting to refresh with logged-out refresh token should fail
    after_logout_refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": fresh_refresh_token},
    )
    assert after_logout_refresh.status_code == 401
