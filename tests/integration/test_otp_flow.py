import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OTPPurpose
from app.services.otp_service import OTPService


@pytest.mark.asyncio
async def test_passwordless_otp_login_flow(client: httpx.AsyncClient, db_session: AsyncSession):
    email = "passwordless@example.com"

    # 1. Request OTP login
    req_resp = await client.post(
        "/api/v1/otp/request-login-otp",
        json={"email": email},
    )
    assert req_resp.status_code == 200
    assert "one-time login code has been sent" in req_resp.json()["message"]

    # 2. To test deterministic verification, generate a known OTP code via OTPService
    plain_otp = await OTPService.create_otp(
        db=db_session,
        email=email,
        purpose=OTPPurpose.LOGIN,
    )

    # 3. Verify login using incorrect code
    fail_resp = await client.post(
        "/api/v1/otp/verify-login-otp",
        json={"email": email, "code": "999999"},
    )
    assert fail_resp.status_code == 401

    # 4. Verify login using correct code
    success_resp = await client.post(
        "/api/v1/otp/verify-login-otp",
        json={"email": email, "code": plain_otp},
    )
    assert success_resp.status_code == 200
    tokens = success_resp.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    # 5. Access protected route with the received access token
    me_resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email


@pytest.mark.asyncio
async def test_password_reset_flow(client: httpx.AsyncClient, db_session: AsyncSession):
    email = "resetme@example.com"
    old_password = "OldPassword123!"
    new_password = "NewStrongPassword456!"

    # 1. Register user
    reg = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": old_password, "full_name": "Reset User"},
    )
    assert reg.status_code == 201

    # 2. Request forgot password
    forgot_resp = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": email},
    )
    assert forgot_resp.status_code == 200

    # 3. Create known reset OTP
    reset_otp = await OTPService.create_otp(
        db=db_session,
        email=email,
        purpose=OTPPurpose.PASSWORD_RESET,
    )

    # 4. Confirm password reset
    reset_resp = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "email": email,
            "code": reset_otp,
            "new_password": new_password,
        },
    )
    assert reset_resp.status_code == 200
    assert "Password reset successfully" in reset_resp.json()["message"]

    # 5. Old password login should fail
    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": old_password},
    )
    assert old_login.status_code == 401

    # 6. New password login should succeed
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": new_password},
    )
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()
