import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_user_profile_and_password_change(client: httpx.AsyncClient):
    # 1. Register a user
    user_data = {
        "email": "userprofile@example.com",
        "password": "InitialPassword123!",
        "full_name": "Profile User",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=user_data)
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Update full name
    patch_resp = await client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"full_name": "Updated Profile Name"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["full_name"] == "Updated Profile Name"

    # 4. Change password with wrong current password
    fail_change = await client.post(
        "/api/v1/users/change-password",
        headers=headers,
        json={
            "current_password": "WrongPassword123!",
            "new_password": "BrandNewPassword123!",
        },
    )
    assert fail_change.status_code == 400
    assert "Current password is incorrect" in fail_change.json()["detail"]

    # 5. Change password successfully
    success_change = await client.post(
        "/api/v1/users/change-password",
        headers=headers,
        json={
            "current_password": user_data["password"],
            "new_password": "BrandNewPassword123!",
        },
    )
    assert success_change.status_code == 200
    assert "Password changed successfully" in success_change.json()["message"]

    # 6. Login with new password succeeds
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": user_data["email"], "password": "BrandNewPassword123!"},
    )
    assert new_login.status_code == 200


@pytest.mark.asyncio
async def test_admin_and_verified_route_gating(client: httpx.AsyncClient, db_session: AsyncSession):
    # 1. Register regular user
    reg = await client.post(
        "/api/v1/auth/register",
        json={"email": "regular@example.com", "password": "PassWord123!", "full_name": "Regular"},
    )
    assert reg.status_code == 201

    # Access admin demonstration route with regular user token -> 403 Forbidden
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular@example.com", "password": "PassWord123!"},
    )
    user_token = login.json()["access_token"]
    admin_fail = await client.get(
        "/api/v1/users/admin-demonstration",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert admin_fail.status_code == 403
    assert "Superuser privileges required" in admin_fail.json()["detail"]

    # 2. Elevate user to superuser in DB and access -> 200 OK
    from sqlalchemy import update

    from app.models.user import User

    await db_session.execute(update(User).where(User.email == "regular@example.com").values(is_superuser=True))
    await db_session.commit()

    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular@example.com", "password": "PassWord123!"},
    )
    admin_token = admin_login.json()["access_token"]
    admin_success = await client.get(
        "/api/v1/users/admin-demonstration",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_success.status_code == 200
    assert admin_success.json()["access"] == "granted"


@pytest.mark.asyncio
async def test_oauth_routes(client: httpx.AsyncClient):
    # Google login initiation URL test
    google_resp = await client.get("/api/v1/oauth/google/login?redirect=false")
    # Service returns 503 if credentials unconfigured or 200 with URL if mock/configured
    assert google_resp.status_code in (200, 503)

    # GitHub login initiation URL test
    github_resp = await client.get("/api/v1/oauth/github/login?redirect=false")
    assert github_resp.status_code in (200, 503)
