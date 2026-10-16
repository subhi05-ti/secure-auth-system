"""Automated API Testing Script for Secure Authentication System.

Run this script against a running server (default: http://127.0.0.1:8000):
    python scripts/test_api.py
"""
import sys
import time
import httpx

BASE_URL = "http://127.0.0.1:8000"
API_V1 = f"{BASE_URL}/api/v1"


def print_step(title: str):
    print(f"\n{'='*20} {title} {'='*20}")


def main():
    print(f"Starting End-to-End API Test against: {BASE_URL}")
    client = httpx.Client(timeout=10.0)

    # 1. Health check
    print_step("1. Health Check")
    resp = client.get(f"{BASE_URL}/health")
    print(f"Status: {resp.status_code}, Response: {resp.json()}")
    assert resp.status_code == 200, "Health check failed!"

    timestamp = int(time.time())
    email = f"testuser_{timestamp}@example.com"
    password = "SecurePassword123!"

    # 2. Register user
    print_step("2. User Registration")
    resp = client.post(
        f"{API_V1}/auth/register",
        json={"email": email, "password": password, "full_name": "API Tester"},
    )
    print(f"Status: {resp.status_code}, Response: {resp.json()}")
    assert resp.status_code == 201, "Registration failed!"

    # 3. Duplicate registration check
    print_step("3. Duplicate Registration Guardrail")
    resp = client.post(
        f"{API_V1}/auth/register",
        json={"email": email, "password": password, "full_name": "API Tester"},
    )
    print(f"Status: {resp.status_code} (Expected 400), Response: {resp.json()}")
    assert resp.status_code == 400, "Duplicate registration check failed!"

    # 4. User Login
    print_step("4. User Login (Email + Password)")
    resp = client.post(
        f"{API_V1}/auth/login",
        json={"email": email, "password": password},
    )
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 200, "Login failed!"
    tokens = resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    print(f"Received Access Token: {access_token[:25]}... (valid 15m)")
    print(f"Received Refresh Token: {refresh_token[:25]}... (rotates on use)")

    headers = {"Authorization": f"Bearer {access_token}"}

    # 5. Access Protected Profile (/me)
    print_step("5. Access Protected Route (/api/v1/users/me)")
    resp = client.get(f"{API_V1}/users/me", headers=headers)
    print(f"Status: {resp.status_code}, Profile: {resp.json()}")
    assert resp.status_code == 200, "Accessing protected profile failed!"

    # 6. Update Profile
    print_step("6. Update Profile (/api/v1/users/me)")
    resp = client.patch(
        f"{API_V1}/users/me",
        headers=headers,
        json={"full_name": "Updated API Tester"},
    )
    print(f"Status: {resp.status_code}, Updated Profile: {resp.json()}")
    assert resp.status_code == 200, "Updating profile failed!"

    # 7. Unverified user accessing premium route should be rejected (403)
    print_step("7. Verification Guardrail on Premium Route")
    resp = client.get(f"{API_V1}/users/premium-demonstration", headers=headers)
    print(f"Status: {resp.status_code} (Expected 403), Response: {resp.json()}")
    assert resp.status_code == 403, "Unverified user was unexpectedly allowed into premium route!"

    # 8. Refresh Token Rotation
    print_step("8. Refresh Token Rotation")
    resp = client.post(
        f"{API_V1}/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 200, "Token rotation failed!"
    new_tokens = resp.json()
    new_access_token = new_tokens["access_token"]
    new_refresh_token = new_tokens["refresh_token"]
    assert new_refresh_token != refresh_token, "Refresh token was not rotated!"
    print("New rotated token pair received successfully.")

    # 9. Token Reuse Detection
    print_step("9. Security Check: Token Reuse Detection")
    resp = client.post(
        f"{API_V1}/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    print(f"Status: {resp.status_code} (Expected 401), Response: {resp.json()}")
    assert resp.status_code == 401, "Reused token was not rejected!"
    print("Token reuse was successfully neutralized.")

    # 10. Passwordless Login Request
    print_step("10. Passwordless Login OTP Request")
    resp = client.post(
        f"{API_V1}/otp/request-login-otp",
        json={"email": email},
    )
    print(f"Status: {resp.status_code}, Response: {resp.json()}")
    assert resp.status_code == 200, "Requesting OTP failed!"

    # 11. Secure Logout
    print_step("11. Secure Logout")
    login_resp = client.post(
        f"{API_V1}/auth/login",
        json={"email": email, "password": password},
    )
    active_access_token = login_resp.json()["access_token"]
    active_refresh_token = login_resp.json()["refresh_token"]

    resp = client.post(
        f"{API_V1}/auth/logout",
        headers={"Authorization": f"Bearer {active_access_token}"},
        json={"refresh_token": active_refresh_token},
    )
    print(f"Status: {resp.status_code}, Response: {resp.json()}")
    assert resp.status_code == 200, "Logout failed!"

    # Verify blacklisted access token is rejected
    print_step("12. Verify Immediate Access Token Invalidation Post-Logout")
    resp = client.get(
        f"{API_V1}/users/me",
        headers={"Authorization": f"Bearer {active_access_token}"},
    )
    print(f"Status: {resp.status_code} (Expected 401), Response: {resp.json()}")
    assert resp.status_code == 401, "Logged out access token was not revoked!"

    print("\nALL END-TO-END API TESTS PASSED SUCCESSFULLY! ")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as err:
        print(f"\nTEST ASSERTION FAILED: {err}", file=sys.stderr)
        sys.exit(1)
    except httpx.ConnectError:
        print(
            "\nERROR: Could not connect to API server at http://127.0.0.1:8000.\n"
            "Please ensure the server is running:\n"
            "    uvicorn app.main:app --reload",
            file=sys.stderr,
        )
        sys.exit(1)
