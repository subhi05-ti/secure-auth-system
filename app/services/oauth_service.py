from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.oauth import OAuthAccount
from app.models.user import User
from app.schemas.token import TokenResponse
from app.services.auth_service import AuthService

settings = get_settings()


class OAuthService:
    @staticmethod
    def get_google_auth_url(state: str) -> str:
        """Construct Google OAuth 2.0 authorization URL."""
        if not settings.google_client_id:
            raise ValueError("Google OAuth is not configured. Please set GOOGLE_CLIENT_ID.")

        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state,
            "prompt": "select_account",
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    @staticmethod
    def get_github_auth_url(state: str) -> str:
        """Construct GitHub OAuth authorization URL."""
        if not settings.github_client_id:
            raise ValueError("GitHub OAuth is not configured. Please set GITHUB_CLIENT_ID.")

        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    @classmethod
    async def handle_google_callback(cls, db: AsyncSession, code: str) -> TokenResponse:
        """Exchange Google authorization code for tokens and link or create user."""
        token_url = "https://oauth2.googleapis.com/token"
        userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"

        data = {
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret.get_secret_value(),
            "redirect_uri": settings.google_redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(token_url, data=data)
            if token_resp.status_code != 200:
                raise ValueError("Failed to retrieve token from Google.")
            token_data = token_resp.json()
            access_token = token_data.get("access_token")

            userinfo_resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if userinfo_resp.status_code != 200:
                raise ValueError("Failed to fetch user profile from Google.")
            profile = userinfo_resp.json()

        email = profile.get("email")
        provider_user_id = profile.get("sub")
        full_name = profile.get("name")

        if not email or not provider_user_id:
            raise ValueError("Incomplete Google user profile received.")

        return await cls._link_or_create_oauth_user(
            db=db,
            provider="google",
            provider_user_id=provider_user_id,
            email=email,
            full_name=full_name,
        )

    @classmethod
    async def handle_github_callback(cls, db: AsyncSession, code: str) -> TokenResponse:
        """Exchange GitHub authorization code for tokens and link or create user."""
        token_url = "https://github.com/login/oauth/access_token"
        user_url = "https://api.github.com/user"
        emails_url = "https://api.github.com/user/emails"

        data = {
            "code": code,
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret.get_secret_value(),
            "redirect_uri": settings.github_redirect_uri,
        }

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                token_url,
                data=data,
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                raise ValueError("Failed to retrieve token from GitHub.")
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise ValueError("GitHub did not provide an access token.")

            user_resp = await client.get(
                user_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if user_resp.status_code != 200:
                raise ValueError("Failed to fetch GitHub profile.")
            user_data = user_resp.json()

            provider_user_id = str(user_data.get("id"))
            full_name = user_data.get("name") or user_data.get("login")
            email = user_data.get("email")

            if not email:
                # Fetch verified primary email
                emails_resp = await client.get(
                    emails_url,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )
                if emails_resp.status_code == 200:
                    emails_list: list[dict[str, Any]] = emails_resp.json()
                    for item in emails_list:
                        if item.get("primary") and item.get("verified"):
                            email = item.get("email")
                            break
                    if not email and emails_list:
                        email = emails_list[0].get("email")

        if not email or not provider_user_id:
            raise ValueError("Unable to determine verified email from GitHub account.")

        return await cls._link_or_create_oauth_user(
            db=db,
            provider="github",
            provider_user_id=provider_user_id,
            email=email,
            full_name=full_name,
        )

    @staticmethod
    async def _link_or_create_oauth_user(
        db: AsyncSession,
        provider: str,
        provider_user_id: str,
        email: str,
        full_name: str | None,
    ) -> TokenResponse:
        """Link an existing user account or create a new user and return JWT tokens."""
        normalized_email = email.strip().lower()

        # Check existing OAuth link
        result = await db.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_user_id == provider_user_id,
            )
        )
        oauth_account = result.scalar_one_or_none()

        if oauth_account:
            user = await AuthService.get_user_by_id(db, oauth_account.user_id)
            if not user or not user.is_active:
                raise ValueError("User account is inactive or not found.")
            return await AuthService.create_tokens_for_user(db, user)

        # Check if user already exists by email
        user = await AuthService.get_user_by_email(db, normalized_email)
        if not user:
            user = User(
                email=normalized_email,
                full_name=full_name,
                hashed_password=None,
                is_active=True,
                is_verified=True,  # Verified by OAuth identity provider
                is_superuser=False,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        # Create OAuth account link
        new_oauth = OAuthAccount(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=normalized_email,
        )
        db.add(new_oauth)
        await db.commit()

        return await AuthService.create_tokens_for_user(db, user)
