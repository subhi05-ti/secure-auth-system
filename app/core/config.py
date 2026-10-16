from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Secure Authentication System"
    app_env: Literal["development", "testing", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # Database (defaults to local SQLite for zero-setup execution)
    database_url: str = "sqlite+aiosqlite:///./secure_auth.db"

    # JWT and sessions
    jwt_secret_key: SecretStr = SecretStr(
        "odIkJnTe9YGj2kaJr5iq9Kw_eqdjefRFBNVZ1U9G-Jkal-VG69ty_09LGZ5ZgIEx"
    )
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 14

    # Cookies and CORS
    refresh_cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    frontend_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from_email: str = ""
    smtp_starttls: bool = True

    # Google OAuth
    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    google_redirect_uri: str = "http://localhost:8000/api/v1/auth/oauth/google/callback"

    # GitHub OAuth
    github_client_id: str = ""
    github_client_secret: SecretStr = SecretStr("")
    github_redirect_uri: str = "http://localhost:8000/api/v1/auth/oauth/github/callback"

    # OTP and verification
    otp_expire_minutes: int = 10
    otp_max_attempts: int = 5

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.frontend_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
