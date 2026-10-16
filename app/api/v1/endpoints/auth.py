from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.core.config import get_settings
from app.core.token_blacklist import token_blacklist
from app.database.session import get_db
from app.schemas.auth import (
    EmailVerificationRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
)
from app.schemas.token import RefreshTokenRequest, TokenResponse
from app.schemas.user import UserLogin, UserRegister, UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Set secure HttpOnly refresh token cookie."""
    max_age = settings.refresh_token_expire_days * 24 * 60 * 60
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=max_age,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Clear refresh token cookie."""
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(
    user_in: UserRegister,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Create a new user account and dispatch an email verification OTP."""
    try:
        user, _ = await AuthService.register_user(db, user_in)
        return UserResponse.model_validate(user)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User login with email and password",
)
async def login(
    credentials: UserLogin,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate credentials and issue access token with rotating refresh token."""
    try:
        user = await AuthService.authenticate_user(db, credentials.email, credentials.password)
        tokens = await AuthService.create_tokens_for_user(db, user)
        if tokens.refresh_token:
            _set_refresh_cookie(response, tokens.refresh_token)
        return tokens
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and issue new token pair",
)
async def refresh_tokens(
    request: Request,
    response: Response,
    body: RefreshTokenRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Rotate an existing refresh token with reuse-detection guardrails."""
    refresh_token = (body.refresh_token if body else None) or request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token must be provided via request body or cookie.",
        )

    try:
        new_tokens = await AuthService.rotate_refresh_token(db, refresh_token)
        if new_tokens.refresh_token:
            _set_refresh_cookie(response, new_tokens.refresh_token)
        return new_tokens
    except ValueError as exc:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Secure logout and refresh token revocation",
)
async def logout(
    request: Request,
    response: Response,
    body: RefreshTokenRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    # 1. Invalidate access token JTI if present in Authorization header
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        access_token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = decode_token(access_token, expected_type="access")
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                token_blacklist.revoke(jti, float(exp))
        except Exception:
            pass

    # 2. Invalidate refresh token session
    refresh_token = (body.refresh_token if body else None) or request.cookies.get("refresh_token")
    if refresh_token:
        await AuthService.revoke_refresh_token(db, refresh_token)
    _clear_refresh_cookie(response)
    return MessageResponse(message="Successfully logged out.")


@router.post(
    "/request-verification-email",
    response_model=MessageResponse,
    summary="Request a new email verification code",
)
async def request_verification_email(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Send a fresh verification OTP code to user's email."""
    await AuthService.request_email_verification(db, payload.email)
    return MessageResponse(message="Verification code sent to your email.")


@router.post(
    "/verify-email",
    response_model=MessageResponse,
    summary="Verify email address with OTP code",
)
async def verify_email(
    payload: EmailVerificationRequest,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Confirm user email address via dynamic OTP."""
    try:
        await AuthService.verify_user_email(db, payload.email, payload.code)
        return MessageResponse(message="Email address verified successfully.")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset OTP",
)
async def forgot_password(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Dispatch a dynamic OTP for password reset without leaking account existence."""
    await AuthService.request_password_reset(db, payload.email)
    return MessageResponse(message="If this account exists, a password reset code has been sent to your email.")


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using OTP code",
)
async def reset_password(
    payload: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Validate OTP code and update user password while revoking all previous sessions."""
    try:
        await AuthService.reset_password_with_otp(
            db=db,
            email=payload.email,
            code=payload.code,
            new_password=payload.new_password,
        )
        return MessageResponse(message="Password reset successfully. You may now log in.")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
