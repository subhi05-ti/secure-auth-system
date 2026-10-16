from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import _set_refresh_cookie
from app.core.config import get_settings
from app.database.session import get_db
from app.schemas.otp import OTPRequest, OTPResponse, OTPVerify
from app.schemas.token import TokenResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/otp", tags=["One-Time Password (OTP)"])
settings = get_settings()


@router.post(
    "/request-login-otp",
    response_model=OTPResponse,
    summary="Request a passwordless login OTP",
)
async def request_login_otp(
    payload: OTPRequest,
    db: AsyncSession = Depends(get_db),
) -> OTPResponse:
    """Generate and dispatch a 6-digit numeric OTP for secure passwordless login."""
    try:
        await AuthService.request_otp_login(db, payload.email)
        return OTPResponse(
            message="A one-time login code has been sent to your email.",
            email=payload.email,
            expires_in_minutes=settings.otp_expire_minutes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/verify-login-otp",
    response_model=TokenResponse,
    summary="Login using one-time password code",
)
async def verify_login_otp(
    payload: OTPVerify,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Verify passwordless login code and return authenticated access and refresh tokens."""
    try:
        tokens = await AuthService.verify_otp_login(db, payload.email, payload.code)
        if tokens.refresh_token:
            _set_refresh_cookie(response, tokens.refresh_token)
        return tokens
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
