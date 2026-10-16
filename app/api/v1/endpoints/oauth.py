import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import _set_refresh_cookie
from app.database.session import get_db
from app.schemas.token import TokenResponse
from app.services.oauth_service import OAuthService

router = APIRouter(prefix="/oauth", tags=["Social Authentication (OAuth2)"])


@router.get(
    "/google/login",
    summary="Initiate Google OAuth2 sign-in",
)
async def google_login(redirect: bool = Query(default=True)):
    """Redirect to Google consent screen or return authorization URL with anti-CSRF state."""
    try:
        state = secrets.token_urlsafe(32)
        auth_url = OAuthService.get_google_auth_url(state=state)

        if redirect:
            resp = RedirectResponse(url=auth_url)
        else:
            resp = JSONResponse(content={"authorization_url": auth_url, "state": state})

        resp.set_cookie(
            key="oauth_google_state",
            value=state,
            httponly=True,
            samesite="lax",
            max_age=300,
            path="/",
        )
        return resp
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Handle Google OAuth2 callback with CSRF state validation",
)
async def google_callback(
    request: Request,
    response: Response,
    code: str = Query(..., description="Authorization code from Google"),
    state: str | None = Query(default=None, description="Anti-CSRF state token"),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validate CSRF state, exchange Google code for tokens, and return user session."""
    expected_state = request.cookies.get("oauth_google_state")
    response.delete_cookie(key="oauth_google_state", path="/")

    if expected_state and state and expected_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSRF state validation failed. Possible cross-site request forgery detected.",
        )

    try:
        tokens = await OAuthService.handle_google_callback(db, code)
        if tokens.refresh_token:
            _set_refresh_cookie(response, tokens.refresh_token)
        return tokens
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "/github/login",
    summary="Initiate GitHub OAuth2 sign-in",
)
async def github_login(redirect: bool = Query(default=True)):
    """Redirect to GitHub consent screen or return authorization URL with anti-CSRF state."""
    try:
        state = secrets.token_urlsafe(32)
        auth_url = OAuthService.get_github_auth_url(state=state)

        if redirect:
            resp = RedirectResponse(url=auth_url)
        else:
            resp = JSONResponse(content={"authorization_url": auth_url, "state": state})

        resp.set_cookie(
            key="oauth_github_state",
            value=state,
            httponly=True,
            samesite="lax",
            max_age=300,
            path="/",
        )
        return resp
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.get(
    "/github/callback",
    response_model=TokenResponse,
    summary="Handle GitHub OAuth2 callback with CSRF state validation",
)
async def github_callback(
    request: Request,
    response: Response,
    code: str = Query(..., description="Authorization code from GitHub"),
    state: str | None = Query(default=None, description="Anti-CSRF state token"),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validate CSRF state, exchange GitHub code for tokens, and return user session."""
    expected_state = request.cookies.get("oauth_github_state")
    response.delete_cookie(key="oauth_github_state", path="/")

    if expected_state and state and expected_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSRF state validation failed. Possible cross-site request forgery detected.",
        )

    try:
        tokens = await OAuthService.handle_github_callback(db, code)
        if tokens.refresh_token:
            _set_refresh_cookie(response, tokens.refresh_token)
        return tokens
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
