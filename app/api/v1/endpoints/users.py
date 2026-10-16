from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import (
    get_current_superuser,
    get_current_user,
    get_current_verified_user,
)
from app.core.security import hash_password, verify_password
from app.database.session import get_db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.user import (
    PasswordChange,
    ProtectedResourceResponse,
    UserResponse,
    UserUpdate,
)

router = APIRouter(prefix="/users", tags=["Users & Protected Routes"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retrieve the authenticated user's profile information."""
    return UserResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile",
)
async def update_my_profile(
    updates: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Update profile attributes for the authenticated user."""
    if updates.full_name is not None:
        current_user.full_name = updates.full_name.strip() or None

    await db.commit()
    await db.refresh(current_user)
    return UserResponse.model_validate(current_user)


@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change user password",
)
async def change_password(
    payload: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Change account password and revoke existing refresh tokens."""
    if not current_user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account does not have a local password set (social login). Please use password reset.",
        )

    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    current_user.hashed_password = hash_password(payload.new_password)

    # Security: Revoke all existing refresh tokens
    await db.execute(update(RefreshToken).where(RefreshToken.user_id == current_user.id).values(is_revoked=True))
    await db.commit()

    return MessageResponse(message="Password changed successfully. All previous sessions have been revoked.")


@router.get(
    "/premium-demonstration",
    response_model=ProtectedResourceResponse,
    summary="Protected route demonstration (requires verified email)",
)
async def protected_premium_demonstration(
    current_user: User = Depends(get_current_verified_user),
) -> ProtectedResourceResponse:
    """Demonstrate OAuth2 dependency injection gating premium / verified-only API endpoints."""
    return ProtectedResourceResponse(
        message=f"Welcome to the premium zone, {current_user.full_name or current_user.email}!",
        user_id=str(current_user.id),
        is_verified=current_user.is_verified,
        access="granted",
    )


@router.get(
    "/admin-demonstration",
    response_model=ProtectedResourceResponse,
    summary="Admin route demonstration (requires superuser privileges)",
)
async def protected_admin_demonstration(
    current_user: User = Depends(get_current_superuser),
) -> ProtectedResourceResponse:
    """Demonstrate role-based access control gating admin-only API endpoints."""
    return ProtectedResourceResponse(
        message="Welcome, Administrator. You have full access to system management.",
        admin_email=current_user.email,
        access="granted",
    )
