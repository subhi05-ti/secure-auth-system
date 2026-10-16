import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import (
    JWTError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.core.security import (
    hash_password,
    hash_secret_token,
    verify_password,
)
from app.models.otp import OTPPurpose
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.token import TokenResponse
from app.schemas.user import UserRegister
from app.services.email_service import EmailService
from app.services.otp_service import OTPService


class AuthService:
    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
        result = await db.execute(select(User).where(User.email == email.strip().lower()))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    @classmethod
    async def register_user(cls, db: AsyncSession, user_in: UserRegister) -> tuple[User, str]:
        """Register a new user, hash password, and trigger email verification OTP."""
        normalized_email = user_in.email.strip().lower()

        existing = await cls.get_user_by_email(db, normalized_email)
        if existing:
            raise ValueError("A user with this email already exists.")

        user = User(
            email=normalized_email,
            hashed_password=hash_password(user_in.password),
            full_name=user_in.full_name,
            is_active=True,
            is_verified=False,
            is_superuser=False,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        otp_code = await OTPService.create_otp(
            db=db,
            email=normalized_email,
            purpose=OTPPurpose.EMAIL_VERIFICATION,
            user_id=user.id,
        )
        await EmailService.send_verification_email(normalized_email, otp_code)
        return user, otp_code

    @classmethod
    async def authenticate_user(cls, db: AsyncSession, email: str, password: str) -> User:
        """Authenticate user by email and password."""
        user = await cls.get_user_by_email(db, email)
        if not user or not user.hashed_password:
            raise ValueError("Invalid email or password.")

        if not user.is_active:
            raise ValueError("Account is deactivated. Please contact support.")

        if not verify_password(password, user.hashed_password):
            raise ValueError("Invalid email or password.")

        return user

    @staticmethod
    async def create_tokens_for_user(db: AsyncSession, user: User) -> TokenResponse:
        """Issue access and refresh token pair and persist refresh token in database."""
        access_token, expires_in = create_access_token(
            subject=str(user.id),
            email=user.email,
            is_superuser=user.is_superuser,
        )
        refresh_token_str, jti, expire_dt = create_refresh_token(
            subject=str(user.id),
            email=user.email,
        )

        token_hash = hash_secret_token(refresh_token_str)
        refresh_record = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            jti=jti,
            expires_at=expire_dt,
            is_revoked=False,
        )
        db.add(refresh_record)
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            refresh_token=refresh_token_str,
        )

    @classmethod
    async def rotate_refresh_token(cls, db: AsyncSession, refresh_token_str: str) -> TokenResponse:
        """Validate and rotate a refresh token with automatic token-reuse detection."""
        payload = decode_token(refresh_token_str, expected_type="refresh")
        jti = payload.get("jti")
        if not jti:
            raise ValueError("Invalid refresh token payload.")

        result = await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        token_record = result.scalar_one_or_none()

        if not token_record:
            raise ValueError("Refresh token not found or already invalidated.")

        # Token reuse detection: If an already-revoked refresh token is presented,
        # someone might have stolen it. Invalidate all tokens for this user.
        if token_record.is_revoked:
            await db.execute(
                update(RefreshToken).where(RefreshToken.user_id == token_record.user_id).values(is_revoked=True)
            )
            await db.commit()
            raise ValueError(
                "Revoked token presented. For security, all sessions have been terminated. Please log in again."
            )

        now = datetime.now(UTC)
        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < now:
            token_record.is_revoked = True
            await db.commit()
            raise ValueError("Refresh token expired. Please log in again.")

        user = await cls.get_user_by_id(db, token_record.user_id)
        if not user or not user.is_active:
            raise ValueError("User account is inactive or not found.")

        # Generate new pair
        new_tokens = await cls.create_tokens_for_user(db, user)

        # Mark previous token as revoked and track replacement lineage
        new_payload = decode_token(new_tokens.refresh_token, expected_type="refresh")  # type: ignore
        token_record.is_revoked = True
        token_record.replaced_by = new_payload.get("jti")
        await db.commit()

        return new_tokens

    @staticmethod
    async def revoke_refresh_token(db: AsyncSession, refresh_token_str: str) -> bool:
        """Revoke a refresh token on logout."""
        try:
            payload = decode_token(refresh_token_str, expected_type="refresh")
            jti = payload.get("jti")
            if jti:
                await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
                await db.commit()
                return True
        except (JWTError, ValueError):
            pass

        # Fallback: check by hash
        token_hash = hash_secret_token(refresh_token_str)
        await db.execute(update(RefreshToken).where(RefreshToken.token_hash == token_hash).values(is_revoked=True))
        await db.commit()
        return True

    @classmethod
    async def request_password_reset(cls, db: AsyncSession, email: str) -> bool:
        """Request a password reset code. Does not leak account existence."""
        normalized_email = email.strip().lower()
        user = await cls.get_user_by_email(db, normalized_email)
        if user and user.is_active:
            otp_code = await OTPService.create_otp(
                db=db,
                email=normalized_email,
                purpose=OTPPurpose.PASSWORD_RESET,
                user_id=user.id,
            )
            await EmailService.send_password_reset_email(normalized_email, otp_code)
        return True

    @classmethod
    async def reset_password_with_otp(
        cls,
        db: AsyncSession,
        email: str,
        code: str,
        new_password: str,
    ) -> bool:
        """Verify password reset OTP, update password, and revoke all active sessions."""
        normalized_email = email.strip().lower()
        await OTPService.verify_otp(
            db=db,
            email=normalized_email,
            code=code,
            purpose=OTPPurpose.PASSWORD_RESET,
        )

        user = await cls.get_user_by_email(db, normalized_email)
        if not user:
            raise ValueError("User not found.")

        user.hashed_password = hash_password(new_password)

        # Security: Revoke all existing refresh tokens
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(is_revoked=True))
        await db.commit()
        return True

    @classmethod
    async def request_email_verification(cls, db: AsyncSession, email: str) -> bool:
        """Dispatch a new verification OTP code for an unverified user."""
        normalized_email = email.strip().lower()
        user = await cls.get_user_by_email(db, normalized_email)
        if user and not user.is_verified:
            otp_code = await OTPService.create_otp(
                db=db,
                email=normalized_email,
                purpose=OTPPurpose.EMAIL_VERIFICATION,
                user_id=user.id,
            )
            await EmailService.send_verification_email(normalized_email, otp_code)
        return True

    @classmethod
    async def verify_user_email(cls, db: AsyncSession, email: str, code: str) -> bool:
        """Verify user email via OTP."""
        normalized_email = email.strip().lower()
        await OTPService.verify_otp(
            db=db,
            email=normalized_email,
            code=code,
            purpose=OTPPurpose.EMAIL_VERIFICATION,
        )

        user = await cls.get_user_by_email(db, normalized_email)
        if not user:
            raise ValueError("User not found.")

        user.is_verified = True
        await db.commit()
        return True

    @classmethod
    async def request_otp_login(cls, db: AsyncSession, email: str) -> bool:
        """Request a one-time password code for passwordless login."""
        normalized_email = email.strip().lower()
        user = await cls.get_user_by_email(db, normalized_email)
        if not user:
            # Create user on the fly for passwordless login
            user = User(
                email=normalized_email,
                hashed_password=None,
                is_active=True,
                is_verified=True,
                is_superuser=False,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        if not user.is_active:
            raise ValueError("Account is deactivated.")

        otp_code = await OTPService.create_otp(
            db=db,
            email=normalized_email,
            purpose=OTPPurpose.LOGIN,
            user_id=user.id,
        )
        await EmailService.send_otp_login_email(normalized_email, otp_code)
        return True

    @classmethod
    async def verify_otp_login(cls, db: AsyncSession, email: str, code: str) -> TokenResponse:
        """Verify passwordless login OTP and issue access/refresh token pair."""
        normalized_email = email.strip().lower()
        await OTPService.verify_otp(
            db=db,
            email=normalized_email,
            code=code,
            purpose=OTPPurpose.LOGIN,
        )

        user = await cls.get_user_by_email(db, normalized_email)
        if not user or not user.is_active:
            raise ValueError("User not found or inactive.")

        user.is_verified = True
        await db.commit()

        return await cls.create_tokens_for_user(db, user)
