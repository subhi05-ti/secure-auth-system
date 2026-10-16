import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import generate_numeric_otp, hash_secret_token
from app.models.otp import OTPCode, OTPPurpose

settings = get_settings()


class OTPService:
    @staticmethod
    async def create_otp(
        db: AsyncSession,
        email: str,
        purpose: OTPPurpose,
        user_id: uuid.UUID | None = None,
    ) -> str:
        """Create a new time-limited numeric OTP and invalidate any previous active ones for this purpose."""
        normalized_email = email.strip().lower()

        # Invalidate previous unconsumed OTPs for this email and purpose
        await db.execute(
            update(OTPCode)
            .where(
                OTPCode.email == normalized_email,
                OTPCode.purpose == purpose,
                OTPCode.is_used.is_(False),
            )
            .values(is_used=True)
        )

        plain_code = generate_numeric_otp(digits=6)
        code_hash = hash_secret_token(plain_code)
        expires_at = datetime.now(UTC) + timedelta(minutes=settings.otp_expire_minutes)

        otp_record = OTPCode(
            user_id=user_id,
            email=normalized_email,
            code_hash=code_hash,
            purpose=purpose,
            expires_at=expires_at,
            attempts=0,
            is_used=False,
        )
        db.add(otp_record)
        await db.commit()
        await db.refresh(otp_record)
        return plain_code

    @staticmethod
    async def verify_otp(
        db: AsyncSession,
        email: str,
        code: str,
        purpose: OTPPurpose,
    ) -> OTPCode:
        """Verify an OTP code, checking expiration and enforcing attempt limits."""
        normalized_email = email.strip().lower()
        now = datetime.now(UTC)

        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.email == normalized_email,
                OTPCode.purpose == purpose,
                OTPCode.is_used.is_(False),
            )
            .order_by(desc(OTPCode.created_at))
            .limit(1)
        )
        otp_record = result.scalar_one_or_none()

        if not otp_record:
            raise ValueError("No active OTP found. Please request a new code.")

        expires_at = otp_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if expires_at < now:
            otp_record.is_used = True
            await db.commit()
            raise ValueError("OTP code has expired. Please request a new code.")

        if otp_record.attempts >= settings.otp_max_attempts:
            otp_record.is_used = True
            await db.commit()
            raise ValueError("Maximum OTP attempts exceeded. Please request a new code.")

        incoming_hash = hash_secret_token(code.strip())
        if otp_record.code_hash != incoming_hash:
            otp_record.attempts += 1
            await db.commit()
            remaining = settings.otp_max_attempts - otp_record.attempts
            raise ValueError(f"Invalid OTP code. {remaining} attempt(s) remaining.")

        otp_record.is_used = True
        await db.commit()
        await db.refresh(otp_record)
        return otp_record
