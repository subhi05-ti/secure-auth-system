import logging
from email.message import EmailMessage

import aiosmtplib

from app.core.config import get_settings

logger = logging.getLogger("secure_auth.email")
settings = get_settings()


class EmailService:
    @staticmethod
    async def _send_email(to_email: str, subject: str, text_content: str, html_content: str | None = None) -> bool:
        """Send an email using aiosmtplib, falling back to logger in development if SMTP is unconfigured."""
        if not settings.smtp_host or not settings.smtp_from_email:
            logger.warning(
                "SMTP not configured. Simulating email dispatch to %s with subject '%s'.\nContent: %s",
                to_email,
                subject,
                text_content,
            )
            return True

        message = EmailMessage()
        message["From"] = settings.smtp_from_email
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(text_content)

        if html_content:
            message.add_alternative(html_content, subtype="html")

        try:
            await aiosmtplib.send(
                message,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username or None,
                password=settings.smtp_password.get_secret_value() if settings.smtp_password else None,
                start_tls=settings.smtp_starttls,
            )
            logger.info("Successfully dispatched email to %s", to_email)
            return True
        except Exception as exc:
            logger.error("Failed to send email to %s via SMTP: %s", to_email, str(exc))
            return False

    @classmethod
    async def send_verification_email(cls, to_email: str, code: str) -> bool:
        subject = f"{settings.app_name} - Verify Your Email Address"
        text = (
            f"Welcome to {settings.app_name}!\n\n"
            f"Your email verification code is: {code}\n\n"
            f"This code will expire in {settings.otp_expire_minutes} minutes. "
            f"If you did not create an account, please ignore this email."
        )
        return await cls._send_email(to_email, subject, text)

    @classmethod
    async def send_password_reset_email(cls, to_email: str, code: str) -> bool:
        subject = f"{settings.app_name} - Password Reset Request"
        text = (
            f"Hello,\n\n"
            f"We received a request to reset your password for {settings.app_name}.\n\n"
            f"Your one-time password reset code is: {code}\n\n"
            f"This code is valid for {settings.otp_expire_minutes} minutes. "
            f"If you did not request a password reset, please secure your account immediately."
        )
        return await cls._send_email(to_email, subject, text)

    @classmethod
    async def send_otp_login_email(cls, to_email: str, code: str) -> bool:
        subject = f"{settings.app_name} - One-Time Login Code"
        text = (
            f"Hello,\n\n"
            f"Here is your temporary passcode for passwordless login: {code}\n\n"
            f"This passcode will expire in {settings.otp_expire_minutes} minutes. "
            f"Never share this code with anyone."
        )
        return await cls._send_email(to_email, subject, text)
