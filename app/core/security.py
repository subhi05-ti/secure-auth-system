import hashlib
import re
import secrets

from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=\[\]{}|;:,.<>])[A-Za-z\d@$!%*?&#^()_+\-=\[\]{}|;:,.<>]{8,128}$"
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against an Argon2id hash."""
    return password_hash.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    """Validate password complexity rules.

    Requirements:
    - Between 8 and 128 characters.
    - At least one uppercase letter.
    - At least one lowercase letter.
    - At least one numeric digit.
    - At least one special character.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&#^()_+\-=\[\]{}|;:,.<>]", password):
        return False, "Password must contain at least one special character."
    return True, None


def hash_secret_token(token: str) -> str:
    """Hash a sensitive token (refresh token, reset token, OTP) using SHA-256 for secure storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe random string."""
    return secrets.token_urlsafe(nbytes)


def generate_numeric_otp(digits: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP string."""
    return "".join(secrets.choice("0123456789") for _ in range(digits))
