from app.core.security import (
    generate_numeric_otp,
    generate_secure_token,
    hash_password,
    hash_secret_token,
    validate_password_strength,
    verify_password,
)


def test_password_hashing_and_verification():
    raw_password = "SecurePassword123!"
    hashed = hash_password(raw_password)

    assert hashed.startswith("$argon2id$")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_password_strength_validation():
    # Valid password
    valid, msg = validate_password_strength("StrongPass123!")
    assert valid is True
    assert msg is None

    # Too short (< 8 chars)
    valid, msg = validate_password_strength("Ab1!")
    assert valid is False
    assert "at least 8 characters" in msg

    # Missing uppercase
    valid, msg = validate_password_strength("strongpass123!")
    assert valid is False
    assert "uppercase" in msg

    # Missing lowercase
    valid, msg = validate_password_strength("STRONGPASS123!")
    assert valid is False
    assert "lowercase" in msg

    # Missing digit
    valid, msg = validate_password_strength("StrongPass!")
    assert valid is False
    assert "digit" in msg

    # Missing special character
    valid, msg = validate_password_strength("StrongPass123")
    assert valid is False
    assert "special character" in msg


def test_hash_secret_token():
    token = "random_refresh_token_string"
    hashed1 = hash_secret_token(token)
    hashed2 = hash_secret_token(token)

    assert len(hashed1) == 64  # SHA-256 hexadecimal output length
    assert hashed1 == hashed2
    assert hashed1 != hash_secret_token("different_token")


def test_generate_numeric_otp():
    otp = generate_numeric_otp(digits=6)
    assert len(otp) == 6
    assert otp.isdigit()

    # Verify uniqueness
    another_otp = generate_numeric_otp(digits=6)
    assert otp != another_otp or len(otp) == 6


def test_generate_secure_token():
    token = generate_secure_token(32)
    assert isinstance(token, str)
    assert len(token) > 30
