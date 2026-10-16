from pydantic import BaseModel, ConfigDict


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str | None = None

    model_config = ConfigDict(from_attributes=True)


class TokenPayload(BaseModel):
    sub: str
    email: str
    exp: int
    iat: int
    type: str
    jti: str | None = None
    is_superuser: bool = False


class RefreshTokenRequest(BaseModel):
    refresh_token: str | None = None
