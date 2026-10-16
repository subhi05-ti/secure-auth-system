from fastapi import APIRouter

from app.api.v1.endpoints import auth, oauth, otp, users

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(otp.router)
api_router.include_router(oauth.router)
api_router.include_router(users.router)
