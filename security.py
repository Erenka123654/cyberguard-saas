from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
from fastapi import Header, HTTPException
from app.config import settings

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd.hash(password)

def verify_password(password, hashed):
    return pwd.verify(password, hashed)

def create_token(user_id, role):
    payload = {"sub": str(user_id), "role": role,
               "exp": datetime.now(timezone.utc) + timedelta(hours=12)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")

def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        p = jwt.decode(authorization[7:], settings.jwt_secret, algorithms=["HS256"])
        return {"id": int(p["sub"]), "role": p["role"]}
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
