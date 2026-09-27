import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

load_dotenv()  # carga las variables definidas en .env

# 🔑 SIEMPRE en variable de entorno — nunca en el código
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-cambiar-en-prod")
ALGORITHM = "HS256"
EXPIRY_MIN = 30
REFRESH_EXPIRY_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Vive aquí (y no en main.py) para evitar la importación circular main ↔ auth
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _encode(data: dict, expires: timedelta, token_type: str) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + expires
    payload["type"] = token_type  # distingue access de refresh
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_token(data: dict) -> str:
    return _encode(data, timedelta(minutes=EXPIRY_MIN), "access")


def create_refresh_token(data: dict) -> str:
    return _encode(data, timedelta(days=REFRESH_EXPIRY_DAYS), "refresh")


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _decode(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise _unauthorized("Token expirado o inválido")
    if not payload.get("sub"):
        raise _unauthorized("Token inválido")
    if payload.get("type") != expected_type:
        raise _unauthorized(f"Se esperaba un token de tipo '{expected_type}'")
    return payload


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return _decode(token, "access")


def verify_refresh_token(token: str) -> dict:
    return _decode(token, "refresh")
