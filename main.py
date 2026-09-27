from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from auth import (
    create_refresh_token,
    create_token,
    get_current_user,
    hash_password,
    verify_password,
    verify_refresh_token,
)

app = FastAPI(title="API con JWT")

# Base de datos simulada (en producción: PostgreSQL).
# Los hashes se generan al arrancar para que las contraseñas de prueba funcionen.
fake_users = {
    "maria@ujap.edu.ve": {"hashed": hash_password("profesor123"), "role": "profesor"},
    "estudiante@ujap.edu.ve": {"hashed": hash_password("estudiante123"), "role": "estudiante"},
}


class RefreshRequest(BaseModel):
    refresh_token: str


def _issue_tokens(email: str, role: str) -> dict:
    data = {"sub": email, "role": role}
    return {
        "access_token": create_token(data),
        "refresh_token": create_refresh_token({"sub": email}),
        "token_type": "bearer",
    }


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = fake_users.get(form.username)
    if not user or not verify_password(form.password, user["hashed"]):
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _issue_tokens(form.username, user["role"])


@app.post("/refresh-token")      # 🔄 Renueva el access token sin volver a pedir contraseña
def refresh_token(body: RefreshRequest):
    payload = verify_refresh_token(body.refresh_token)
    email = payload["sub"]
    user = fake_users.get(email)
    if not user:  # el usuario pudo ser eliminado después de emitir el token
        raise HTTPException(
            status_code=401,
            detail="Usuario no existe",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # El rol se lee de la BD, no del token: si cambió, el nuevo access token lo refleja
    return _issue_tokens(email, user["role"])


@app.get("/publico")             # 🌐 Sin protección
def ruta_publica():
    return {"msg": "Cualquiera puede ver esto"}


@app.get("/privado")             # 🔐 Requiere token válido
def ruta_privada(user=Depends(get_current_user)):
    return {"msg": f"Hola {user['sub']}, rol: {user['role']}"}


@app.get("/admin")               # 🛡️ Solo profesores
def ruta_admin(user=Depends(get_current_user)):
    if user["role"] != "profesor":
        raise HTTPException(status_code=403, detail="Solo para profesores")
    return {"msg": "Panel de administración"}
