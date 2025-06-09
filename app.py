from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import RedirectResponse
import uuid
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# Armazenamento em memória
codes_storage = {}
SECRET_KEY = "mysecretkey"

# Rota de autorização
@app.get("/oauth2/authorize")
async def authorize(
    response_type: str,
    redirect_uri: str,
    scope: str
):
    code = str(uuid.uuid4())
    codes_storage[code] = {
        "redirect_uri": redirect_uri,
        "scope": scope
    }
    return RedirectResponse(f"{redirect_uri}?code={code}")

# Rota de token
@app.post("/oauth2/token")
async def token(
    code: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form(...),
    redirect_uri: str = Form(...),
    grant_type: str = Form(...)
):
    if code not in codes_storage:
        raise HTTPException(400, "Código inválido")

    # Gerar tokens
    access_token = str(uuid.uuid4())
    refresh_token = str(uuid.uuid4())

    # Criar JWT
    payload = {
        "user_login": "AAAA",
        "given_name": "Fernando",
        "email": "fernando@example.com",
        "department": "LACEO",
        "exp": datetime.utcnow() + timedelta(seconds=3600)
    }
    id_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "scope": scope,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    }
