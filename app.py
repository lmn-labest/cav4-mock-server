from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import RedirectResponse
import uuid
import jwt
from datetime import datetime, timedelta
from fastapi.templating import Jinja2Templates

app = FastAPI()

# Armazenamento em memória
codes_storage = {}
SECRET_KEY = "mysecretkey"

templates = Jinja2Templates(directory="templates")

users = {
    "AAAA": {
        "given_name": "Fernando",
        "email": "fernando@example.com",
        "department": "LACEO",
    },
    "BBBB": {
        "given_name": "Henrique",
        "email": "henrique@example.com",
        "department": "LABEST",
    },
    "CCCC": {
        "given_name": "Gabriela",
        "email": "gabi@example.com",
        "department": "LACEO",
    },
    "DDDD": {
        "given_name": "Guilherme",
        "email": "gui@example.com",
        "department": "LACEO",
    },
    "EEEE": {
        "given_name": "Manoel",
        "email": "manoel@example.com",
        "department": "LABEST",
    }, 
    "FFFF": {
        "given_name": "Breno",
        "email": "brenol@example.com",
        "department": "LACEO",
    },
}

# Rota de autorização
@app.get("/oauth2/authorize")
async def authorize(
    request: Request,
    response_type: str,
    redirect_uri: str,
    scope: str
):
    referer = request.headers.get("referer")

    if referer:
        if referer == redirect_uri:
            uri_to_use = redirect_uri
        else:
            uri_to_use = referer
    else:
        uri_to_use = redirect_uri

    code = str(uuid.uuid4())
    codes_storage[code] = {
        "redirect_uri": uri_to_use,
        "scope": scope
    }

    return RedirectResponse(f"/oauth2/login?code={code}&redirect_uri={uri_to_use}")

# Rota de token
@app.post("/oauth2/token")
async def token(
    request: Request,
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
    user_key = codes_storage[code]['user_key']
    payload = {
        **users[user_key],
        "user_login": user_key,
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


@app.get("/oauth2/login")
async def login_get(request: Request, code: str, redirect_uri: str):

    return templates.TemplateResponse(
        request=request,
        name="login.jinja",
        context={
            "request": request,
            "code": code,
            "redirect_uri": redirect_uri,
            "users": users,
        }
    )


@app.post("/oauth2/login")
async def login_post(
    user_key: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
):
    codes_storage[code] |= { "user_key": user_key }
    return RedirectResponse(f"{redirect_uri}?code={code}")
