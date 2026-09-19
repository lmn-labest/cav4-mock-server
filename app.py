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

APPLICATION_ID = "A17790"


def user_group(code: str, enabled: bool = True) -> dict:
    """Grupo do usuário na aplicação: `code` é o papel (`administrador` ou `usuario`)."""
    return {
        "uid": 66828,
        "code": code,
        "area": {"uid": 190663, "code": APPLICATION_ID},
        "enabled": enabled,
    }


# Grupos de cada usuário na CA. Fica fora de `users` porque `users` vai inteiro para o id_token.
user_groups = {
    "AAAA": [user_group("administrador")],
    "BBBB": [user_group("administrador")],
    "CCCC": [user_group("usuario")],
    "DDDD": [user_group("usuario")],
    "EEEE": [user_group("usuario")],
    "FFFF": [user_group("usuario")],
    "GGGG": [user_group("usuario", enabled=False)],
    "IIII": [],
}

# `access_token` emitido em `/oauth2/token` -> chave do usuário.
access_tokens = {}


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
    "GGGG": {
        "given_name": "Ana",
        "email": "ana@example.com",
        "department": "LABEST",
    },
    "IIII": {
        "given_name": "Rodrigo",
        "email": "rodrigo@example.com",
        "department": "LABEST",
    },
}

# Rota de autorização
@app.get("/oauth2/authorize")
async def authorize(
    request: Request,
    response_type: str,
    redirect_uri: str,
    scope: str,
    state: str,
):
    referer = request.headers.get("referer")
    if referer:
        if referer == redirect_uri:
            uri_to_use = redirect_uri
        else:
            uri_to_use = f"{referer}oauth2/login"
    else:
        uri_to_use = redirect_uri
    uri_to_use = redirect_uri

    code = str(uuid.uuid4())
    codes_storage[code] = {
        "redirect_uri": uri_to_use,
        "scope": scope,
        "state": state,
    }
    return RedirectResponse(f"/oauth2/login?code={code}&redirect_uri={uri_to_use}&state={state}")

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
    access_tokens[access_token] = user_key
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
async def login_get(request: Request, code: str, redirect_uri: str, state: str):
    return templates.TemplateResponse(
        request=request,
        name="login.jinja",
        context={
            "request": request,
            "code": code,
            "redirect_uri": redirect_uri,
            "state": state,
            "users": users,
        }
    )


@app.post("/oauth2/login")
async def login_post(
    user_key: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(...),
):
    codes_storage[code] |= { "user_key": user_key }
    return RedirectResponse(f"{redirect_uri}?code={code}&state={state}")


@app.get("/api/users/current/user-groups")
async def current_user_groups(request: Request):
    scheme, _, access_token = request.headers.get("authorization", "").partition(" ")

    if scheme.lower() != "bearer" or access_token not in access_tokens:
        raise HTTPException(401, "Token inválido")

    content = user_groups[access_tokens[access_token]]

    return {
        "content": content,
        "pageable": {"size": 100, "number": 0, "sort": {}, "mode": "OFFSET"},
        "totalSize": len(content),
    }
