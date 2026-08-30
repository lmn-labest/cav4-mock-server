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

APPLICATIONS = [
    {
        "uid": 1178,
        "catalogId": "A17790",
        "creationDate": "2025-04-29T10:49:46Z",
        "applicationEnvironments": [
            {
                "uid": 10024667,
                "application": {
                    "catalogId": "A17790"
                },
                "environment": {
                    "uid": 8,
                    "code": "PRD",
                    "name": "Produção"
                },
                "administratorAuthorized": True,
                "readOnly": True,
                "grcEnabled": False,
                "authorizationProcessExternallyManaged": False,
                "consoleAuthorized": True,
                "integratedAuthenticationAllowed": True,
                "creationDate": "2025-09-02T11:05:31Z",
                "logSynchronous": False,
                "usingB2c": False
            },
            {
                "uid": 10024666,
                "application": {
                    "catalogId": "A17790"
                },
                "environment": {
                    "uid": 7,
                    "code": "HMG",
                    "name": "Homologação"
                },
                "administratorAuthorized": True,
                "readOnly": False,
                "grcEnabled": False,
                "authorizationProcessExternallyManaged": False,
                "consoleAuthorized": True,
                "integratedAuthenticationAllowed": True,
                "creationDate": "2025-09-02T11:05:00Z",
                "logSynchronous": False,
                "usingB2c": False
            },
            {
                "uid": 10024666,
                "application": {
                    "catalogId": "A17790"
                },
                "environment": {
                    "uid": 7,
                    "code": "TST",
                    "name": "Teste"
                },
                "administratorAuthorized": True,
                "readOnly": False,
                "grcEnabled": False,
                "authorizationProcessExternallyManaged": False,
                "consoleAuthorized": True,
                "integratedAuthenticationAllowed": True,
                "creationDate": "2025-09-02T11:05:00Z",
                "logSynchronous": False,
                "usingB2c": False
            }
        ],
        "translations": [
            {
                "uid": 21707,
                "shortName": "CONFIACIM",
                "name": "CONFIACIM",
                "description": "Calculadora do risco de vazamento e análise de confiabilidade do cimento. A aplicação executa análises de bainhas de cimento utilizando conceitos de confiabilidade estrutural.",
                "order": 1,
                "languageCode": "PT_BR"
            }
        ]
    },
]


users = {
    "AAAA": {
        "given_name": "Fernando",
        "email": "fernando@example.com",
        "department": "LACEO",
        "applications": APPLICATIONS,
    },
    "BBBB": {
        "given_name": "Henrique",
        "email": "henrique@example.com",
        "department": "LABEST",
        "applications": APPLICATIONS,
    },
    "CCCC": {
        "given_name": "Gabriela",
        "email": "gabi@example.com",
        "department": "LACEO",
        "applications": APPLICATIONS,
    },
    "DDDD": {
        "given_name": "Guilherme",
        "email": "gui@example.com",
        "department": "LACEO",
        "applications": APPLICATIONS,
    },
    "EEEE": {
        "given_name": "Manoel",
        "email": "manoel@example.com",
        "department": "LABEST",
        "applications": APPLICATIONS,
    },
    "FFFF": {
        "given_name": "Breno",
        "email": "brenol@example.com",
        "department": "LACEO",
        "applications": APPLICATIONS,
    },
    "GGGG": {
        "given_name": "Ana",
        "email": "ana@example.com",
        "department": "LABEST",
        "applications": APPLICATIONS,
    },
    "IIII": {
        "given_name": "Rodrigo",
        "email": "rodrigo@example.com",
        "department": "LABEST",
        "applications": APPLICATIONS,
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
    # referer = request.headers.get("referer")
    # if referer:
    #     if referer == redirect_uri:
    #         uri_to_use = redirect_uri
    #     else:
    #         uri_to_use = f"{referer}oauth2/login"
    # else:
    #     uri_to_use = redirect_uri
    uri_to_use = redirect_uri

    code = str(uuid.uuid4())
    codes_storage[code] = {
        "redirect_uri": uri_to_use,
        "scope": scope,
        "state": state,
    }
    breakpoint()
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


@app.get("/api/system/users/{user_key}/applications")
async def user_applications(user_key: str):
    return users[user_key]["applications"]
