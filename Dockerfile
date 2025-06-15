FROM python:3.12-slim-bullseye
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock ./

RUN uv sync --locked --no-install-project --no-dev

COPY app.py ./

CMD ["uv", "run", "fastapi", "run", "--port", "9000"]

EXPOSE 9000
