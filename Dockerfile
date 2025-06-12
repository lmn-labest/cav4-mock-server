FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock ./

RUN uv sync --locked --no-install-project --no-dev

COPY app.py ./

CMD ["uv", "run", "fastapi", "dev", "--port", "9000", "--host", "0.0.0.0"]

EXPOSE 9000
