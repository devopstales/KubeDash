# backend/Dockerfile (build context = repo root)
# --- stage 1: frontend build ----------------------------------------------
FROM node:20 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN npm install -g pnpm@10
ENV CI=true
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# --- stage 2: python deps --------------------------------------------------
FROM python:3.12-slim AS deps
WORKDIR /app
COPY --from=docker.io/astral/uv:latest /uv /usr/local/bin/uv
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# --- stage 3: runtime ------------------------------------------------------
FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=deps /app/.venv /app/.venv
COPY backend/app ./app
COPY backend/wsgi.py ./
COPY --from=frontend /build/dist ./static
ENV PATH="/app/.venv/bin:$PATH" \
    KUBEDASH_STATIC_DIR=/app/static \
    GUNICORN_WORKERS=4 GUNICORN_THREADS=2
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["sh", "-c", "exec gunicorn -w \"$GUNICORN_WORKERS\" --threads \"$GUNICORN_THREADS\" -b 0.0.0.0:8080 wsgi:app"]
