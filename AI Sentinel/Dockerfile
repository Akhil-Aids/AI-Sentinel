# AI Sentinel — multi-stage production image.
# Stage 1: build the React dashboard. Stage 2: FastAPI backend + static hosting.

FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim AS runtime

# Non-root user for security
RUN groupadd -r sentinel && useradd -r -g sentinel -m -s /bin/false sentinel

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_ENV=production \
    SENTINEL_ENVIRONMENT=production

WORKDIR /app
COPY backend/ /app/backend/
COPY --from=frontend-build /build/dist /app/frontend/dist

RUN mkdir -p /app/data && \
    pip install --no-cache-dir -r /app/backend/requirements.txt && \
    chown -R sentinel:sentinel /app

USER sentinel
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
