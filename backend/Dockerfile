FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini entrypoint.sh ./
RUN python -m pip install --no-cache-dir . && chmod +x /app/entrypoint.sh

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/health', timeout=3)"
CMD ["/app/entrypoint.sh"]
