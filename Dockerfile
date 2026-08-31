# syntax=docker/dockerfile:1.7

FROM python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

ARG PIP_VERSION=26.2.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system --gid 10001 decaustrum \
    && useradd --system --uid 10001 --gid decaustrum \
        --home-dir /nonexistent --no-create-home decaustrum

COPY requirements/runtime.lock ./requirements/runtime.lock

RUN python -m pip install --upgrade "pip==${PIP_VERSION}" \
    && python -m pip install --require-hashes --no-deps \
        --requirement requirements/runtime.lock

COPY --chown=10001:10001 LICENSE THIRD_PARTY_NOTICES.md ./
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 policies ./policies

RUN install -d --owner=10001 --group=10001 /app/data

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).read()"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
