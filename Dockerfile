FROM python:3.12.14-alpine3.23@sha256:167bc85084c9df34480efc26b4528fb68feaa8a79183b5658952137025b6f061

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Apply Alpine's util-linux security fixes until the pinned base includes them.
RUN apk add --no-cache libuuid=2.41.6-r1

RUN addgroup -S -g 10001 decaustrum \
    && adduser -S -D -H -u 10001 -G decaustrum \
        -h /nonexistent -s /sbin/nologin decaustrum

COPY requirements/bootstrap.txt requirements/runtime.txt ./requirements/

# Check dependencies before removing pip, its vendored libraries, and its bootstrap.
RUN python -m pip install --upgrade --require-hashes --no-deps \
        --only-binary=:all: \
        --requirement requirements/bootstrap.txt \
    && python -m pip install --require-hashes --no-deps \
        --only-binary=:all: \
        --requirement requirements/runtime.txt \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -r /usr/local/lib/python3.12/ensurepip

COPY --chown=10001:10001 LICENSE THIRD_PARTY_NOTICES.md ./
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 policies ./policies

RUN mkdir -p /app/data \
    && chown 10001:10001 /app/data \
    && chmod 0700 /app/data

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).read()"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
