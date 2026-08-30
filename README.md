# RegTrace

RegTrace is a project-scoped authorization backend for AI agents and other
automated systems. It evaluates configurable policies, records verifiable
decision evidence, supports human approval, and issues one-time execution
grants before a protected side effect can run.

This repository contains the FastAPI backend, SQLite persistence, webhook
worker, offline evidence verifier, and independently installable Python SDK.

## Reproducible environment

The supported development and runtime line is CPython 3.12. The repository
pins the preferred patch in `.python-version`, fixes direct and transitive
dependencies under `requirements/`, and uses the same locks in local setup,
CI, and the container image.

### Windows PowerShell

```powershell
Copy-Item .env.example .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
.\scripts\run-api.ps1
```

### Linux or macOS

```bash
cp .env.example .env
sh ./scripts/bootstrap.sh
sh ./scripts/run-api.sh
```

The example secrets are only for local development. Replace them before any
shared or production deployment. Once the API is ready:

- liveness: `http://127.0.0.1:8000/health/live`;
- readiness: `http://127.0.0.1:8000/health/ready`;
- interactive API documentation: `http://127.0.0.1:8000/docs`.

Run the webhook delivery process in a second terminal with
`scripts/run-worker.ps1` or `scripts/run-worker.sh`.

## Docker Compose

After copying `.env.example` to `.env`, start the API and webhook worker with:

```powershell
docker compose up --build
```

Compose builds a Python 3.12 image pinned by digest, runs as an unprivileged
user with dropped Linux capabilities, and stores SQLite state in the named
`regtrace-data` volume. The development port is bound only to
`127.0.0.1`, so it is not exposed to other devices on the local network. Stop
services without deleting evidence using:

```powershell
docker compose down
```

Deleting the named volume is intentionally a separate destructive operation.

## Verification

Run the complete local quality gate:

```powershell
.\scripts\check.ps1
```

or:

```bash
sh ./scripts/check.sh
```

It audits dependency vulnerabilities, rejects new Python security findings,
scans publishable files against reviewed secret-fixture fingerprints, runs the
complete test suite, and builds the distributable SDK wheel in a temporary
directory. An unreviewed or confirmed-secret baseline entry fails the gate. The
backend's deployment artifact is its container image. GitHub Actions repeats
those checks on Ubuntu, runs CodeQL and dependency review, scans the repository
and runtime image, and starts the image until `/health/ready` succeeds.

## Python SDK

The SDK can be installed independently:

```powershell
python -m pip install -e .\sdk\python
```

See `docs/sdk-python.md` for authorization, approval, asynchronous use, typed
errors, and guarded business-operation examples.

## Project documentation

- `docs/architecture.md`: boundaries, transaction model, integrity, webhooks,
  approvals, and security design;
- `docs/operations.md`: configuration, production hardening, health, metrics,
  logs, backups, and operational runbooks;
- `docs/sdk-python.md`: SDK and real side-effect integration.

The project is local until its owner explicitly publishes or deploys it.
