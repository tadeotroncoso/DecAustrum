# RegTrace security and operations

This document describes the runtime controls built into the local MVP and the
minimum deployment contract around them. Application defaults are convenient
for local development. Production mode intentionally fails during startup when
security-critical configuration is missing or weak.

## Runtime configuration

| Variable | Development default | Production requirement |
| --- | --- | --- |
| `REGTRACE_ENVIRONMENT` | `development` | Set to `production`. |
| `REGTRACE_API_KEY` | No default | Required; at least 32 UTF-8 bytes. |
| `REGTRACE_ADMIN_API_KEY` | No default | Required; at least 32 bytes and different from the project key. |
| `REGTRACE_WEBHOOK_MASTER_SECRET` | No default | Required before provisioning or delivering webhooks; at least 32 bytes. |
| `REGTRACE_EXECUTION_GRANT_SECRET` | No default | Required to approve or consume grants; at least 32 bytes. Production startup fails without it, and it must differ from project and administrator keys. |
| `REGTRACE_TRUSTED_HOSTS` | Local hosts and `testserver` | Required comma-separated exact hosts or controlled `*.example.com` patterns. `*` is rejected. |
| `REGTRACE_CORS_ALLOWED_ORIGINS` | Empty | Optional comma-separated exact HTTPS origins. `*` and origins containing paths or credentials are rejected. |
| `REGTRACE_ENFORCE_HTTPS` | `false` | Defaults to `true` and cannot be disabled. |
| `REGTRACE_EXPOSE_DOCS` | `true` | Defaults to `false`. |
| `REGTRACE_MAX_REQUEST_BODY_BYTES` | `1048576` | Set to the smallest limit clients need; accepted range is 1 byte to 100 MiB. |
| `REGTRACE_APPROVAL_TTL_SECONDS` | `86400` | Approval window; 60 to 2,592,000 seconds. |
| `REGTRACE_EXECUTION_GRANT_TTL_SECONDS` | `300` | One-time execution window after approval; 30 to 3,600 seconds. |
| `REGTRACE_RATE_LIMIT_ENABLED` | `true` | Keep enabled. |
| `REGTRACE_RATE_LIMIT_WINDOW_SECONDS` | `60` | 1 to 3,600 seconds. |
| `REGTRACE_AUTHORIZATION_RATE_LIMIT` | `300` | Requests per credential and client address per window for `/v1/authorize`. |
| `REGTRACE_TENANT_RATE_LIMIT` | `600` | Requests per credential and client address per window for other tenant routes. |
| `REGTRACE_ADMIN_RATE_LIMIT` | `300` | Requests per administrator credential and client address per window for admin routes and metrics. |
| `REGTRACE_LOG_LEVEL` | `INFO` | Use `INFO`, `WARNING`, or `ERROR` normally. |

Boolean values accept `true/false`, `yes/no`, `on/off`, or `1/0`. Invalid
values stop application construction instead of silently weakening a control.
Copy `.env.example` only as a starting point and keep the resulting `.env`
outside version control.

Generate project, administrator, webhook, and execution-grant secrets
independently. Store them in the deployment platform's secret manager rather
than in command history, images, source files, logs, or monitoring labels.

## HTTP security boundary

Every HTTP request passes through one outer middleware before routing. It:

- rejects untrusted or ambiguous `Host` headers;
- enforces HTTPS in production and adds HSTS to HTTPS responses;
- allows only explicitly configured CORS origins, methods, and headers;
- rejects oversized bodies, malformed length framing, and non-JSON v1 write
  bodies;
- applies separate fixed-window limits to authorization, tenant, and
  administrator traffic, both by credential and by client address;
- accepts a safe caller `X-Request-ID` or generates a UUID;
- returns generic internal errors and validation errors without request input;
- adds `nosniff`, clickjacking, referrer, permissions, and no-store headers;
- records only route templates, never raw URLs or query strings.

CORS is a browser control, not authentication. Every tenant route still
requires `X-API-Key`, while administrator routes and `/metrics` require
`X-Admin-API-Key`.

The built-in limiter is thread-safe but process-local. It is correct for the
single API process used by this SQLite MVP. Before running multiple API
processes or replicas, move rate-limit state to a shared gateway or store such
as Redis; otherwise each process enforces an independent allowance. Configure
the HTTP server to trust forwarded client information only from the known
reverse proxy.

## Approval execution runbook

An authorization response with `REQUIRE_APPROVAL` creates a pending request
whose `expires_at` is controlled by `REGTRACE_APPROVAL_TTL_SECONDS`.

1. Review and approve with
   `POST /v1/approvals/{decision_id}/approve`.
2. Protect the returned `execution_grant` as a short-lived bearer credential.
   Do not log it, place it in URLs, persist it in analytics, or send it through
   webhook payloads.
3. Execute the exact approved agent/action/context through
   `POST /v1/execution-grants/consume`. Success consumes the credential in the
   same transaction that records audit and webhook events.
4. Treat `execution_grant_mismatch`, `execution_grant_already_consumed`, and
   `execution_grant_expired` as terminal for that token. Re-authorize the
   action when a fresh decision is needed.

Rejected or expired approvals never receive a grant. An approved grant may be
consumed once and cannot be reset. RegTrace stores only its SHA-256 hash; the
raw credential appears only in approval responses. Grant issue, consumption,
expiry, and approval expiry are visible in immutable administrative audit and
the transactional webhook outbox without secret material.

Approved rows created by an older RegTrace version are migrated as historical
records but never receive a grant retroactively. Re-authorize those actions so
the new approval and grant are created under the closed flow.

Changing `REGTRACE_EXECUTION_GRANT_SECRET` immediately invalidates every
unconsumed token signed with the previous value. For a planned rotation, either
wait longer than the configured maximum grant TTL after stopping new approval
issuance, or explicitly accept that outstanding grants will be invalidated.
The current local MVP intentionally supports one active signing secret rather
than a multi-key verification ring.

## Health and metrics

| Endpoint | Authentication | Meaning |
| --- | --- | --- |
| `GET /health` | None | Backward-compatible liveness response. |
| `GET /health/live` | None | The process can answer HTTP. It does not touch storage. |
| `GET /health/ready` | None | SQLite is reachable, WAL is active, foreign keys are enabled, and essential tables exist. Returns 503 without internal details when unavailable. |
| `GET /metrics` | Administrator key | Prometheus text exposition. It is intentionally omitted from OpenAPI. |

Prometheus output contains build and process-start information, readiness,
in-flight requests, request totals and latency histograms by method, route
template and status, security events, and authorization decisions. It never
labels metrics with API keys, project IDs, decision IDs, agents, actions,
contexts, raw paths, or other unbounded tenant data.

The metrics registry is in process memory. A restart resets counters, which is
normal for Prometheus counters when each process is identified as a new target.
With multiple processes, expose or aggregate one registry per process rather
than assuming the current endpoint combines them.

Suggested probes:

```text
liveness:  GET /health/live
readiness: GET /health/ready
```

Do not use `/metrics` as a health probe because it deliberately requires an
administrator secret.

## Structured logs

RegTrace application and webhook-worker logs are one JSON object per line.
HTTP completion records use bounded fields such as request ID, method, route
template, status, duration, and authenticated principal type. Worker records
contain only delivery outcome counts. Exceptions record their type but not the
exception message.

The application does not log request or response bodies, API keys, webhook
secrets, authorization contexts, query strings, project identifiers, or raw
resource paths. Uvicorn's raw access logger is disabled when RegTrace logging is
configured because the middleware emits the safer access record. Ship stdout
and stderr to a centralized, access-controlled log system and alert on:

- repeated `authentication_failed`, `invalid_host`, `cors_origin_denied`, or
  `rate_limit_exceeded` events;
- sustained HTTP 5xx responses;
- readiness becoming zero;
- webhook retries and dead-letter outcomes.

Keep log retention and access aligned with the sensitivity of authorization
metadata even though payloads are excluded.

## SQLite operational behavior

Every connection enables foreign keys, a five-second busy timeout, and
`synchronous=NORMAL`. Initialization enables WAL mode. These settings improve
concurrent read/write behavior and turn transient lock contention into a
bounded wait. They do not make a single SQLite file highly available.

Use a persistent local volume, restrict filesystem permissions to the service
account, take tested backups of the database plus WAL state, and monitor disk
space. Run only one writer deployment against a local SQLite database. Moving
to multiple hosts requires a transactional server database and migration of
the repository layer.

## Production deployment checklist

1. Put RegTrace behind a reverse proxy or load balancer that terminates TLS.
2. Set `REGTRACE_ENVIRONMENT=production`, exact trusted hosts, and only the
   required HTTPS CORS origins.
3. Generate distinct high-entropy project, administrator, webhook, and
   execution-grant secrets and inject them from a secret manager.
4. Configure the server to trust proxy headers only from the actual proxy,
   suppress its implementation header, and keep raw access logging disabled.
5. Start with one API process while using the local SQLite backend and built-in
   rate limiter.
6. Run `python -m app.webhook_worker` as a separate supervised process when
   transactional webhooks are enabled.
7. Probe `/health/live` and `/health/ready`; scrape `/metrics` with a dedicated
   administrator credential over the private network.
8. Centralize JSON logs and create alerts for authentication abuse, rate-limit
   events, 5xx responses, readiness failures, and webhook dead letters.
9. Back up and restore-test the SQLite data volume. Protect any externally
   stored integrity-chain checkpoint separately from the database.
10. Run the full test suite before release and test key rotation, restore, and
    webhook recovery in a non-production environment.

This block hardens the application boundary and makes one-process operation
observable. Network firewalling, certificate management, secret rotation by
the hosting platform, centralized alert delivery, distributed rate limiting,
database high availability, and signed or externally anchored ledger heads
remain deployment/infrastructure responsibilities.
