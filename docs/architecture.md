# DecAustrum backend architecture

DecAustrum uses a layered modular architecture. The goal is to keep HTTP,
application workflows, domain logic, and SQLite persistence independently
changeable while preserving explicit transaction boundaries.

## Layers

### Composition root

`app/main.py` builds the FastAPI application, owns its lifespan, and registers
routers. It must not contain endpoint or persistence logic.

### HTTP routers

`app/routers/` contains transport concerns:

- request parameters and headers;
- FastAPI dependencies;
- response models and status codes;
- delegation to application services or repositories.

Routers are grouped by domain: administration, administrative audit, policies,
authorization, decisions, evidence export, approvals, execution grants,
transactional webhooks, and health.

### Application services

`app/services/` coordinates complete use cases that involve validation,
multiple models, or multiple persistence operations. Examples include issuing
a project API key, evaluating an authorization request, resolving an approval,
and consuming its execution grant.

### Dependency wiring

`app/dependencies.py` owns the configured `EvidenceStore` instance and the
FastAPI dependencies for role-aware project and administrator authentication.
Project keys carry either a `RUNTIME` or `REVIEWER` role. Tests replace the
store through FastAPI's dependency override mechanism.

### Domain logic and models

The policy engine and Pydantic models remain independent from FastAPI and
SQLite. They define policy evaluation, decision priority, evidence, traces,
projects, API keys, approvals, execution grants, administrative audit events,
and authorization responses. Execution-grant signing is independent from HTTP
and SQLite persistence.

### Persistence

`app/storage/` contains one SQLite repository per domain:

- `projects.py`;
- `api_keys.py`;
- `audit.py`;
- `policies.py`;
- `decisions.py`;
- `evidence.py`;
- `integrity.py`;
- `approvals.py`;
- `execution_grants.py`;
- `idempotency.py`;
- `webhooks.py`.

`database.py` owns schema initialization, connections, foreign-key enforcement,
and legacy migrations.

`EvidenceStore` remains the public persistence facade for compatibility. It
delegates single-domain operations and coordinates transactions that span
several repositories.

## Main authorization flow

1. The authorization router authenticates a `RUNTIME` project key.
2. The authorization service checks project-scoped idempotency.
3. Active policies are loaded for that project only.
4. The policy engine returns a structured evaluation and complete trace.
5. The service creates the decision and, when required, a pending approval.
6. Decision, integrity proof, approval, idempotency record, immutable webhook
   events, and matching delivery rows are persisted in one transaction.

## Closed approval and execution flow

A `REQUIRE_APPROVAL` decision is not executable merely because its approval
row becomes `APPROVED`. The complete state machine is:

```text
PENDING -> REJECTED
PENDING -> EXPIRED
PENDING -> APPROVED + ACTIVE grant
                       |-> CONSUMED
                       `-> EXPIRED
```

Approval and rejection require a separate `REVIEWER` key. The runtime key that
created a request is structurally unable to resolve it, while reviewer keys
cannot authorize or consume execution grants. The API derives `resolved_by`
from the authenticated reviewer key ID and rejects any client-supplied resolver
identity.

New approval requests receive a UTC `expires_at`. A lazy transactional sweep
runs before approval reads, searches, exports, and resolution; due requests
are durably changed to `EXPIRED` and emit immutable audit and webhook events.
Legacy rows with no expiry remain readable and non-expiring.

Approval creates a version-1 HMAC-SHA-256 execution grant bound to the exact
project, decision, agent, action, and context through a canonical SHA-256
request fingerprint. The signed bearer token contains UUIDs, the fingerprint,
and issue/expiry times, but no authorization context. SQLite stores only the
token hash and grant claims. The plaintext token is returned only by the
approval response and can be deterministically regenerated for an idempotent
retry while it remains active.

`POST /v1/execution-grants/consume` verifies the signature, tenant, immutable
decision fingerprint, presented request fingerprint, stored token hash,
status, and expiry. One conditional SQLite update changes `ACTIVE` to
`CONSUMED`; a replay receives a conflict. A changed request receives a mismatch
conflict without consuming the grant, while malformed, forged, unknown, and
cross-project tokens all receive the same generic unauthorized response.

Database checks and triggers enforce the state machine independently of the
service layer. They prevent approval without an active matching grant,
out-of-window grant issuance, terminal approval rewrites, grant identity
changes, replay transitions, and deletion of either lifecycle record.

## Transaction boundaries

Multi-domain operations intentionally owned by `EvidenceStore` include:

- provisioning a project with its first API key and policy templates;
- persisting an authorization with its integrity proof, optional approval, and
  idempotency record;
- approving a request with its execution grant, audit events, webhook events,
  and matching deliveries;
- consuming or expiring a grant with its audit and transactional outbox event.

Administrative mutations are also coordinated there so the state change and
its audit event commit or roll back together. This covers project lifecycle,
API-key lifecycle, policy configuration and rollback, approval resolution and
expiry, and execution-grant issuance, consumption, and expiry.
The same boundary appends the corresponding webhook event and materializes one
delivery for every active matching subscription. An outbox failure therefore
rolls back the business mutation and its audit event rather than silently
losing external notification.

Policy configuration also has an explicit repository transaction: updating the
active policy snapshot and appending its immutable version either both succeed
or both roll back.

If any write fails, SQLite rolls back the complete operation. Domain
repositories expose connection-aware insert methods only for these coordinated
transactions.

## Project lifecycle invariants

Administrators can list, inspect, suspend, and reactivate managed projects.
Project status transitions follow these rules:

- repeating the current status is idempotent and preserves `updated_at`;
- a real status transition updates `updated_at` but never `created_at`;
- disabled projects cannot authenticate or receive additional API keys;
- reactivation restores access through non-revoked keys only;
- revoked keys remain revoked after any project transition;
- the default system project cannot be disabled through the administration API.

All project listing and lifecycle routes require the administrator API key.

## Immutable administrative audit

`administrative_audit_events` is the append-only control-plane history. Every
successful effective mutation records:

- a unique event ID and UTC timestamp;
- the affected project;
- actor type (`ADMIN`, `PROJECT`, or `SYSTEM`) and actor identifier;
- a constrained action and resource identity;
- an optional reason;
- JSON snapshots of the state before and after the mutation;
- action-specific metadata such as policy versions or approval resolution.

Execution-grant audit snapshots deliberately exclude token hashes and request
fingerprints.

The recorded actions are project creation and status changes, API-key creation
and revocation, policy creation, update, disable and rollback, approval
resolution or expiry, and execution-grant issuance, consumption, or expiry.
Initial project templates and default-project bootstrap operations are
attributed to `decaustrum-bootstrap` as a `SYSTEM` actor.

Administrative API clients can identify the operator with `X-Admin-Actor` and
provide a ticket or explanation with `X-Audit-Reason`. Existing clients remain
compatible: when the actor header is absent, DecAustrum records
`admin-api-key`. Approval resolution uses the authenticated project as the
actor type, derives the actor identifier from the `REVIEWER` key ID, and accepts
only an optional reason from the request.

Only effective state changes create events. Repeating an already completed
status change, key revocation, or policy disable is operationally idempotent
and does not append misleading duplicates. Failed validation and failed state
changes create no event. More importantly, the mutation and event share one
SQLite transaction; an audit insert failure rolls back the domain mutation.

API-key audit snapshots use public metadata only. Raw keys and key hashes are
never included. SQLite foreign keys preserve project ownership, and triggers
reject every `UPDATE` or `DELETE` against audit rows.

The administrator-only API supports paginated global or project-scoped
listing, exact event retrieval, and filters for action, resource, actor, and
timezone-aware occurrence range.

Webhook subscription creation, disablement, signing-secret rotation, and
manual delivery replay are administrative mutations too. They use the same
actor and reason headers and append `WEBHOOK_SUBSCRIPTION_CREATED`,
`WEBHOOK_SUBSCRIPTION_DISABLED`, `WEBHOOK_SECRET_ROTATED`, or
`WEBHOOK_REDELIVERY_REQUESTED` respectively. Subscription snapshots expose a
secret version but never a signing secret or master secret.

This log intentionally does not reconstruct historical administrative actions
that happened before the table existed because their actor and reason cannot be
known reliably. It is immutable against normal application and database writes,
but it is not a signed non-repudiation mechanism: a privileged database operator
could drop protections. Administrator identity is also declarative while a
shared admin key is used. SSO/RBAC identity and cryptographic audit anchoring
belong to later production hardening.

## Transactional events and signed webhooks

`webhook_events` is the immutable domain-event outbox. DecAustrum currently
emits these version-1 event types:

- `authorization.created`;
- `approval.requested`, `approval.resolved`, and `approval.expired`;
- `execution_grant.issued`, `execution_grant.consumed`, and
  `execution_grant.expired`;
- `project.created` and `project.status_changed`;
- `api_key.created` and `api_key.revoked`;
- `policy.created`, `policy.updated`, `policy.disabled`, and
  `policy.rolled_back`;
- subscription lifecycle and manual-redelivery administrative events.

Each event has a UUID, project, UTC occurrence time, constrained resource
identity, type, schema version, and JSON data. The exact canonical JSON body is
stored once with sorted keys, compact separators, UTF-8 Unicode, and rejected
non-finite numbers. SQLite triggers reject event updates and deletes.

When an event is appended, DecAustrum selects only active subscriptions in the
same project whose event selectors contain the event type or the standalone
`*` wildcard. It creates a unique `(event_id, subscription_id)` delivery in the
same SQLite transaction. A subscription created later never receives old
events. Event rows remain queryable even when no subscription matched, which
provides an operational record without inventing retroactive deliveries.

Administrators can create, list, inspect, rotate, and disable subscriptions at
`/v1/admin/projects/{project_id}/webhook-subscriptions`. Creation and rotation
return the signing secret once. Normal list and detail responses never include
it. Subscriptions are disabled rather than deleted so historical delivery
ownership remains intact. Disabling is idempotent and cancels queued work.

Signing secrets are derived with HMAC-SHA-256 from the subscription UUID,
secret version, and `DECAUSTRUM_WEBHOOK_MASTER_SECRET`. The master must contain at
least 32 bytes and must be supplied through the environment, never committed.
SQLite stores only `secret_version`; neither the master nor a derived signing
secret is persisted. Rotation increments the version and immediately changes
the key used for future attempts, including retries of previously queued
deliveries. Retaining the same master is therefore required across restarts.

Every request body is signed over:

```text
<unix_timestamp>.<exact_request_body>
```

with the derived subscription secret. Deliveries include:

- `X-DecAustrum-Delivery-Id` for receiver-side idempotency;
- `X-DecAustrum-Event-Id` and `X-DecAustrum-Event-Type`;
- `X-DecAustrum-Timestamp` for replay-window checks;
- `X-DecAustrum-Signature` in `v1=<hex-hmac>` format.

Receivers must verify the signature against the raw body before parsing JSON,
reject stale timestamps (five minutes is the provided verifier default), and
store processed delivery IDs. Delivery is deliberately **at least once**: an
expired worker lease can be reclaimed after a crash, so a request that reached
the receiver immediately before the crash may be sent again.

The dispatcher claims due rows with a 30-second lease and performs HTTP outside
the business transaction. Any 2xx response succeeds. Network failures and
non-2xx responses are appended to immutable `webhook_delivery_attempts` and use
exponential retry delays of 30, 60, 120, 240 seconds and so on, capped at one
hour. After five consecutive failures, the delivery enters `DEAD_LETTER`.
Manual redelivery resets the current failure cycle while preserving total
attempt history and increments `redelivery_count`.

Administrators can inspect project-scoped event and delivery pages, filter by
event or status, retrieve a delivery with its event, subscription, and complete
attempt history, and request redelivery. The synchronous administrator-only
`POST /v1/admin/webhook-deliveries/dispatch` endpoint processes a bounded batch
and is suitable for manual local operation or an external scheduler. The same
dispatcher is available as a dedicated process:

```powershell
python -m app.webhook_worker
```

`--once` processes one batch for cron-style scheduling; `--batch-size` and
`--poll-interval` control bounded work and idle polling. API and worker must use
the same SQLite database and `DECAUSTRUM_WEBHOOK_MASTER_SECRET`. A production
deployment should run this worker separately from the API so outbound latency
and retries never consume request-serving capacity.

Webhook URLs require HTTPS and reject credentials, fragments, localhost, and
private or reserved IP literals. The real transport resolves DNS exactly once
per attempt and rejects the complete result if any address is private or
reserved. It then connects directly to one of those validated addresses while
preserving the original hostname for TLS certificate verification and the HTTP
Host header. It returns 3xx responses without following them, so a redirect
cannot change the validated destination. The transport intentionally ignores
ambient proxy variables because a proxy would reintroduce an independent name
resolution and routing boundary. These controls reduce SSRF exposure but do
not replace production egress allowlists, an explicitly reviewed proxy policy,
rate limits, or per-customer network controls. Authorization event payloads
intentionally include the decision context; customers must treat their webhook
endpoint and signing secret as access to that potentially sensitive data.

## Immutable policy history

`project_policies` contains the current policy configuration used by the policy
engine. `project_policy_versions` is the append-only audit history. Each history
row contains the complete policy definition, its project and version identity,
the creation time, and one of these change types:

- `CREATED`: the first version of a policy;
- `UPDATED`: a normal policy revision;
- `ROLLBACK`: a new version copied from an older revision;
- `MIGRATED`: the current snapshot found when upgrading a legacy database.

Rollback never rewrites an old row or moves the current version backwards. If
version 2 is current and version 1 is restored, DecAustrum creates version 3 with
`change_type=ROLLBACK` and `source_version=1`. The current policy is re-enabled
as part of that transaction. Disabling a policy changes operational state but
does not create a content version.

SQLite triggers reject `UPDATE` and `DELETE` operations on history rows. The
primary key `(project_id, policy_id, version)` and every history query preserve
tenant isolation. Administrative endpoints support paginated history listing,
single-version retrieval, and rollback; tenant API keys cannot use them.

When an existing database is upgraded, DecAustrum can only preserve the current
snapshot because older overwritten definitions no longer exist. It records that
snapshot once as `MIGRATED`; initialization and backfill are idempotent.

## Cryptographically verifiable decision ledger

Every authorization decision is appended to a separate SHA-256 chain for its
project. DecAustrum serializes the fields defined by the immutable payload schema
version 1 as canonical JSON using UTF-8, sorted object keys, compact separators,
preserved Unicode, and rejected non-finite numbers. A later API response field
therefore cannot silently change historical hashes. Version 1 contains
`decision_id`, `project_id`, `evaluated_at`, `decision`, `policy`,
`policy_version`, `reason`, `evidence`, `agent`, `action`, `context`, and
`trace`. It then calculates:

```text
payload_hash = SHA-256(canonical_json(decision))
```

The integrity record is also canonicalized and hashed:

```text
record_hash = SHA-256(canonical_json({
    algorithm,
    created_at,
    decision_id,
    payload_hash,
    previous_hash,
    project_id,
    schema_version,
    sequence_number
}))
```

The first project record has `sequence_number=1` and `previous_hash=null`.
Every later record references the preceding `record_hash`. The schema version
is part of the hashed envelope, so it cannot be changed without invalidating the
proof. This makes payload changes, internal deletion, insertion, and reordering
detectable. Decision and integrity rows are inserted in one SQLite transaction,
and triggers reject updates or deletes from both tables.

Existing decisions are backfilled once in deterministic order by
`evaluated_at, decision_id`. A partially populated migration is rejected rather
than silently constructing a chain over an ambiguous state.

The authenticated integrity API provides:

- a descending, paginated project ledger;
- the proof for one decision;
- a self-contained decision-and-proof evidence bundle;
- complete project-chain verification;
- verification that an optional, previously trusted `head_hash` checkpoint is
  still present in the chain;
- administrator verification for any managed project.

Verification returns the first failing record and distinguishes missing
records, sequence gaps, broken predecessor links, unsupported schema versions,
unreadable decisions, timestamp mismatches, payload changes, invalid record
hashes, and a chain head that differs from an external checkpoint. The
checkpoint comparison also detects truncation from the end of an otherwise
internally consistent chain. Later valid appends do not invalidate an older
checkpoint.

### Threat model

The ledger is tamper-evident and independently reproducible from an exported
evidence bundle. It protects against application bugs and database writes that
do not also rebuild the complete chain. A client that stores a trusted head can
also detect a later full-chain rewrite or tail truncation. SHA-256 alone does
not provide non-repudiation when no trusted checkpoint exists: a privileged
operator able to drop database protections can recompute every hash. That
stronger guarantee requires signing or externally anchoring periodic chain
heads and is intentionally a separate production-hardening capability.

## Evidence search and verifiable export

Decision listing supports project-scoped combinations of decision, exact agent,
exact action, policy, policy presence, approval status, timezone-aware evaluated
range, case-insensitive text search, and ascending or descending order. Search
uses parameterized SQL, deterministic `evaluated_at, decision_id` ordering, and
compound project indexes. The tenant endpoint is `/v1/decisions`; administrators
can inspect one managed project at
`/v1/admin/projects/{project_id}/decisions`. Neither endpoint can query across
tenant boundaries.

The same filters are accepted by these authenticated export routes:

- `/v1/evidence/export` and `/v1/evidence/bundle` for a tenant;
- `/v1/admin/projects/{project_id}/evidence/export` and
  `/v1/admin/projects/{project_id}/evidence/bundle` for administrators.

The regular export supports streaming `json`, `ndjson`, and `csv` formats. Each
selected decision includes its integrity proof; CSV keeps nested context,
evidence, and trace values as canonical JSON columns. Response headers expose
the project, snapshot time, selected record count, maximum sequence, and chain
head. JSON also contains the criteria and snapshot in its envelope. Exports are
bounded to 2,000 selected records and 32 MiB of canonical record data so an
accidental unfiltered request cannot consume unbounded memory. CSV cells whose
first effective character is `=`, `+`, `-`, or `@` are prefixed with an
apostrophe, including leading-whitespace and control-character variants, so a
spreadsheet does not execute tenant text as a formula.

An export captures the chain head and selected records in one SQLite read
transaction. Later decisions receive higher sequence numbers and cannot enter
that export. This also prevents an approval status transition during generation
from changing which immutable decisions belong to the selected result. The
response body is then encoded incrementally.

The ZIP evidence bundle is the forensic format. It contains exactly:

```text
manifest.json
records.ndjson
chain.ndjson
```

`records.ndjson` contains the filtered decisions and their proofs.
`chain.ndjson` contains every proof from sequence 1 through the captured head,
not just matching decisions. This lets an offline verifier prove continuity,
ordering, predecessor links, every record hash, and each selected decision's
payload hash. The manifest records the exact filters, snapshot and generation
times, project, counts, captured head, optional trusted checkpoint, and separate
SHA-256 digests for the selected records, full chain, and logical bundle.

Archive loading rejects duplicate, missing, or unexpected members, malformed
JSON, invalid DecAustrum models, and oversized uncompressed content. ZIP member
metadata is deterministic, while verification hashes canonical logical data so
irrelevant whitespace or ZIP compression differences do not alter the result.
DecAustrum verifies every generated bundle before returning it and refuses export
with HTTP 409 if the live project ledger fails integrity verification. Bundle
chains are bounded to 10,000 records and 32 MiB; generated archive content is
bounded to 64 MiB. Database cursors are consumed incrementally and every limit
is checked before an additional record is retained.

The verifier does not require the API or database:

```powershell
python -m app.evidence_verifier evidence.zip
python -m app.evidence_verifier evidence.zip `
    --expected-head-hash <trusted-sha256-checkpoint>
```

It returns exit code 0 for verified evidence, 1 for a cryptographic verification
failure, and 2 for an unreadable or malformed archive. Supplying a checkpoint
that the verifier obtained through an independent trusted channel is the
strongest mode: an older checkpoint remains valid after legitimate appends, but
a rewritten or truncated chain is rejected. Without an external checkpoint the
bundle proves internal consistency and detects accidental or partial tampering;
as with the live ledger, an attacker able to replace the entire bundle and
recompute every digest is outside the SHA-256-only non-repudiation guarantee.

## Python SDK integration boundary

`sdk/python` is a separate, typed distribution with no import dependency on
the backend. It depends only on `httpx` and treats the HTTP API as the trust
boundary. Synchronous and asynchronous clients validate local inputs, send the
project API key and correlation ID, parse UUIDs and timezone-aware timestamps,
and reject malformed success responses instead of passing untyped dictionaries
into application code.

Remote SDK base URLs must use HTTPS. Plaintext HTTP is allowed only for loopback
development, and each request explicitly disables redirects even when a caller
injects an HTTPX client configured to follow them. Context validation rejects
non-finite numbers before a request is sent.

The SDK runtime surface covers authorization, decision lookup, approval
listing and resolution, and one-time execution-grant consumption. It does not
expose the administrator control plane. This separation lets application
runtimes receive only project-scoped credentials while project provisioning,
policy mutation, API-key lifecycle, webhook administration, and immutable
audit access remain privileged REST operations.

`DecAustrumGuard` is the real side-effect integration boundary:

```text
business request
      |
      v
SDK authorize ---- DENY ------------> callback not invoked
      |
      +---------- REQUIRE_APPROVAL --> callback not invoked
      |                                  |
      |                         reviewer approves
      |                                  |
      |                         one-time grant consumed
      |                                  |
      `---------- ALLOW -----------------+----> callback invoked
```

The approved path consumes its grant before entering the callback. This closes
the authorization state machine but cannot make an arbitrary external side
effect transactional with DecAustrum. Integrations should therefore keep the
callback narrow and idempotent, and re-authorize after an ambiguous or failed
post-consumption operation rather than replaying a grant.

SDK contract tests use mocked HTTP responses for transport and parser behavior.
Integration tests run both synchronous and asynchronous clients against the
real FastAPI ASGI app, SQLite repositories, policy engine, approval workflow,
and grant state machine; they assert the callback is reached exactly once only
on an authorized path.

## Reproducible distribution topology

The repository produces two intentional distribution boundaries:

```text
reviewed source + exact locks
          |
          +----> Python SDK wheel
          |
          `----> one backend container image
                         |
                         +----> API process
                         `----> webhook worker process
                                      |
                           shared SQLite data volume
```

API and worker use the same source, Python runtime, and runtime dependency lock;
only their process command differs. This prevents the dispatcher from drifting
from the API's domain and persistence models. The SDK remains a separate wheel
because clients must not import backend implementation modules.

The reproducibility boundary fixes the Python minor, every direct and transitive
Python package, the container base-image digest, and every third-party CI action
commit. Runtime configuration and secrets are deliberately outside that
boundary: they are injected from `.env` locally or a deployment secret manager
and never enter an artifact. Generated databases, caches, virtual environments,
test output, and local credentials are excluded from both Git and Docker build
context.

Local verification proves a clean dependency installation, the complete test
suite, and SDK packaging. CI additionally proves Compose parsing, image build,
container startup, and readiness on a clean Linux runner. Operational update
and release procedures are documented in `docs/operations.md`.

## Dependency direction

Dependencies flow inward:

```text
main -> routers -> services -> domain / EvidenceStore
                                  |
                                  v
                         storage repositories
                                  |
                                  v
                           SQLiteDatabase
```

Storage modules may depend on domain models. Domain models and the policy
engine must not import routers, services, or storage modules.

## Security and observability boundary

`create_app()` constructs runtime settings, a bounded Prometheus registry, and
a process-local rate limiter before registering the domain routers. A pure ASGI
middleware wraps every HTTP route and centralizes trusted-host checks, optional
CORS, production HTTPS enforcement, body and content-type limits, request IDs,
rate limits, defensive response headers, safe 500 responses, request metrics,
and structured access logs. Authentication remains a FastAPI dependency so
tenant and administrator identity is resolved by the existing domain boundary.

Metrics use route templates and fixed decision/security labels. Tenant IDs,
resource IDs, request values, API keys, raw paths, and query strings never
become labels or application-log fields. `/metrics` uses administrator
authentication and is hidden from OpenAPI. `/health/live` is process-only;
`/health/ready` verifies the SQLite connection and essential schema without
returning storage details. The legacy `/health` response remains available.

SQLite connections enable foreign keys, a bounded busy timeout, and
`synchronous=NORMAL`; initialization enables WAL. The in-memory rate limiter
and metrics registry deliberately match the current single-process SQLite MVP.
Horizontal scaling requires shared rate-limit state, per-process metrics
collection, and migration to a server database. Full deployment guidance and
the configuration contract are in `docs/operations.md`.

## Adding functionality

- Add a new endpoint to the router for its domain.
- Put multi-step workflow logic in a service rather than the router.
- Put SQL in the matching repository rather than a service.
- Add cross-repository transactions to `EvidenceStore` explicitly.
- Preserve project scoping on every tenant-owned query.
- Cover behavior at the narrowest useful layer and with an API integration test
  when the public contract changes.
