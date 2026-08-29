# RegTrace backend architecture

RegTrace uses a layered modular architecture. The goal is to keep HTTP,
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

Routers are grouped by domain: administration, policies, authorization,
decisions, approvals, and health.

### Application services

`app/services/` coordinates complete use cases that involve validation,
multiple models, or multiple persistence operations. Examples include issuing
a project API key, evaluating an authorization request, and resolving an
approval.

### Dependency wiring

`app/dependencies.py` owns the configured `EvidenceStore` instance and the
FastAPI dependencies for tenant and administrator authentication. Tests replace
the store through FastAPI's dependency override mechanism.

### Domain logic and models

The policy engine and Pydantic models remain independent from FastAPI and
SQLite. They define policy evaluation, decision priority, evidence, traces,
projects, API keys, approvals, and authorization responses.

### Persistence

`app/storage/` contains one SQLite repository per domain:

- `projects.py`;
- `api_keys.py`;
- `policies.py`;
- `decisions.py`;
- `approvals.py`;
- `idempotency.py`.

`database.py` owns schema initialization, connections, foreign-key enforcement,
and legacy migrations.

`EvidenceStore` remains the public persistence facade for compatibility. It
delegates single-domain operations and coordinates transactions that span
several repositories.

## Main authorization flow

1. The authorization router authenticates the project.
2. The authorization service checks project-scoped idempotency.
3. Active policies are loaded for that project only.
4. The policy engine returns a structured evaluation and complete trace.
5. The service creates the decision and, when required, a pending approval.
6. Decision, approval, and idempotency record are persisted in one transaction.

## Transaction boundaries

Two multi-domain operations are intentionally owned by `EvidenceStore`:

- provisioning a project with its first API key and policy templates;
- persisting an authorization with its optional approval and idempotency record.

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
version 2 is current and version 1 is restored, RegTrace creates version 3 with
`change_type=ROLLBACK` and `source_version=1`. The current policy is re-enabled
as part of that transaction. Disabling a policy changes operational state but
does not create a content version.

SQLite triggers reject `UPDATE` and `DELETE` operations on history rows. The
primary key `(project_id, policy_id, version)` and every history query preserve
tenant isolation. Administrative endpoints support paginated history listing,
single-version retrieval, and rollback; tenant API keys cannot use them.

When an existing database is upgraded, RegTrace can only preserve the current
snapshot because older overwritten definitions no longer exist. It records that
snapshot once as `MIGRATED`; initialization and backfill are idempotent.

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

## Adding functionality

- Add a new endpoint to the router for its domain.
- Put multi-step workflow logic in a service rather than the router.
- Put SQL in the matching repository rather than a service.
- Add cross-repository transactions to `EvidenceStore` explicitly.
- Preserve project scoping on every tenant-owned query.
- Cover behavior at the narrowest useful layer and with an API integration test
  when the public contract changes.
