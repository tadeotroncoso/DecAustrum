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

If any write fails, SQLite rolls back the complete operation. Domain
repositories expose connection-aware insert methods only for these coordinated
transactions.

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
