# DecAustrum HTTP API

This document is a route and behavior map for reviewers and integrators. The
generated OpenAPI document is authoritative for request and response schemas.
When documentation is enabled, it is available from a running API at:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`

The local base URL is `http://127.0.0.1:8000`. Deployments must enforce HTTPS
before credentials are sent over a network.

## Authentication boundaries

DecAustrum deliberately separates project traffic from control-plane traffic.

| Boundary | Header | Used for |
| --- | --- | --- |
| Public | None | Health checks only. |
| Project | `X-API-Key` | Authorization, project policies, decisions, approvals, grants, integrity, and evidence. |
| Administrator | `X-Admin-API-Key` | Project provisioning, API keys, policy configuration, audit, webhooks, cross-project evidence, and metrics. |

Administrative mutations also accept `X-Admin-Actor` and `X-Audit-Reason`.
They make the responsible actor and reason explicit in the immutable
administrative audit trail. The administrator key is a control-plane secret and
must never be distributed to project clients.

All `/v1` write requests with a body use `application/json`. A caller may send a
safe `X-Request-ID`; otherwise the API generates one. The response always
returns the effective request identifier in `X-Request-ID`.

## Request semantics

### Idempotency

`POST /v1/authorize` accepts an optional `Idempotency-Key` header of up to 255
characters. The key is scoped to the authenticated project.

- Repeating the same key with the same normalized request returns the original
  authorization record.
- Reusing the key for a different agent, action, or context returns `409
  Conflict`.
- An idempotent retry does not create a second decision, approval, integrity
  record, or webhook event.

### Pagination

Collection endpoints use `limit` and `offset`:

- `limit` defaults to `20` and must be between `1` and `100`;
- `offset` defaults to `0` and must be non-negative; and
- paginated JSON responses contain `items`, `total`, `limit`, and `offset`.

### Decision search

Decision lists and evidence exports accept the same filter vocabulary:

| Parameter | Meaning |
| --- | --- |
| `decision` | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. |
| `agent` | Exact agent identifier. |
| `action` | Exact action identifier. |
| `policy_id` | Exact winning policy identifier. |
| `has_policy` | Whether a policy produced the final decision. |
| `approval_status` | Approval state associated with the decision. |
| `evaluated_after` | Inclusive lower timestamp boundary with timezone. |
| `evaluated_before` | Inclusive upper timestamp boundary with timezone. |
| `query` | Bounded free-text search over indexed decision fields. |
| `sort` | `asc` or `desc`; defaults to newest first. |

Evidence exports additionally accept `expected_head_hash`, an externally
trusted current or historical chain checkpoint. Standard exports use
`format=json`, `format=ndjson`, or `format=csv`.

### Errors

Domain errors use FastAPI's `detail` envelope with a stable machine-readable
code and a human-readable message:

```json
{
  "detail": {
    "code": "idempotency_key_conflict",
    "message": "Idempotency key has already been used with a different request."
  }
}
```

The main status classes are:

| Status | Meaning |
| --- | --- |
| `401` | Missing or invalid project/admin credentials, or an invalid execution grant. |
| `404` | Resource not found inside the authenticated boundary. |
| `409` | Idempotency, lifecycle, replay, or immutable-state conflict. |
| `413` | Request body or evidence export exceeds its configured limit. |
| `415` | A `/v1` write body is not JSON. |
| `422` | Invalid schema, search range, policy context, or query parameters. |
| `429` | The configured request limit has been exceeded. |

Validation responses are sanitized and do not echo submitted values.

## Project API

Every route in this section requires `X-API-Key` and can only access the
authenticated project.

### Authorization and active policies

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/authorize` | Evaluate an action and persist its complete decision record. |
| `GET` | `/v1/policies` | List the project's active policy configurations. |
| `GET` | `/v1/policies/{policy_id}` | Read one active project policy. |

An authorization response contains the decision ID, project ID, UTC timestamp,
decision, winning policy and version, reason, condition evidence, original
agent/action/context, and complete policy trace.

### Decisions, evidence, and integrity

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/decisions` | Search and paginate authorization decisions. |
| `GET` | `/v1/decisions/{decision_id}` | Read one decision. |
| `GET` | `/v1/decisions/{decision_id}/evidence` | Return the canonical verifiable decision record. |
| `GET` | `/v1/decisions/{decision_id}/integrity` | Return the decision's chain proof. |
| `GET` | `/v1/integrity` | Page through integrity records. |
| `GET` | `/v1/integrity/verify` | Verify the authenticated project's decision chain. |
| `GET` | `/v1/evidence/export` | Stream filtered JSON, NDJSON, or CSV evidence. |
| `GET` | `/v1/evidence/bundle` | Download a self-contained, verifiable ZIP bundle. |

The bundle contains `manifest.json`, `records.ndjson`, and `chain.ndjson`. The
offline verifier checks file digests, manifest metadata, canonical record
hashes, chain continuity, selection boundaries, and an optional external
checkpoint. See the [operations guide](operations.md) for verifier commands and
the integrity threat model.

### Approval and execution

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/approvals` | List approvals, optionally filtered by status. |
| `GET` | `/v1/approvals/{decision_id}` | Read the approval associated with a decision. |
| `POST` | `/v1/approvals/{decision_id}/approve` | Approve a pending request and issue a one-time execution grant. |
| `POST` | `/v1/approvals/{decision_id}/reject` | Reject a pending request. |
| `POST` | `/v1/execution-grants/consume` | Consume a grant bound to the exact approved request. |

The closed approval flow is:

1. Authorize an action.
2. If the result is `REQUIRE_APPROVAL`, review the pending approval.
3. Approve it to obtain a short-lived bearer grant, or reject it terminally.
4. Submit the grant with the original agent, action, and context.
5. Run the protected side effect only after grant consumption succeeds.

Grant consumption happens before the business callback. A consumed, expired,
cross-project, or request-mismatched grant cannot authorize execution.

## Administrative API

Every route in this section requires `X-Admin-API-Key`.

### Projects and API keys

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/admin/projects` | List projects, optionally filtered by lifecycle status. |
| `POST` | `/v1/admin/projects` | Provision a project and its first API key. |
| `GET` | `/v1/admin/projects/{project_id}` | Read project metadata. |
| `PATCH` | `/v1/admin/projects/{project_id}` | Activate or disable a project. |
| `POST` | `/v1/admin/projects/{project_id}/api-keys` | Create an additional project key. |
| `GET` | `/v1/admin/projects/{project_id}/api-keys` | List key metadata without exposing key material. |
| `DELETE` | `/v1/admin/projects/{project_id}/api-keys/{api_key_id}` | Revoke a project key. |

Plaintext project keys are returned only when provisioned. The database stores
key hashes and non-secret metadata.

### Policy configuration and history

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/admin/projects/{project_id}/policies` | List project policy configurations. |
| `GET` | `/v1/admin/projects/{project_id}/policies/{policy_id}` | Read the active configuration for one policy. |
| `PUT` | `/v1/admin/projects/{project_id}/policies/{policy_id}` | Create or replace a policy by appending a version. |
| `DELETE` | `/v1/admin/projects/{project_id}/policies/{policy_id}` | Disable a policy without deleting its history. |
| `GET` | `/v1/admin/projects/{project_id}/policies/{policy_id}/versions` | List immutable policy versions. |
| `GET` | `/v1/admin/projects/{project_id}/policies/{policy_id}/versions/{version}` | Read one historical version. |
| `POST` | `/v1/admin/projects/{project_id}/policies/{policy_id}/rollback` | Restore historical content as a new version. |

### Administrative audit

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/admin/audit-events` | Filter and paginate immutable administrative events. |
| `GET` | `/v1/admin/audit-events/{event_id}` | Read one audit event. |

The audit list supports project, action, resource, actor, and timezone-aware
date filters. Mutations and their audit records commit atomically.

### Webhooks and transactional delivery

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/admin/projects/{project_id}/webhook-subscriptions` | Create a signed webhook subscription. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-subscriptions` | List subscriptions. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-subscriptions/{subscription_id}` | Read one subscription. |
| `DELETE` | `/v1/admin/projects/{project_id}/webhook-subscriptions/{subscription_id}` | Disable a subscription. |
| `POST` | `/v1/admin/projects/{project_id}/webhook-subscriptions/{subscription_id}/rotate-secret` | Rotate the signing secret. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-events` | List immutable outbox events. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-events/{event_id}` | Read one event. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-deliveries` | List delivery attempts. |
| `GET` | `/v1/admin/projects/{project_id}/webhook-deliveries/{delivery_id}` | Read one delivery attempt. |
| `POST` | `/v1/admin/projects/{project_id}/webhook-deliveries/{delivery_id}/redeliver` | Requeue a dead-letter delivery. |
| `POST` | `/v1/admin/webhook-deliveries/dispatch` | Dispatch a bounded batch administratively. |

The independent worker is the intended delivery path. It uses at-least-once
semantics, so receivers must deduplicate by event ID.

### Cross-project evidence and operations

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/admin/projects/{project_id}/decisions` | Search one managed project's decisions. |
| `GET` | `/v1/admin/projects/{project_id}/evidence/export` | Export filtered project evidence. |
| `GET` | `/v1/admin/projects/{project_id}/evidence/bundle` | Build a verifiable project evidence bundle. |
| `GET` | `/v1/admin/projects/{project_id}/integrity/verify` | Verify a managed project's chain. |
| `GET` | `/metrics` | Read bounded Prometheus metrics. |

## Health endpoints

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | None | Compatibility health response. |
| `GET` | `/health/live` | None | Process liveness. |
| `GET` | `/health/ready` | None | Database and application readiness; returns `503` when unavailable. |

Health responses intentionally contain no configuration, version inventory,
credential state, or database details.

## SDK boundary

Application code should normally use the typed [Python SDK](sdk-python.md)
instead of constructing requests directly. `DecAustrumGuard` and
`AsyncDecAustrumGuard` ensure the protected callback is not invoked for `DENY`
or `REQUIRE_APPROVAL`, and support the one-time approved execution path.
