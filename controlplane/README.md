# controlplane — Enterprise AI Runtime Security Control Plane (Sprint 1–3)

Reference implementation of the Enterprise AI Runtime Security Control Plane,
per spec `[10]Cloud Native Enterprise AI Security Control Plane -v1.6.md`
(§23 Sprint 1 + Sprint 2 + Sprint 3).

This module is a **compilable, testable end-to-end vertical slice**: the
contracts, deterministic fusion, deterministic policy resolution, the
`POST /v1/decisions:evaluate` runtime decision API (INV-7 provenance check,
first-write-wins idempotency, signed Decision Contract), minimal synchronous
evidence commit, a mock Enforcement Adapter, and the **Tool / MCP
pre-execution security slice** (metadata snapshots, drift detection, trust
state, confirmation binding + TOCTOU re-validation). It has **zero external
dependencies** (Go stdlib only).

## Layout

```
controlplane/
├── go.mod                         module (stdlib only)
├── contracts/                     normative machine artifacts (embedded)
│   ├── embed.go                   go:embed of the artifacts below
│   ├── stage_action_matrix.json   canonical Stage x Action Matrix (v1.6 §2)
│   └── schema/
│       ├── context.schema.json    Context contract (v1.6 §7)
│       ├── signal.schema.json     Signal contract (v1.6 §8, INV-7)
│       └── decision.schema.json   Decision contract (v1.6 §11, §1.4, §6.2)
├── model/                         shared types + severity/uncertainty lattices
│   ├── enums.go                   Stage, Severity, Action(+strength), RiskFamily, ...
│   └── types.go                   Context, Signal, FusedRisk, Conflict, ...
├── matrix/                        Stage x Action Matrix loader + validator
│   ├── matrix.go                  the SINGLE validator for lint/decision/enforce
│   └── matrix_test.go
├── fusion/                        deterministic fusion engine (v1.6 §3)
│   ├── fuse.go                    normalize -> monotonic rule merge -> aggregate
│   └── fuse_test.go               golden vectors TV-1..TV-6
├── policy/                        deterministic conflict resolution (v1.6 §4)
│   ├── resolve.go                 action strength order + constraint union
│   ├── evaluate.go                policy evaluator v0 (scope + condition match)
│   ├── bundle_default.go          MVP bundle for the 3 golden scenarios
│   └── resolve_test.go
├── tool/                          Tool/MCP pre-execution security (v1.5 §15, INV-5)
│   ├── tool.go                    ActionContext, snapshot, drift, trust, fingerprint
│   └── tool_test.go
├── approval/                      Approval Binding Service (v1.5 §15.3/§15.4)
│   ├── approval.go                bind + TOCTOU re-validation (§15.4 rules)
│   └── approval_test.go
├── decision/                      Decision Contract (INV-3, v1.6 §11)
│   └── contract.go                build + hash + sign + validate + approval binding
├── evidence/                      minimal synchronous evidence commit (v1.6 §13.3)
├── enforcement/                   mock Enforcement Adapter (v1.5 §12)
├── sign/                          decision integrity signing (HMAC, v1.6 §5.4)
├── idutil/                        prefixed id generation
├── service/                       runtime decision MVP
│   ├── service.go                 Evaluate(): provenance -> fuse -> resolve -> sign -> evidence
│   ├── registry.go                Detector Registry (INV-7)
│   ├── http.go                    POST /v1/decisions:evaluate
│   ├── defaults.go                fully-wired default Service
│   └── golden_test.go            3 golden scenarios end to end
└── cmd/controlplane/main.go       HTTP server
```

## Run the server

```bash
cd controlplane
go run ./cmd/controlplane          # listens on :8080 (CONTROL_PLANE_ADDR to change)

curl -s -X POST localhost:8080/v1/decisions:evaluate \
  -H 'Content-Type: application/json' -d @example_request.json
```

> Note: the v1.6 spec doc shows the Stage x Action Matrix in YAML for
> readability; the canonical **machine** artifact in this module is
> `contracts/stage_action_matrix.json` (so the loader stays stdlib-only). The
> two MUST be kept in sync; the JSON is authoritative for code.

## Build & test

```bash
cd controlplane
go build ./...
go vet ./...
go test ./...
```

## What is implemented

### Sprint 1 — Contract Foundation
- **Stage × Action Matrix** single source of truth (`matrix.Validate`) backing
  lint (PL-002), decision-output validation, and enforcement-input validation.
- **Deterministic Fusion** (`fusion.Fuse`): canonical normalization, monotonic
  lattice merge (order-independent), FR-008..FR-006, `deterministic_v1`
  aggregation. Proven order-independent (`TestTV6_OrderIndependence`).
- **Deterministic Policy Resolution** (`policy.Resolve`): action strength order +
  constraint union, "combine" semantics, terminal-stop suppression,
  redaction-tie escalation, fail-closed defaults.
- **JSON Schemas** for Context / Signal / Decision (INV-7 + §6.2 fields).

### Sprint 2 — Runtime Decision MVP
- **`POST /v1/decisions:evaluate`** (`service.Service`) orchestrating
  provenance → fusion → policy → signed decision → evidence.
- **INV-7 provenance** (`service.verifyProvenance`): unregistered/invalid sources
  dropped and surfaced as `registry_miss` / `signal_integrity_violation`, recorded
  in `replay_binding.dropped_signals`.
- **First-write-wins idempotency** keyed by `(trace_id, request_id, stage)` (§5.3).
- **Policy evaluator v0** (`policy.Bundle.Match`) + MVP bundle covering all
  three golden scenarios.
- **Decision Contract** built, hashed, and HMAC-signed (`decision.Build`); §11.2
  correctness validated (`decision.Validate`).
- **Minimal synchronous evidence commit** (`evidence.MemStore`, §13.3).
- **Mock Enforcement Adapter** (`enforcement.MockAdapter`): verifies signature
  (INV-3 extended), validates against the matrix, executes the action; gates
  (`require_confirmation`/`step_up_auth`/`require_review`) return `skipped`.

### Sprint 3 — Tool Pre-Execution Slice
- **ToolActionContext + Metadata Snapshot + Registry** (`tool`): the platform MCP
  registry is authoritative; the control plane snapshots it (INV-5).
- **Drift detection + trust state** (`tool.DetectDrift` / `tool.ResolveTrust`):
  schema/manifest drift, pinned-exact-match, revoked, unknown (§15.5).
- **Approval Binding Service** (`approval`): binds a concrete action via an action
  fingerprint, and **re-validates at execution time** against the §15.4 rules
  (schema/manifest/parameter/target/destination drift, expiry) — closing the
  TOCTOU window between approval and execution (review P1-4).
- **`service.EvaluateToolAction`** + `ApproveToolAction`: the full
  require_confirmation → approve → allow lifecycle.

### Golden / tool scenario results
| Scenario | Stage | Decision |
| -------- | ----- | -------- |
| 1 Enterprise data leakage | output | `redact` |
| 2 Prompt injection retrieval | retrieval | `restrict_scope` |
| 3 Tool pre-execution (no approval) | tool_pre_execution | `require_confirmation` (tool not executed) |
| 3 + valid approval | tool_pre_execution | `allow` |
| 3 + schema drift after approval | tool_pre_execution | `require_confirmation` (approval invalidated) |
| 3 + tampered target (TOCTOU) | tool_pre_execution | not `allow` |
| Revoked tool | tool_pre_execution | `deny` |
| Unknown elevated tool | tool_pre_execution | `deny` |
| Unknown read tool | tool_pre_execution | `require_review` |

## Not yet implemented (later sprints)

- Edge security: mTLS, workload identity, rate limiting, anti-replay (§5.1/§5.2)
  — belongs to the serving edge, intentionally out of the handler.
- Async judge augmentation + `decision_revision` flow (§6.2 fields are present).
- Replay-lite API, Evaluation Harness, Release Gate (Sprint 4–5).
- Full Evidence Package enrichment + encryption/tenant isolation (Sprint 4).
- HTTP route for `EvaluateToolAction` (currently the in-process API; the
  `/v1/decisions:evaluate` handler covers the non-tool path).
- JSON Schema runtime validation wiring (schemas embedded; validator pending).

## Design guarantees

| Property | Where | Test |
| -------- | ----- | ---- |
| Fusion determinism / replayability | `fusion.Fuse` | TV-1..TV-6 |
| Order-independence | monotonic merge + canonical sort | `TestTV6_OrderIndependence`, `TestResolveOrderIndependence` |
| Single-source stage/action validation | `matrix` | `TestStageActionRules` |
| Policy conflict determinism | action strength order | `TestPairwiseConflicts`, `TestMultiPolicyConstraintUnion` |
| Fail-closed defaults | `policy.defaultDecision` | `TestDefaultDecisionFailClosed` |
| Idempotency (first-write-wins) | `service.storeIfAbsent` | `TestIdempotencyFirstWriteWins` |
| Signal provenance (INV-7) | `service.verifyProvenance` | `TestProvenanceDropsUnregisteredSource` |
| Decision signing + verify | `decision.Build` / `enforcement` | golden tests `assertReplayBindingComplete` |
| End-to-end golden scenarios | `service.Evaluate` | `TestGolden1/2/3/3b` |
| Tool drift / trust state | `tool.DetectDrift` / `ResolveTrust` | `TestDetectDriftAndTrust` |
| Approval invalidation (§15.4) | `approval.Validate` | `TestSchemaDriftInvalidatesApproval` |
| Confirmation lifecycle | `service.EvaluateToolAction` | `TestTool_ConfirmationLifecycle` |
| TOCTOU re-validation (P1-4) | `service.resolveApproval` | `TestTool_TOCTOURevalidation` |
