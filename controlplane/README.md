# controlplane — Enterprise AI Runtime Security Control Plane (Sprint 1 skeleton)

Reference implementation of the **contract foundation** for the Enterprise AI
Runtime Security Control Plane, per spec
`[10]Cloud Native Enterprise AI Security Control Plane -v1.6.md` (Sprint 1, §23).

This module is the **compilable, testable vertical-slice skeleton**: the
contracts, the deterministic fusion engine, and the deterministic policy
conflict resolver — the pieces that make `replay_consistency` achievable by
construction. It has **zero external dependencies** (Go stdlib only).

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
└── policy/                        deterministic conflict resolution (v1.6 §4)
    ├── resolve.go                 action strength order + constraint union
    └── resolve_test.go            v1.5 §10.4 pairwise + multi-policy union
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

## What is implemented (Sprint 1 DoD)

- **Stage × Action Matrix** as a single source of truth backing lint (PL-002),
  decision-output validation, and enforcement-input validation (`matrix.Validate`).
- **Deterministic Fusion** (`fusion.Fuse`): canonical normalization (total order
  via `signal_id` tiebreak), monotonic lattice merge (order-independent),
  fixed-precedence rules FR-008..FR-006, and the `deterministic_v1` confidence
  aggregation. Proven order-independent by `TestTV6_OrderIndependence`.
- **Deterministic Policy Resolution** (`policy.Resolve`): action strength total
  order for primary selection + most-restrictive constraint union, including the
  "combine" semantics for `require_confirmation` + `step_up_auth`, terminal-stop
  suppression, redaction-profile-tie escalation, and environment fail behavior.
- **JSON Schemas** for Context / Signal / Decision (incl. INV-7 provenance and
  the §6.2 `decision_revision` fields).

## Not yet implemented (later sprints)

- `POST /v1/decisions:evaluate` HTTP surface + idempotency store (Sprint 2).
- Signal Adapter / Context Normalizer / Enforcement Adapter (Sprint 2-3).
- Evidence Package, Replay-lite, Evaluation Harness, Release Gate (Sprint 4-5).
- JSON Schema runtime validation wiring (the schemas are embedded; a validator
  can be added without external deps or via a vetted library when network allows).

## Design guarantees

| Property | Where | Test |
| -------- | ----- | ---- |
| Fusion determinism / replayability | `fusion.Fuse` | TV-1..TV-6 |
| Order-independence | monotonic merge + canonical sort | `TestTV6_OrderIndependence`, `TestResolveOrderIndependence` |
| Single-source stage/action validation | `matrix` | `TestStageActionRules` |
| Policy conflict determinism | action strength order | `TestPairwiseConflicts`, `TestMultiPolicyConstraintUnion` |
| Fail-closed defaults | `policy.defaultDecision` | `TestDefaultDecisionFailClosed` |
