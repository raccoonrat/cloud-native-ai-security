# controlplane — Enterprise AI Runtime Security Control Plane (Sprint 1–6)

Reference implementation of the Enterprise AI Runtime Security Control Plane,
per spec `[10]Cloud Native Enterprise AI Security Control Plane -v1.6.md`
(§23 Sprint 1–5 + Sprint 6: async judge path §6 and gate-guarded bundle activation).

This module is a **compilable, testable end-to-end vertical slice**: the
contracts, deterministic fusion, deterministic policy resolution, the
`POST /v1/decisions:evaluate` runtime decision API (INV-7 provenance check,
first-write-wins idempotency, signed Decision Contract), evidence commit +
completeness scoring, a mock Enforcement Adapter, the **Tool / MCP
pre-execution security slice** (metadata snapshots, drift detection, trust
state, confirmation binding + TOCTOU re-validation), **decision-level Replay**
(`POST /v1/replay:decision`), an **Evaluation Harness** producing per-stage
/ per-risk-family metric cards, and the **Release Gate** (INV-6) with policy
diff, dry-run, replay regression, and a gate decision
(`POST /v1/release-gates:evaluate`). It has **zero external dependencies** (Go
stdlib only).

See [CHANGELOG.md](CHANGELOG.md) for security-hardening fixes applied after the
initial Sprint 1–6 slice (2026-06-25 review: P0 / P1 / P2).

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
│   ├── diff.go                    policy diff + blast radius + diff risk (§16.5/§18)
│   └── resolve_test.go
├── gate/                          Release Gate (INV-6, v1.5 §16.5/§18)
│   └── gate.go                    diff + dry-run + replay regression -> gate decision
├── tool/                          Tool/MCP pre-execution security (v1.5 §15, INV-5)
│   ├── tool.go                    ActionContext, snapshot, drift, trust, fingerprint
│   └── tool_test.go
├── approval/                      Approval Binding Service (v1.5 §15.3/§15.4)
│   ├── approval.go                bind + TOCTOU re-validation (§15.4 rules)
│   └── approval_test.go
├── decision/                      Decision Contract (INV-3, v1.6 §11)
│   └── contract.go                build + hash + sign + validate + approval binding
├── evidence/                      evidence commit + completeness scoring (v1.6 §13)
│   ├── evidence.go                minimal synchronous commit (§13.3)
│   └── package.go                 full Package + §13.5 completeness + enrichment
├── replay/                        decision-level Replay-lite (v1.6 §14)
│   └── replay.go                  re-run fuse+policy, consistency verdict + diff
├── eval/                          Evaluation Harness (v1.6 §17)
│   └── eval.go                    Case/Report/Run + per-stage/per-family cards
├── enforcement/                   mock Enforcement Adapter (v1.5 §12)
├── sign/                          decision integrity signing (HMAC + Ed25519, v1.6 §5.4)
├── idutil/                        prefixed random + deterministic id generation
├── service/                       runtime decision MVP
│   ├── service.go                 Evaluate(); AugmentJudge(); ReplayDecision(); EvaluateReleaseGate(); ActivateBundle()
│   ├── registry.go                Detector Registry (INV-7)
│   ├── http.go                    POST /v1/decisions:evaluate, :augment, /v1/replay:decision, /v1/release-gates:evaluate
│   ├── defaults.go                fully-wired default Service
│   ├── golden_test.go            3 golden scenarios end to end
│   ├── replay_test.go            golden-replay reproduction + completeness
│   ├── gate_test.go              release gate blocks breaking policy update
│   ├── judge_test.go             provisional -> revised async judge flow (§6.2)
│   ├── activation_test.go        gate-guarded blue/green bundle activation
│   ├── p0_regression_test.go     security review P0 regressions
│   ├── p1_regression_test.go     security review P1 regressions
│   └── p2_regression_test.go     security review P2 regressions
└── cmd/controlplane/main.go       HTTP server
```

## Run the server

```bash
cd controlplane
go run ./cmd/controlplane          # listens on :8080 (CONTROL_PLANE_ADDR to change)

curl -s -X POST localhost:8080/v1/decisions:evaluate \
  -H 'Content-Type: application/json' -d @example_request.json
```

> **Tool pre-execution:** `POST /v1/decisions:evaluate` rejects
> `stage=tool_pre_execution` with `422 tool_path_required`. Tool/MCP decisions
> must go through the in-process `service.EvaluateToolAction` API (drift,
> trust, TOCTOU approval re-validation). An HTTP route for the tool path is
> planned for a later sprint.

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
go test -race ./...   # recommended after concurrent / activation changes
```

## Security hardening (2026-06-25)

Post–Sprint-6 fixes from a full architecture / security review. Details in
[CHANGELOG.md](CHANGELOG.md).

| Area | Fix |
| ---- | --- |
| **Decision integrity** | Hash/signature now cover constraints, approval binding, decision mode, and revision lineage (`hash_version=dch_v2`); enforcement re-derives the hash (`VerifyIntegrity`) so tampered fields are rejected |
| **Fail-closed** | Output-stage no-match → `block` (not invalid `deny`) |
| **Tool bypass** | Generic evaluate route rejects tool stage / `tool_action` |
| **Signal TTL** | Live fusion pins eval time; replay snapshots carry `eval_time` |
| **Concurrency** | `activeBundle()` / `bundleForVersion()` — no bundle read races |
| **MODE-B** | `CanonicalSignalHash` binds signature to signal payload |
| **Replay** | Replays use pinned `bundle_version`, not active bundle |
| **Determinism** | `idutil.Derive` for synthetic/tool signal IDs → stable decision hash |
| **Release gate** | Drift vs correctness split; `MaxFalseNegativeRate`; optional `LabeledCorpus` |
| **Evidence** | Commit only after idempotency win; replay reports real commit status |
| **Policy** | `drifted_tool_policy`; review-queue tie keeps highest priority |
| **Signing** | Optional `Ed25519Signer` / `Ed25519Verifier` (default remains HMAC) |

## What is implemented

### Sprint 1 — Contract Foundation
- **Stage × Action Matrix** single source of truth (`matrix.Validate`) backing
  lint (PL-002), decision-output validation, and enforcement-input validation.
- **Deterministic Fusion** (`fusion.Fuse`): canonical normalization, monotonic
  lattice merge (order-independent), FR-008..FR-006, `deterministic_v1`
  aggregation. Proven order-independent (`TestTV6_OrderIndependence`).
- **Deterministic Policy Resolution** (`policy.Resolve`): action strength order +
  constraint union, "combine" semantics, terminal-stop suppression,
  redaction-tie escalation, **stage-aware** fail-closed defaults (`output` →
  `block`, other stages → `deny`).
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
- **Decision Contract** built, hashed, and signed (`decision.Build` — default
  HMAC; optional Ed25519 via `sign.Ed25519Signer`); §11.2 correctness validated
  (`decision.Validate`).
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

### Sprint 4 — Evidence / Replay / Evaluation
- **Full Evidence Package + completeness scoring** (`evidence.BuildFromContract`,
  `Package.Completeness`, §13.5): stage-specific required-field tables; the
  synchronous Decision Contract now carries `evidence.evidence_completeness`, and
  asynchronous **enrichment** (`evidence.Enrichment`) completes the package
  (content spans, enforcement result) post-decision (§13.4).
- **Decision-level Replay-lite** (`replay.Run`, `service.ReplayDecision`,
  `POST /v1/replay:decision`, §14): re-runs fusion + policy from the pinned
  context/signal snapshot (**`eval_time`**, **`bundle_version`**) and returns a
  `match` / `partial` / `mismatch` verdict with a diff. Replaying with the same
  pinned versions reproduces the original action for every golden scenario
  (deterministic by §3/§4).
- **Evaluation Harness** (`eval.Run` → `eval.Report`, §17): scores **control**
  effectiveness — `action_correctness`, `reason_correctness`,
  `evidence_completeness`, `replay_consistency`, false-positive / false-negative
  rates, p95 latency — broken down **per stage** and **per risk family**, with a
  per-case metric `Card` and a `Report.Render()` summary.

### Sprint 5 — Release Gate (INV-6)
- **Policy diff + blast radius** (`policy.Diff`, §16.5/§18): added / removed /
  modified policies, affected stages / actions / apps, and a `policy_diff_risk`
  classification — **critical** when an active control is removed or weakened,
  **high** on other action changes, **medium** on additions / constraint edits,
  **low** for metadata-only diffs.
- **Release Gate** (`gate.Evaluate`, `service.EvaluateReleaseGate`,
  `POST /v1/release-gates:evaluate`): runs the candidate bundle as a **dry-run**
  over a labeled / historical corpus and a **replay regression** vs the current
  bundle, computes the §17.2 metric set, and renders a `GateEvaluationRecord`
  binding the target + artifacts (offline-eval / replay-regression / policy-diff
  / latency report refs). INV-6: every release-gated change produces one record.
- **Deterministic gate decision** (`gate.Decide`, §18.2):
  `block` (contained floor failure) → `rollback_required` (floor failure +
  severe behavior drift) → `shadow_only` (critical diff risk) → `canary_only`
  (high diff risk / elevated drift) → `pass_with_warning` → `pass`.

### Sprint 6 — Async Judge Path + Gate-Guarded Activation
- **Synchronous path never blocks on a judge** (§6.1): with `options.pending_judge`
  set and no judge (`source_type=judge`) signal present, the decision is computed
  immediately and marked `stability = provisional_pending_async`.
- **Async judge augmentation + `decision_revision`** (`service.AugmentJudge`,
  `POST /v1/decisions:augment`, §6.2): a late judge signal (re-checked through
  INV-7 provenance) re-runs the deterministic core over the pinned snapshot and
  emits a **revised decision** (`decision_revision += 1`,
  `supersedes_decision_id` = original, `stability = final`).
  `service.LatestDecision(trace, stage)` returns the latest non-superseded
  decision — enforcement MUST act on it, never on a stale provisional one.
- **Gate-guarded blue/green bundle activation** (`service.ActivateBundle` /
  `RollbackBundle`, decision #9): bundles are immutable; activation is a
  version-pointer switch permitted only when the `GateEvaluationRecord` allows it
  for the target environment (`pass`/`pass_with_warning` anywhere, `canary_only`
  in canary/shadow, `shadow_only`/`block`/`rollback_required` never promote to
  prod). The previous bundle is retained for rollback.

### Golden / tool scenario results
| Scenario | Stage | Decision |
| -------- | ----- | -------- |
| 1 Enterprise data leakage | output | `redact` |
| 2 Prompt injection retrieval | retrieval | `restrict_scope` |
| 3 Tool pre-execution (no approval) | tool_pre_execution | `require_confirmation` (tool not executed) |
| 3 + valid approval | tool_pre_execution | `allow` |
| 3 + schema drift after approval | tool_pre_execution | `require_confirmation` (approval invalidated) |
| 3 + tampered target (TOCTOU) | tool_pre_execution | not `allow` |
| Drifted tool (metadata changed) | tool_pre_execution | `require_confirmation` |
| Revoked tool | tool_pre_execution | `deny` |
| Unknown elevated tool | tool_pre_execution | `deny` |
| Unknown read tool | tool_pre_execution | `require_review` |

## Not yet implemented (later sprints)

- Edge security: mTLS, workload identity, rate limiting, anti-replay (§5.1/§5.2)
  — belongs to the serving edge, intentionally out of the handler.
- Evidence encryption + tenant isolation / durable evidence store (current store
  is in-memory; completeness scoring + enrichment are implemented).
- Durable persistence for decisions / replay+gate corpora / effective-decision
  and bundle-history maps (bundle versions are retained in-memory per activation;
  durable store still pending).
- HTTP route for `EvaluateToolAction` (in-process API only; generic
  `/v1/decisions:evaluate` **rejects** `tool_pre_execution` — see Run the server).
- JSON Schema runtime validation wiring (schemas embedded; validator pending).
- Default deployment wiring for Ed25519 signing (implementation available in
  `sign`; `NewDefault` still uses HMAC for the MVP).

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
| Evidence completeness scoring (§13.5) | `evidence.Package.Completeness` | `TestCompleteness_*` |
| Decision replay reproduction (§14) | `replay.Run` / `service.ReplayDecision` | `TestReplay_GoldenScenariosReproduce`, `TestReplay_*` |
| Evaluation metric cards (§17) | `eval.Run` | `TestHarness_Report` |
| Policy diff risk classification (§16.5/§18) | `policy.Diff` | `TestDiff_*` |
| Gate blocks breaking policy update (INV-6) | `gate.Decide` / `service.EvaluateReleaseGate` | `TestGate_BlockOnRegression`, `TestReleaseGate_BlocksBreakingPolicyUpdate` |
| Canary-only / rollback-required outcomes (§18.2) | `gate.Decide` | `TestGate_CanaryOnlyOnDrift`, `TestGate_RollbackRequiredOnSevereRegression` |
| Sync path never blocks on judge; provisional→revised (§6) | `service.AugmentJudge` | `TestJudge_ProvisionalThenRevised`, `TestJudge_PresentSignalIsFinal` |
| Gate-guarded blue/green activation + rollback (decision #9) | `service.ActivateBundle` / `RollbackBundle` | `TestActivation_*` |
| Output fail-closed is `block` (not invalid `deny`) | `policy.defaultDecision` | `TestDefaultDecisionFailClosed`, `TestP0_OutputFailClosedIsBlockNotError` |
| Tool stage rejected on generic HTTP path | `service/http.go` | `TestP0_ToolStageRejectedOnGenericPath` |
| Signal TTL enforced + replayable | `fusion.Config.Now` / `replay.Inputs.EvalTime` | `TestP0_ExpiredSignalDroppedAndReplayable` |
| Bundle read race-free under activation | `service.activeBundle` | `TestP0_ConcurrentEvaluateAndActivateNoRace` |
| MODE-B signature binds payload | `model.CanonicalSignalHash` | `TestP1_ModeBSignatureBindsPayload` |
| Replay uses pinned bundle version | `service.bundleForVersion` | `TestP1_ReplayUsesPinnedBundleVersion` |
| Deterministic decision hash | `idutil.Derive` | `TestP1_DeterministicDecisionHash` |
| Gate does not penalize strengthening | `gate.Evaluate` / `LabeledCorpus` | `TestP1_GateDoesNotPenalizeStrengthening` |
| Idempotent replay evidence status | `service.evidenceStatus` | `TestP2_IdempotentReplayReportsRealStatus` |
| Drifted tool requires confirmation | `drifted_tool_policy` | `TestP2_DriftedToolRequiresConfirmation` |
| Ed25519 verify-only enforcement boundary | `sign.Ed25519Verifier` | `TestEd25519SignVerify` |
