# Changelog

All notable changes to the `controlplane` module are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security — P0 (critical)

#### Fixed
- **Output-stage fail-closed** (`policy.defaultDecision`): prod high-risk no-match now
  returns `block` at `output` and `deny` at other stages, matching the Stage × Action
  Matrix. Previously an invalid `deny` at `output` failed `decision.Validate` and
  broke fail-closed instead of stopping the request.
- **Tool path endpoint confusion** (`service.Evaluate`, `service/http.go`): the generic
  `POST /v1/decisions:evaluate` route rejects `stage=tool_pre_execution` and any
  `tool_action` payload with `422 tool_path_required`. Tool decisions must use
  `EvaluateToolAction` so drift detection, trust resolution, and TOCTOU approval
  re-validation cannot be skipped.
- **Signal TTL expiry on the live path** (`service.decide`, `replay.Inputs.EvalTime`):
  fusion now pins `cfg.Now` to the request evaluation instant; replay snapshots carry
  `eval_time` so TTL drops are deterministic and actually enforced (previously
  `Now == zero` disabled expiry).
- **`s.bundle` data race** (`service.activeBundle`): all decision/replay reads of the
  active policy bundle go through a lock-protected snapshot; safe under concurrent
  `ActivateBundle` / `RollbackBundle`.

### Security — P1 (high)

#### Added
- **`model.CanonicalSignalHash`**: canonical content hash for MODE-B signal integrity.
- **`idutil.Derive`**: deterministic prefixed IDs for control-plane-synthesized signals.
- **`service.bundles` + `bundleForVersion`**: version-indexed immutable bundle store for
  replay against the bundle a decision was made under.
- **`ReleaseGateRequest.LabeledCorpus`**: optional independently-labeled offline corpus
  for gate correctness scoring.
- **`gate.Thresholds.MaxFalseNegativeRate`**: control-loss ceiling in release gate
  decisions.

#### Changed
- **MODE-B provenance** (`service.verifyProvenance`): verifies
  `SignedPayloadHash == CanonicalSignalHash(sig)` before signature check so a valid
  `(hash, signature)` pair cannot be replayed onto a tampered signal.
- **`policy.Resolve`**: takes `stage` for stage-aware fail-closed defaults.
- **Replay** (`replay.Inputs`, `service.ReplayDecision`, `service.AugmentJudge`): replays
  against the snapshot's pinned `bundle_version`, not the currently active bundle.
- **Synthetic / tool signal IDs** (`service.systemSignalTyped`, `tool.toolSignal`): use
  `idutil.Derive` instead of random IDs so identical logical inputs yield identical
  Decision Contract hashes.
- **Release gate metrics** (`gate.Evaluate`, `service.EvaluateReleaseGate`):
  - `action_correctness` scored only against samples with independent `ExpectedAction`
    labels (unlabeled historical snapshots drive drift/FN only).
  - Historical runtime snapshots no longer use incumbent output as correctness ground
    truth (strengthening/correcting policies is not penalized).
  - `Decide` enforces `MaxFalseNegativeRate` (candidate dropping an active control).

### Security — P2 (robustness)

#### Added
- **`sign.Ed25519Signer` / `sign.Ed25519Verifier`**: asymmetric decision signing for
  canary/prod trust boundaries (enforcement holds public key only; cannot forge).
- **`drifted_tool_policy`** in `policy.DefaultBundle()`: `trust_state == drifted` →
  `require_confirmation` in all environments (including shadow/canary).
- **`service.evidenceStatus`**, **`service.updateStored`**: accurate idempotent evidence
  reporting and post-commit store updates.

#### Fixed
- **Idempotent replay evidence status** (`service.decide`): replays report the stored
  decision's real `committed` / `pending` status instead of always `committed`.
- **Orphan evidence on idempotency races** (`service.decide`): evidence is committed only
  after `storeIfAbsent` wins the idempotency slot.
- **Review queue tie** (`policy.mergeConstraints`): equal-severity queues no longer
  clobber the higher-priority policy's queue (strict `>` override only).

### Tests

#### Added
- `service/p0_regression_test.go` — P0 regression (fail-closed block, tool path reject,
  TTL expiry + replay, concurrent bundle activation).
- `service/p1_regression_test.go` — P1 regression (MODE-B payload binding, pinned-bundle
  replay, deterministic decision hash, gate strengthening).
- `service/p2_regression_test.go` — P2 regression (idempotent evidence status, drifted
  tool confirmation).
- `policy/resolve_test.go` — `TestReviewQueueTieKeepsHighestPriority`.
- `sign/sign_test.go` — `TestEd25519SignVerify`.

#### Changed
- `policy/resolve_test.go` — `TestDefaultDecisionFailClosed` covers per-stage terminal
  actions (`output` → `block`, others → `deny`).

## [Sprint 1–6] — 2026-06-24

Initial vertical slice per spec v1.6 (§23 Sprint 1–6):

- Stage × Action Matrix, deterministic fusion, policy resolution, Decision Contract.
- Runtime decision API, INV-7 provenance, idempotency, HMAC signing, evidence commit.
- Tool/MCP pre-execution security, approval binding, TOCTOU re-validation.
- Decision-level replay, evaluation harness, release gate (INV-6).
- Async judge path (§6.2), gate-guarded blue/green bundle activation.

See [README.md](README.md) for the full feature list and golden scenario table.
