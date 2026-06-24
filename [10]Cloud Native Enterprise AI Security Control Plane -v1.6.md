# Enterprise AI Runtime Security Control Plane Spec v1.6

## 0. Document Header

**Title:** Enterprise AI Runtime Security Control Plane Spec
**Subtitle:** 面向 LLM / RAG / Tool / MCP / Agent 的企业级运行时授权与信任控制平面
**Version:** v1.6
**Document Type:** Implementable Engineering Spec / Runtime Protocol / Normative Baseline
**Audience:** AI Security Architects, Runtime Security Engineers, Platform Engineers, xCloud / Enterprise AI Integration Developers, Policy Engineers, Evaluation Engineers
**Status:** Implementation-Ready Engineering Spec
**Primary Positioning:** Enterprise AI Runtime Authorization & Trust Control Plane
**Design Philosophy:** Control Plane First / Contract First / Policy-Driven / Evidence-First / Replayable-by-Design / Gate-Enforced / **Deterministic-by-Construction**
**Source Baseline:** Revised from v1.5. v1.6 closes the P0 implementation blockers identified in the v1.5 architect review.
**Reference Implementation Language:** Go (control plane services); contracts are language-neutral JSON Schema / YAML.

***

## 0.1 What v1.6 Adds (Delta over v1.5)

v1.5 is a correct contract-first architecture but is not yet directly implementable: several mechanisms declared as "deterministic / executable / enforceable" lacked an actual algorithm or a normative artifact. v1.6 does not change v1.5's thesis, invariants INV-1..INV-6, plane separation, MVP scope, stage semantics, or schemas. It **adds the missing normative machinery** so a top-tier team can start Sprint 1 without blocking:

| ID | v1.6 Addition | Closes |
| -- | ------------- | ------ |
| ADD-1 | **INV-7 Signal Provenance Integrity** — signals must have a verifiable trust root. | v1.5 §26 Open Q#3 (signal trust gap) |
| ADD-2 | **Stage × Action Matrix** as a single machine-readable source of truth (table + YAML + lint binding). | v1.5's 7 dangling references to a never-defined matrix |
| ADD-3 | **Deterministic Fusion Algorithm** — normalization order, monotonic lattice merge, fixed rule precedence, aggregation function, golden test vectors. | v1.5 §9 "deterministic" with no algorithm |
| ADD-4 | **Policy Conflict Resolution Algorithm** — action strength lattice + constraint-union merge for N matched policies. | v1.5 §10.4 pairwise-only table |
| ADD-5 | **Control Plane API Security & Idempotency Semantics** — mTLS, caller identity, replay protection, and the stateless/idempotency reconciliation. | v1.5 §16 (no security), §4.2 vs §16.1 contradiction |
| ADD-6 | **Synchronous vs Asynchronous Judge Path + `decision_revision`** — bounded latency under LLM-judge signals. | v1.5 §1854 "non-judge path" with no architecture |

All v1.6 normative statements use **MUST / MUST NOT / SHOULD**. Where v1.6 strengthens a v1.5 "should" into a "must", it is marked **[HARDENED]**.

***

## 1. New Invariant — INV-7: Signal Provenance Integrity

> **The control plane MUST NOT trust an unverifiable signal.**

v1.5 §16.1 makes `signals: []` an **input** to `POST /v1/decisions:evaluate`, i.e. the data plane runs detectors and submits signals. Without a trust root this breaks the entire chain: a compromised or buggy data plane could forge a `severity: low` signal and bypass all controls. INV-1 ("detector never enforces") is necessary but not sufficient; INV-7 makes the signal channel itself trustworthy.

### 1.1 Compliance Modes

A deployment MUST declare one of two provenance modes per integration point:

```text
MODE-A  Control-plane-invoked detectors (RECOMMENDED for MVP)
        Signal Adapters run inside the Control Plane trust boundary.
        The data plane submits only raw artifacts (input/output/tool_action),
        never signals. Provenance is guaranteed by colocation.

MODE-B  Data-plane-submitted signed signals
        The data plane may submit signals, but every signal MUST be signed
        and its source MUST be registered in the Detector Registry.
```

### 1.2 Signal Validity — Provenance Extension to v1.5 §8.3

In addition to v1.5 §8.3, a signal is **provenance-valid** only if:

```text
1. signal.source.source_id   is registered in Detector Registry (status=active)
2. signal.source.source_version resolves to a registered version
3. MODE-B only: signal.integrity.signature verifies against the
   registered public key for source_id
4. signal is not expired:  now <= created_at + ttl_ms
```

### 1.3 Provenance Failure Handling (normative)

| Condition | Behavior |
| --------- | -------- |
| source_id not in registry | drop signal; emit `system` signal `signal_type=registry_miss` (severity=medium) into fusion |
| source_version unknown | drop signal; emit `registry_miss` |
| MODE-B signature invalid | **drop signal; emit `system` signal `signal_type=signal_integrity_violation` (severity=high)**; in prod this MUST raise an alert |
| signal expired (ttl) | drop signal silently; record in evidence `dropped_signals[]` |

Dropped signals MUST be recorded in the Evidence Package (`dropped_signals[]`) so that "absence of a signal" is itself auditable. A fused decision computed after dropping a high/critical signal due to integrity failure MUST NOT be `allow` in prod for privileged/external_send/write objects; it MUST escalate to `require_review` or `deny` per fallback.

### 1.4 Decision Contract & Signal Schema additions

Add to v1.5 Signal Schema (§8.2):

```json
"integrity": {
  "signature": "optional (required in MODE-B)",
  "key_id": "optional",
  "signed_payload_hash": "sha256:..."
}
```

Add to v1.5 Decision Contract (§11.1), inside `replay_binding`:

```json
"provenance_mode": "MODE_A | MODE_B",
"dropped_signals": [
  { "source_id": "string", "reason": "registry_miss | signature_invalid | expired" }
]
```

***

## 2. Stage × Action Matrix (Normative, Machine-Readable)

This is the single source of truth referenced (but never defined) across v1.5 (§3 INV-6, §5.2, §6.x, §10.5 PL-002, §23 Sprint 1, §18.1 gate target). The **same artifact** MUST back:
- `PL-002` policy lint (action valid for stage),
- Decision Service output validation,
- Enforcement Adapter input validation.

### 2.1 Matrix (human-readable)

Legend: `Y` allowed · `—` disallowed. Disallowed actions in a stage MUST be rejected by lint, decision validation, and enforcement validation alike.

| Action | input | retrieval | tool_pre_execution | output |
| ------ | :---: | :-------: | :----------------: | :----: |
| allow | Y | Y | Y | Y |
| audit_only | Y | Y | Y | Y |
| require_review | Y | Y | Y | Y |
| deny | Y | Y | Y | — |
| block | — | — | — | Y |
| sanitize | Y | — | — | — |
| mask | Y | — | — | Y |
| redact | — | — | — | Y |
| restrict_scope | — | Y | — | — |
| annotate_risk | — | Y | — | — |
| require_confirmation | — | — | Y | — |
| step_up_auth | — | — | Y | — |

Notes derived from v1.5 §6:
- `input` has no retrieval scope or tool action yet → `redact / restrict_scope / require_confirmation / step_up_auth / block` are disallowed (v1.5 §6.1 Disallowed). `sanitize/mask` operate on the raw user input.
- `deny` is the hard stop for input/retrieval/tool; `block` is the hard stop reserved for `output` (post-generation). They MUST NOT both be valid in the same stage.
- `output` cannot `deny` an already-produced artifact; it `block`s or `redact`s it.

### 2.2 Action Requirements (what each action MUST carry)

| Action | Required constraint(s) | Evidence required | Enforcement side-effect |
| ------ | ---------------------- | :---------------: | ----------------------- |
| allow | — | minimal | none |
| audit_only | audit_required=true | minimal | none (record only) |
| annotate_risk | risk_annotation | minimal | tag artifact untrusted |
| require_review | review_queue | full | route to review |
| require_confirmation | **approval_binding** | full | block tool until confirmed |
| step_up_auth | target_auth_strength | full | request re-auth |
| restrict_scope | scope_restriction | full | drop/down-scope items |
| sanitize | sanitize_profile | full | transform input |
| mask | mask_profile | full | mask spans |
| redact | redaction_profile | full | redact spans |
| deny | reason_code | full | stop |
| block | reason_code | full | stop delivery |

### 2.3 Machine-readable artifact (`stage_action_matrix.yaml`)

```yaml
schema_version: "1.6"
matrix_version: "stage_action_matrix_v1"
stages: [input, retrieval, tool_pre_execution, output]
actions:
  - action: allow
    allowed_in: [input, retrieval, tool_pre_execution, output]
    requires: []
    evidence: minimal
  - action: audit_only
    allowed_in: [input, retrieval, tool_pre_execution, output]
    requires: [audit_required]
    evidence: minimal
  - action: require_review
    allowed_in: [input, retrieval, tool_pre_execution, output]
    requires: [review_queue]
    evidence: full
  - action: deny
    allowed_in: [input, retrieval, tool_pre_execution]
    requires: [reason_code]
    evidence: full
  - action: block
    allowed_in: [output]
    requires: [reason_code]
    evidence: full
  - action: sanitize
    allowed_in: [input]
    requires: [sanitize_profile]
    evidence: full
  - action: mask
    allowed_in: [input, output]
    requires: [mask_profile]
    evidence: full
  - action: redact
    allowed_in: [output]
    requires: [redaction_profile]
    evidence: full
  - action: restrict_scope
    allowed_in: [retrieval]
    requires: [scope_restriction]
    evidence: full
  - action: annotate_risk
    allowed_in: [retrieval]
    requires: [risk_annotation]
    evidence: minimal
  - action: require_confirmation
    allowed_in: [tool_pre_execution]
    requires: [approval_binding]
    evidence: full
  - action: step_up_auth
    allowed_in: [tool_pre_execution]
    requires: [target_auth_strength]
    evidence: full
```

### 2.4 Gate binding

The matrix is a release-gated object (v1.5 §18.1 `stage_action_matrix_update`). Any change MUST produce a `GateEvaluationRecord`. `matrix_version` MUST be pinned in `Decision.replay_binding` so replays evaluate against the same matrix.

***

## 3. Deterministic Fusion Algorithm

v1.5 §9 requires fusion to be "deterministic, replayable, gateable" but gives only 8 independent rules (FR-001..FR-008) with no precedence, no multi-rule resolution, and an undefined `aggregation: deterministic_v1`. v1.6 specifies the algorithm so that **replay_consistency ≥ 0.99 (v1.5 §10.2 gate) is achievable by construction**.

### 3.1 Fusion is a pure function

```text
fuse : (signals[], context, fusion_config) -> FusedRisk
```

It MUST be a pure, side-effect-free function (consistent with INV-2). Determinism is guaranteed by three properties: **input normalization**, **monotonic lattice merge**, and **fixed rule order**. With monotonic merge, the result is invariant to rule evaluation order; the fixed order is specified anyway for human reproducibility.

### 3.2 Severity & uncertainty lattices

```text
severity:    none(0) < low(1) < medium(2) < high(3) < critical(4)
uncertainty: low(0)  < medium(1) < high(2)
```

Merge operator `⊔` = lattice join (max). Severity and uncertainty only ever **escalate** during fusion; flags are a set that only ever **grows**. This monotonicity is what makes rule order irrelevant to the result.

### 3.3 Canonical normalization (Step 1)

```text
normalize(signals):
  V = [ s for s in signals if provenance_valid(s) and stage_matches(s) ]   # INV-7 + §8.3
  D = dedup(V) keeping first by signal_id                                  # stable
  S = sort(D, key = canonical_key)
  return S

canonical_key(s) = (
   -severity_rank(s.severity),   # critical first
    risk_family_order(s.risk_family),   # SEC<SAF<PRIV<REL<COMP (fixed)
    source_type_rank(s.source.source_type),
    s.signal_id                  # final total-order tiebreak (uuid string asc)
)
```

The final `signal_id` tiebreak guarantees a **total order**, so even non-deterministic detector emission order produces identical fusion input.

### 3.4 Fusion rule table with precedence (Step 2)

Rules from v1.5 §9.3 (FR-001..FR-008), now with explicit `precedence` (lower = evaluated first; ties broken by FR id). Each rule's `effect` is a monotonic update.

| Prec | Rule | Condition | Effect (monotonic) |
| :--: | ---- | --------- | ------------------ |
| 10 | FR-008 | any signal with tool trust_state=revoked | severity ⊔= critical; flags += {tool_revoked}; reason += revoked tool |
| 20 | FR-001 | any critical signal | severity ⊔= critical; reason += cite signal_id |
| 30 | FR-002 | high signal ∧ destination.boundary ∈ {external, cross_tenant} | severity ⊔= critical; reason += cite boundary+signal |
| 40 | FR-003 | tool_schema_drift ∧ prior approval exists | flags += {approval_invalidated}; reason += schema hash diff |
| 50 | FR-007 | registry_miss ∧ tool.permission_class ∈ {write, external_send, privileged} | severity ⊔= high; flags += {needs_review}; reason += registry miss |
| 60 | FR-004 | ≥2 high-confidence signals with conflicting risk_family/severity | flags += {needs_review}; uncertainty ⊔= medium; reason += conflict pair |
| 70 | FR-005 | any signal severity≥high ∧ confidence < low_conf_threshold | flags += {needs_review}; uncertainty ⊔= high; reason += uncertainty |
| 80 | FR-006 | ≥2 medium signals in same trace | severity ⊔= high; reason += cite signal cluster |

`low_conf_threshold` is a value in `threshold_config` (versioned, gate-bound). Default `0.60`.

### 3.5 Aggregation function `deterministic_v1` (Step 3)

```text
confidence_summary:
  min = min(confidence over S)                      # empty -> null
  max = max(confidence over S)
  representative =
     confidence of the FIRST signal in S whose severity == final highest_severity
     (S is already canonically sorted, so "first" is deterministic)
  aggregation = "deterministic_v1"
```

> Aggregation MUST NOT use any non-deterministic reduction (no floating-point summation across an unordered set, no average without fixed order). Summation, if ever added, MUST be over the canonically sorted `S`.

### 3.6 Output mapping

`FusedRisk` (v1.5 §9.2) is populated as: `highest_severity` = final severity; `risk_families` = sorted unique families; `risk_reasons` = reasons in rule-precedence order then signal-canonical order; `conflicts[]` from FR-004; `uncertainty` = final uncertainty; `recommended_policy_path` = config lookup keyed by `(highest_severity, families, flags)`. Fusion MUST NOT emit an action (INV-2): `flags` like `needs_review` / `approval_invalidated` are **facts for Policy**, not decisions.

### 3.7 Golden test vectors (Sprint-1 acceptance)

```text
TV-1  in:  [ {PRIV, high, conf .91, dest=external} ]
      out: highest_severity=critical (FR-002), uncertainty=low, flags={}
TV-2  in:  [ {SEC, critical, conf .80}, {PRIV, low, conf .95} ]
      out: highest_severity=critical (FR-001), representative_conf=.80
TV-3  in:  [ {SEC, high, conf .55} ]              # below low_conf_threshold .60
      out: highest_severity=high, flags={needs_review}, uncertainty=high (FR-005)
TV-4  in:  [ {tool revoked, SEC, medium} ]
      out: highest_severity=critical (FR-008), flags={tool_revoked}
TV-5  in:  [ {SEC, medium}, {PRIV, medium} ]      # 2 mediums
      out: highest_severity=high (FR-006)
TV-6  in:  same as TV-1 but reversed input order
      out: byte-identical to TV-1   # proves order-independence
```

***

## 4. Policy Conflict Resolution Algorithm

v1.5 §10.4 gives only pairwise conflicts and an undefined "combine". Real evaluation matches **N policies** producing N actions + N constraint sets. v1.6 defines a total algorithm.

### 4.1 Action strength order (primary-action selection)

A single total order over the 12 actions; **strongest wins** as the primary action:

```text
deny (120)
> block (110)
> require_review (100)
> step_up_auth (90)
> require_confirmation (80)
> restrict_scope (70)
> redact (60)
> sanitize (50)
> mask (40)
> annotate_risk (30)
> audit_only (20)
> allow (10)
```

This subsumes every v1.5 §10.4 pairwise rule:
`allow vs deny → deny` ✔ · `allow vs redact → redact` ✔ · `redact vs block → block` ✔ · `require_confirmation vs deny → deny` ✔ · `audit_only vs any active → active` ✔.

### 4.2 Constraint merge (the real meaning of "combine")

Primary action selection alone loses information (`require_confirmation vs step_up_auth → combine`, v1.5 §10.4). So after selecting the primary action, v1.6 **unions compatible constraints** from all matched policies:

```text
resolve(matched_policies, context, fused_risk):
  if matched_policies is empty:
      return default_decision(context.environment)        # fail per §20.2

  P = sort(matched_policies, by priority desc, then policy_id asc)

  primary = argmax_strength(p.decision.action for p in P)

  # 4.2.1 same-priority irreconcilable tie -> require_review (v1.5 §10.4 last row)
  top = [ p in P with priority == P[0].priority ]
  if exists two p,q in top with different actions
        AND strength(p.action) == strength(q.action):
      primary = require_review

  # 4.2.2 union constraints from compatible policies
  constraints = {}
  reason_codes = []
  matched_rule_ids = []
  for p in P:                                    # deterministic order
      if compatible(p.decision.action, primary):
          constraints = merge_constraints(constraints, p.decision.constraints)
          reason_codes.append(p.decision.reason_code)
          matched_rule_ids += p.matched_rule_ids

  # 4.2.3 gate-class constraints always co-apply when in a gate primary
  if primary in {require_confirmation, step_up_auth, require_review}:
      if any p.action == require_confirmation: constraints.confirmation_required = true
      if any p.action == step_up_auth:        constraints.step_up_auth_required = true

  return Decision{primary, constraints, reason_codes, matched_rule_ids}
```

### 4.3 Compatibility rules

```text
compatible(a, primary):
  # terminal stops suppress transform/passive constraints (no point redacting a blocked output)
  if primary in {deny, block}:
      return a in {deny, block, require_review, audit_only}   # keep audit/review trail
  # transforms can co-apply with each other and with gates
  return true
```

When `primary ∈ {deny, block}`, transform constraints (redaction_profile, etc.) are NOT applied but the matched policies and their reason_codes MUST still be recorded in evidence (transparency).

### 4.4 Constraint union semantics

`merge_constraints` MUST be deterministic and conservative (most-restrictive wins):

```text
audit_required:        OR
evidence_required:     OR
confirmation_required: OR
step_up_auth_required: OR
scope_restriction:     intersection (narrowest scope)
redaction_profile:     highest-strength profile by registry rank; tie -> require_review
review_queue:          highest-severity queue
user_message_template: from the highest-priority matched policy
```

### 4.5 Determinism requirement

Because `P` is sorted by `(priority desc, policy_id asc)` and all merges are commutative/associative-by-construction, `resolve` is a pure deterministic function and is replayable. Add to `decision.confidence` definition (closes v1.5 ambiguity, review P1-2): `decision.confidence = fused_risk.confidence_summary.representative` unless overridden by an explicit policy constant.

***

## 5. Control Plane API Security & Idempotency

v1.5 §16 defines APIs with no authN/authZ, no transport security, and contradicts itself on state (§4.2 "stateless" vs §16.1 idempotency, which requires a decision store). v1.6 resolves both.

### 5.1 Transport & identity (normative)

```text
- All control-plane APIs MUST be served over mTLS.
- Each caller MUST present a workload identity (e.g., SPIFFE/SVID or platform
  service identity). Anonymous calls MUST be rejected.
- Authorization is per (tenant_id, app_id) scope: a caller may only evaluate
  decisions for tenants/apps it is authorized for.
- Per-tenant rate limiting MUST be enforced; control-plane saturation is an
  availability attack on all AI workloads (review P1-6).
```

### 5.2 Request anti-replay

```text
Every request MUST carry: request_id (uuid), issued_at (RFC3339), nonce.
The server MUST reject requests where |now - issued_at| > clock_skew_window
(default 60s) or where (caller_id, nonce) was already seen within the window.
```

### 5.3 Stateless / idempotency reconciliation [HARDENED]

Resolves the v1.5 §4.2 ↔ §16.1 contradiction:

```text
- "Stateless" means the decision COMPUTATION is stateless: given the same
  (normalized signals, context, pinned config versions) the result is identical.
- Idempotency is provided by an EXTERNAL decision store, not by holding state
  in the evaluator.
- Idempotency key = (trace_id, request_id, stage).
- Semantics: FIRST-WRITE-WINS.
    * First call computes and persists the Decision keyed by the idempotency key.
    * Subsequent calls with the same key return the SAME persisted Decision,
      EVEN IF the submitted signals differ (signals are non-deterministic;
      the first committed decision is authoritative).
    * If submitted signals differ from the original, the server MUST set
      response flag `idempotent_replay=true` and record a
      `signal_divergence` note in evidence for audit.
- Decision store TTL >= max(signal.ttl_ms) for the trace; after TTL the key
  may be recomputed.
```

This keeps the evaluator horizontally scalable (stateless compute) while making the public API observably idempotent.

### 5.4 Decision integrity [HARDENED]

v1.5 §25.1 says decisions "should" be signed. v1.6: in `canary` and `prod`, `decision.integrity.signature` and `signed_by` are **MUST**. Enforcement Adapter MUST verify the signature before acting on a decision (extends INV-3: the only enforcement input is a *verified* Decision Contract).

***

## 6. Synchronous vs Asynchronous Judge Path

v1.5 caps p95 ≤ 300ms but only "for non-judge path" (§24) and defines judge signals as advisory-only (§8.4) without saying what happens when a judge is slow on the synchronous path.

### 6.1 Hard rule

```text
The synchronous decision path MUST NOT block on a judge (source_type=judge)
signal. Judge signals are consumed only if already present within the
decision timeout budget; otherwise the decision is computed WITHOUT them.
```

### 6.2 Decision stability & revision

Add to Decision Contract `decision` block:

```json
"stability": "final | provisional_pending_async",
"decision_revision": 0,
"supersedes_decision_id": "optional"
```

- A decision computed before a pending judge result returns is `provisional_pending_async`.
- When an async judge signal arrives, the control plane MAY emit a **revised decision** (`decision_revision += 1`, `supersedes_decision_id` = original) consumed at the next downstream gate (e.g., a provisional `allow` at `input` can be tightened at `output`), or escalate to async audit / review if no downstream gate remains.
- Enforcement always acts on the latest verified, non-superseded decision for a `(trace_id, stage)`.

### 6.3 Latency budget by stage (resolves v1.5 §26 Q#4)

```text
input               p95 <= 300 ms (sync, no judge)
output              p95 <= 300 ms (sync, no judge)
retrieval           p95 <= 400 ms
tool_pre_execution  p95 <= 500 ms (includes registry read + binding validation)
judge augmentation  async, no sync SLA; bounded by ttl_ms
```

***

## 7. Updated Conformance Checklist (Sprint 1 / 2 entry criteria)

A v1.6-conformant MVP MUST satisfy:

```text
[ ] INV-1..INV-7 enforced (INV-7 provenance mode declared per integration point)
[ ] stage_action_matrix.yaml is the single source for lint + decision + enforcement validation
[ ] fuse() passes golden vectors TV-1..TV-6, including order-independence TV-6
[ ] resolve() reproduces v1.5 §10.4 pairwise cases AND multi-policy constraint union
[ ] all APIs require mTLS + workload identity + anti-replay
[ ] idempotency = first-write-wins via external decision store
[ ] decisions signed and verified in canary/prod
[ ] sync path never blocks on judge; provisional/revised decisions supported
[ ] every dropped/invalid signal is recorded in evidence (dropped_signals[])
[ ] replay_binding pins: policy_bundle, fusion_config, threshold_config,
    matrix_version, provenance_mode
```

***

## 8. Open Questions Resolved (architect decisions, from v1.5 §26)

These are no longer "open" for MVP; they are decided:

1. First xCloud integration point → **AI Gateway** (covers input/output, widest reach).
2. Runtime labels → `label` + `registry` sources first; detector-inferred labels post-MVP.
3. P0 detectors → `prompt_injection`, `enterprise_data_leakage`, `tool_schema_drift`. Others optional.
4. Production p95 → per stage as in §6.3.
5. Evidence storage → platform-owned store + compliance read-only export.
6. First gate owner → Tianmu + Governance (joint).
7. Executive demo path → Golden Scenario 1 (Enterprise Data Leakage Output Control).
8. Shadow mode → MUST compute hypothetical enforcement (needed for dry-run/diff), not read-only.
9. Policy rollback → immutable bundle + version pointer switch (blue/green); no in-place edits.
10. First MCP/tool class → `send_email` (external_send).
11. Confirmation UX → platform owns the control; security owns the binding semantics.
12. MVP data taxonomy → `pii`, `customer_contract`, `source_code`, `credential`.
13. Tool registry truth → platform MCP registry authoritative; control plane snapshots it.
14. Audit export → `decision_id` chain + evidence integrity hash + gate record.

***

## 9. One-line Summary

**v1.6 在不改变 v1.5 架构思想（INV-1..6、平面分离、MVP 四 stage、契约集）的前提下，补齐五项 P0 工程缺口：以 INV-7 建立信号信任根，以机读 Stage×Action Matrix 统一三处校验事实源，以"规范化排序 + 单调格合并 + 固定规则序"的确定性 Fusion 算法保证可重放（TV-1..TV-6 验收），以"action 强度全序 + 约束并集"的 Policy 冲突裁决算法处理 N 策略命中，并通过 mTLS/工作负载身份/防重放、first-write-wins 幂等与无状态计算的协调、以及同步路径禁阻塞 Judge + decision_revision 的异步补评机制，使该控制平面从"架构基线"升级为可由顶级安全开发者直接按 Sprint 1 开工的工程规范。**
