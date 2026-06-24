# Enterprise AI Runtime Security Control Plane Spec v1.5

## 0. Document Header

**Title:** Enterprise AI Runtime Security Control Plane Spec  
**Subtitle:** 面向 LLM / RAG / Tool / MCP / Agent 的企业级运行时授权与信任控制平面  
**Version:** v1.5  
**Document Type:** Architecture Spec / Runtime Protocol / Engineering Baseline  
**Audience:** AI Security Architects, Runtime Security Engineers, Platform Engineers, xCloud / Enterprise AI Integration Developers, Policy Engineers, Evaluation Engineers  
**Status:** Internal Engineering Draft  
**Primary Positioning:** Enterprise AI Runtime Authorization & Trust Control Plane  
**Design Philosophy:** Control Plane First / Contract First / Policy-Driven / Evidence-First / Replayable-by-Design / Gate-Enforced  
**Source Baseline:** Revised from v1.4. 

***

## 1. Executive Summary

Enterprise AI systems are moving from single-turn chat to RAG, tool calling, MCP server access, and agentic workflows. In this environment, security is no longer merely about whether a model response is safe. It becomes a runtime authorization and trust-control problem over AI-mediated enterprise actions.

The control object of this system is:

```text
AI-mediated enterprise action
```

An AI-mediated enterprise action may include:

* accessing enterprise data;
* retrieving contextual documents;
* assembling prompts;
* invoking tools;
* calling MCP servers;
* sending content externally;
* using delegated permissions;
* producing business-impacting outputs;
* triggering downstream automation.

The system must answer:

```text
Given the current actor, tenant, application, model, data asset, tool, destination,
policy, trust state, and business context,
is this AI-mediated action allowed?
If allowed, under what constraints?
If denied or modified, why?
Based on which policy, signals, evidence, and release state?
Can the decision be audited, replayed, evaluated, and gated?
```

v1.5 advances the v1.4 architecture into an engineering-ready runtime control plane. v1.4 already defines the core chain as Context → Signals → Fusion → Policy → Decision → Enforcement → Trace/Evidence → Evaluation → Release Gate. v1.5 makes this chain executable through strict runtime contracts, stage semantics, API surfaces, failure modes, policy lifecycle, and release governance. 

***

## 2. Core Thesis

The system is not:

* another detector;
* another content moderation API;
* another prompt firewall;
* another DLP rule engine;
* another AI observability dashboard;
* another middleware plugin.

The system is:

```text
A runtime authorization and trust control plane
that converts heterogeneous AI risk signals into
policy-grounded, enforceable, auditable, replayable,
and release-gated decisions.
```

The enduring control-plane loop is:

```text
Context
→ Signals
→ Fusion
→ Policy
→ Decision
→ Enforcement
→ Evidence
→ Evaluation
→ Release Gate
```

v1.4 already identifies this loop as the system thesis and requires MVP scenarios to penetrate the full vertical slice. v1.5 turns each node in this loop into an implementable developer contract. 

***

## 3. Architectural Invariants

The following invariants are non-negotiable.

### INV-1: Detector never enforces

Detector output is signal, not decision.

```text
Detector output = signal
Policy runtime output = decision
Enforcement consumes decision
```

This separation is already central to v1.4. In v1.5, any detector that directly returns `allow`, `deny`, `redact`, or `block` as a final action is considered non-compliant unless wrapped by a Signal Adapter. 

***

### INV-2: Policy has no side effect

Policy Runtime evaluates facts and emits a decision candidate. It must not:

* redact content directly;
* call tools;
* write audit logs as primary side effect;
* mutate user state;
* mutate approval state;
* modify tool metadata.

Side effects belong to Enforcement Adapter, Evidence Service, Approval Service, or Registry Service.

***

### INV-3: Decision Contract is the only enforcement input

Enforcement must not inspect raw detector outputs or policy internals. It only executes the `decision.action` and associated constraints in the Decision Contract.

***

### INV-4: Evidence is part of correctness, not logging

A decision without sufficient evidence is an incomplete decision. v1.4 already states that Evidence is the source of truth and must support audit, replay, release review, incident investigation, policy regression, evaluation linkage, and compliance export. v1.5 formalizes this as: 

```text
decision_correctness = action_correctness + reason_correctness + evidence_completeness
```

***

### INV-5: Tool / MCP is an independent execution boundary

Tool / MCP calls are not merely model output. v1.4 already makes Tool / MCP an independent security boundary and requires governance over tool identity, server identity, schema, manifest, permission class, action parameters, target resource, approval binding, schema drift, and tool trust state. 

In v1.5, every tool call must be normalized into `ToolActionContext` before policy evaluation.

***

### INV-6: Release Gate is built into the lifecycle

A detector update, policy update, threshold update, tool metadata baseline change, or approval workflow change must not be treated as a normal configuration update. v1.4 already lists these as release-gated objects. v1.5 requires each such change to produce a `GateEvaluationRecord`. 

***

## 4. Plane Separation

### 4.1 Data Plane

The Data Plane is where AI workloads execute:

* user input;
* retrieval request;
* prompt assembly;
* model inference;
* tool call;
* MCP server call;
* output generation;
* response delivery.

The Data Plane integrates with the Control Plane through synchronous decision calls.

***

### 4.2 Control Plane

The Control Plane performs:

* context normalization;
* signal normalization;
* deterministic fusion;
* policy evaluation;
* decision generation;
* decision signing;
* decision response.

The Control Plane must be stateless for core decision evaluation except for registry lookups and versioned configuration reads.

***

### 4.3 Evidence Plane

The Evidence Plane performs:

* trace creation;
* evidence commit;
* evidence enrichment;
* replay binding;
* evidence indexing;
* audit package generation;
* evaluation linkage.

The Evidence Plane must support both synchronous minimal evidence and asynchronous enrichment.

***

### 4.4 Management Plane

The Management Plane manages:

* policy registry;
* detector registry;
* tool registry;
* MCP server registry;
* threshold registry;
* release gate registry;
* approval workflow registry;
* evaluation profile registry.

***

## 5. MVP Scope

v1.5 keeps v1.4’s MVP principle: do not build a full platform horizontally first; instead build vertical slices across the full chain. v1.4 already defines MVP as Context Snapshot → Signal Adapter → Deterministic Fusion → Policy Runtime → Decision Contract → Enforcement Adapter → Evidence Package → Evaluation Log → Release Gate. 

### 5.1 MVP Runtime Stages

MVP supports four stages:

```text
input
retrieval
tool_pre_execution
output
```

v1.4 already identifies these four as MVP stages. 

***

### 5.2 MVP Control Actions

MVP supports:

```text
allow
deny
block
redact
sanitize
mask
restrict_scope
require_confirmation
require_review
step_up_auth
audit_only
annotate_risk
```

v1.4 lists allow, deny, redact, sanitize, mask, restrict\_scope, require\_confirmation, require\_review, step\_up\_auth, and audit\_only as MVP actions. v1.5 adds explicit `block` and `annotate_risk` normalization because v1.4’s Stage × Action Matrix already uses `block` and `annotate_risk` in stage-specific rows.  

***

### 5.3 MVP Exclusions

MVP does not include:

* full autonomous agent workflow rollback;
* full multi-step attack-chain reasoning;
* automated shadow AI discovery;
* full semantic tool poisoning analysis;
* formal policy verification;
* full IAM replacement;
* full SIEM / SOAR replacement;
* full data classification platform;
* full red-team platform.

These exclusions are aligned with v1.4 Deferred Scope. 

***

## 6. Runtime Stage Semantics

## 6.1 Stage: input

### Purpose

Evaluate user input before it enters prompt construction, model inference, retrieval, or tool planning.

### Input Object

```json
{
  "stage": "input",
  "user_input": "string",
  "actor": {},
  "application": {},
  "model": {},
  "session": {},
  "destination": {}
}
```

### Observable Facts

* prompt injection attempt;
* unsafe request;
* sensitive data in prompt;
* credential exposure;
* policy bypass intent;
* jailbreak indicators;
* enterprise data included by user.

### Allowed Actions

```text
allow
deny
sanitize
mask
require_review
audit_only
```

### Disallowed Actions

```text
redact
restrict_scope
require_confirmation
step_up_auth
```

Rationale: input stage has no retrieval scope or tool action yet. Confirmation is premature unless a tool action exists.

### Failure Mode

* If detector timeout and user input is low risk by policy default: `audit_only`.
* If detector timeout and request targets privileged app or regulated data: `require_review`.
* If policy runtime unavailable in prod: `deny` for high-risk application, `audit_only` for low-risk shadow mode.

***

## 6.2 Stage: retrieval

### Purpose

Evaluate retrieved content, retrieval source, scope, and grounding trust before content is injected into prompt context.

### Input Object

```json
{
  "stage": "retrieval",
  "retrieval_query": "string",
  "retrieved_items": [],
  "source_trust": {},
  "data": {},
  "actor": {},
  "application": {}
}
```

### Observable Facts

* untrusted source;
* external web content;
* hidden instruction;
* poisoned context;
* over-broad retrieval;
* sensitive document retrieval;
* cross-tenant retrieval boundary;
* source/data sensitivity mismatch.

### Allowed Actions

```text
allow
deny
restrict_scope
annotate_risk
require_review
audit_only
```

v1.4 includes retrieval actions such as allow, deny, restrict\_scope, annotate\_risk, and audit\_only. v1.5 adds `require_review` because conflict or uncertainty should be routed to review consistently across stages. 

### Enforcement Examples

* `restrict_scope`: remove or down-scope retrieved documents before prompt assembly.
* `annotate_risk`: mark retrieved content as untrusted and prevent it from controlling tool planning.
* `deny`: stop retrieval result from entering context.

### Failure Mode

If source trust cannot be resolved:

```text
unknown source + external content + tool-capable session → restrict_scope
unknown source + internal low sensitivity → annotate_risk + audit_only
```

***

## 6.3 Stage: tool\_pre\_execution

### Purpose

Authorize a tool or MCP call before execution.

### Input Object

```json
{
  "stage": "tool_pre_execution",
  "tool_action": {
    "tool_id": "string",
    "server_id": "string",
    "tool_version": "string",
    "manifest_hash": "string",
    "schema_hash": "string",
    "permission_class": "read | write | external_send | privileged | unknown",
    "parameters_hash": "string",
    "target_resource": {},
    "destination": {},
    "approval_state": {}
  },
  "actor": {},
  "application": {},
  "data": {}
}
```

### Observable Facts

* write action;
* external send;
* privileged operation;
* schema drift;
* manifest drift;
* revoked tool;
* unknown server;
* missing approval;
* stale approval;
* parameter mismatch after approval;
* target resource change;
* sensitive content sent externally.

### Allowed Actions

```text
allow
deny
require_confirmation
step_up_auth
require_review
audit_only
```

v1.4’s Stage × Action Matrix lists tool\_pre\_execution actions as allow, deny, require\_confirmation, step\_up\_auth, and require\_review. v1.5 adds `audit_only` for shadow and canary rollout. 

### Failure Mode

```text
unknown tool trust state + write/external_send → require_review or deny
schema drift + existing approval → require_confirmation
revoked tool → deny
missing schema hash + privileged action → deny
missing schema hash + read action → require_review
```

***

## 6.4 Stage: output

### Purpose

Evaluate model output before delivery or external disclosure.

### Input Object

```json
{
  "stage": "output",
  "model_output": "string",
  "destination": {},
  "data": {},
  "actor": {},
  "application": {},
  "source_context_refs": []
}
```

### Observable Facts

* enterprise data leakage;
* PII leakage;
* customer contract disclosure;
* source code leakage;
* unsafe content;
* unsupported claim;
* regulated data disclosure;
* external boundary crossing.

### Allowed Actions

```text
allow
redact
block
require_review
audit_only
mask
```

v1.4 includes output actions allow, redact, block, require\_review, and audit\_only. v1.5 adds `mask` because v1.4’s MVP action list includes mask.  

### Failure Mode

```text
classifier timeout + external destination + confidential context → require_review
classifier timeout + internal destination + public context → audit_only
evidence commit failure + high risk output → block or require_review
```

***

## 7. Context Model v1.5

v1.4 defines MVP Context fields including user\_id, tenant\_id, app\_id, session\_id, request\_id, stage, model\_id, data\_asset\_type, data\_sensitivity, destination\_boundary, tool\_id, tool\_server\_id, tool\_permission\_class, and runtime\_environment. v1.5 expands this into a normalized schema. 

```json
{
  "schema_version": "1.5",
  "context_id": "ctx-uuid",
  "trace_id": "trace-uuid",
  "request_id": "req-uuid",
  "stage": "input | retrieval | tool_pre_execution | output",
  "timestamp": "2026-06-24T15:50:00+08:00",

  "actor": {
    "user_id": "string",
    "tenant_id": "string",
    "role": "string",
    "privilege_level": "low | medium | high | admin | unknown",
    "auth_strength": "none | password | mfa | step_up | unknown"
  },

  "application": {
    "app_id": "string",
    "runtime_id": "string",
    "environment": "shadow | canary | prod",
    "integration_point": "ai_gateway | app_middleware | mcp_proxy | service_mesh | unknown"
  },

  "model": {
    "model_id": "string",
    "model_provider": "internal | external | unknown",
    "model_security_profile": "unknown | baseline | hardened | restricted"
  },

  "session": {
    "session_id": "string",
    "conversation_id": "string",
    "turn_id": "string",
    "agentic_mode": "none | tool_assisted | agentic | unknown"
  },

  "data": {
    "data_asset_type": "pii | customer_contract | source_code | financial_data | product_roadmap | credential | unknown",
    "sensitivity": "public | internal | confidential | restricted | regulated | unknown",
    "owner": "string",
    "provenance": "user_input | rag | tool_result | model_output | unknown",
    "classification_source": "label | detector | registry | inherited | unknown"
  },

  "destination": {
    "boundary": "same_user | same_tenant | cross_tenant | external | unknown",
    "channel": "chat | email | api | file | tool | unknown",
    "recipient_type": "user | group | external_address | system | unknown"
  },

  "tool": {
    "tool_id": "optional",
    "server_id": "optional",
    "tool_version": "optional",
    "schema_hash": "optional",
    "manifest_hash": "optional",
    "description_hash": "optional",
    "permission_class": "read | write | external_send | privileged | unknown",
    "trust_state": "approved | pinned | drifted | revoked | unknown"
  },

  "runtime": {
    "region": "string",
    "deployment_id": "string",
    "policy_bundle_version": "string",
    "fusion_config_version": "string",
    "threshold_config_version": "string"
  }
}
```

***

## 8. Signal Model v1.5

v1.4 defines Signals as structured security signals from detectors, trust parsers, policy-aware judges, schema validators, and other components, and emphasizes that Signal is not decision. 

### 8.1 Signal Source Types

```text
rule
model
judge
trust
schema
registry
human
system
```

v1.4 lists rule-based detector, model-based detector, policy-aware reasoning judge, and structure/trust detector as MVP signal sources. v1.5 adds `schema`, `registry`, `human`, and `system` to distinguish engineering origins. 

### 8.2 Signal Schema

```json
{
  "schema_version": "1.5",
  "signal_id": "sig-uuid",
  "trace_id": "trace-uuid",
  "context_id": "ctx-uuid",
  "stage": "input | retrieval | tool_pre_execution | output",

  "signal_type": "prompt_injection | pii | enterprise_data_leakage | unsafe_content | tool_schema_drift | tool_manifest_drift | unauthorized_action | policy_violation | source_untrusted | approval_stale | registry_miss",

  "risk_family": "SEC | SAF | PRIV | REL | COMP",
  "severity": "low | medium | high | critical",
  "confidence": 0.0,

  "source": {
    "source_id": "string",
    "source_type": "rule | model | judge | trust | schema | registry | human | system",
    "source_version": "string"
  },

  "attributes": {
    "data_asset_type": "optional",
    "data_sensitivity": "optional",
    "destination_boundary": "optional",
    "tool_id": "optional",
    "server_id": "optional",
    "matched_pattern": "optional",
    "reason_summary": "optional",
    "span_refs": []
  },

  "evidence_ref": "ev-uuid",
  "latency_ms": 0,
  "ttl_ms": 300000
}
```

### 8.3 Signal Validity Rules

A signal is valid only if:

* it has `signal_id`;
* it binds to `trace_id`;
* it declares `stage`;
* it declares `risk_family`;
* it declares `severity`;
* it declares `source`;
* it has evidence reference or explicit `evidence_pending=true`.

### 8.4 Advisory Judge Constraint

v1.4 already states that Policy-aware Reasoning Judge can only output advisory signal and cannot directly decide action. v1.5 makes this enforceable: 

```text
If source_type == judge:
  signal.attributes.advisory_only must be true
  signal must not contain final_action
```

***

## 9. Fusion & Risk Layer v1.5

v1.4 defines deterministic fusion for MVP, including rules such as critical signal → critical fused risk, high signal + external destination → critical fused risk, schema drift + prior approval → approval invalidated, conflicting signals → require\_review, low confidence high severity → require\_review, and multiple medium signals within same trace → high fused risk. 

### 9.1 Fusion Goals

Fusion must be:

* deterministic;
* explainable;
* testable;
* replayable;
* gateable;
* low latency.

### 9.2 Fused Risk Schema

```json
{
  "schema_version": "1.5",
  "fused_risk_id": "fr-uuid",
  "trace_id": "trace-uuid",
  "context_id": "ctx-uuid",
  "stage": "tool_pre_execution",

  "risk_families": ["SEC", "PRIV"],
  "highest_severity": "high",

  "confidence_summary": {
    "min": 0.62,
    "max": 0.93,
    "aggregation": "deterministic_v1"
  },

  "risk_reasons": [
    "external_destination_with_confidential_data",
    "tool_action_requires_confirmation"
  ],

  "conflicts": [
    {
      "conflict_type": "detector_disagreement",
      "signal_ids": ["sig-a", "sig-b"],
      "resolution": "escalate_to_review"
    }
  ],

  "uncertainty": "low | medium | high",

  "recommended_policy_path": "enterprise_external_disclosure_policy",

  "fusion_config_version": "deterministic_v1"
}
```

### 9.3 Fusion Rule Table

| Rule ID | Condition                             | Fused Result          | Required Explanation     |
| ------- | ------------------------------------- | --------------------- | ------------------------ |
| FR-001  | any critical signal                   | critical              | cite signal\_id          |
| FR-002  | high signal + external destination    | critical              | cite boundary and signal |
| FR-003  | schema drift + prior approval         | approval\_invalidated | cite schema hash diff    |
| FR-004  | conflicting high-confidence signals   | require\_review       | cite conflict pair       |
| FR-005  | low-confidence high-severity signal   | require\_review       | cite uncertainty         |
| FR-006  | multiple medium signals in same trace | high                  | cite signal cluster      |
| FR-007  | registry miss + privileged tool       | high                  | cite registry miss       |
| FR-008  | revoked tool                          | critical              | cite tool registry state |

***

## 10. Policy Runtime v1.5

v1.4 recommends Typed YAML / JSON Policy Schema + deterministic evaluator + unit test + dry-run report + diff report, and explicitly advises against building a complex DSL in the first version. 

### 10.1 Policy Principles

Policy must be:

* declarative;
* versioned;
* lintable;
* testable;
* dry-runnable;
* diffable;
* replay-bindable;
* gateable;
* rollbackable.

### 10.2 Policy Schema

```yaml
schema_version: "1.5"

policy_id: "enterprise_external_disclosure_policy"
version: "1.0.0"
status: "draft | shadow | canary | prod | deprecated"
description: "Prevent confidential enterprise data from crossing external boundaries without redaction or approval."

scope:
  stages:
    - output
  app_ids:
    - "*"
  tenant_ids:
    - "*"
  environments:
    - shadow
    - canary
    - prod

priority: 100

conditions:
  all:
    - field: data.sensitivity
      op: in
      value:
        - confidential
        - restricted
        - regulated
    - field: destination.boundary
      op: in
      value:
        - external
        - cross_tenant

decision:
  action: redact
  reason_code: confidential_enterprise_data_external_boundary
  constraints:
    audit_required: true
    evidence_required: true
    user_message_template: enterprise_data_redacted_external_boundary

fallback:
  on_detector_timeout: require_review
  on_policy_error: deny
  on_evidence_commit_failure: require_review

gate:
  required_eval_profile: privacy_leakage_output_control_v1
  min_recall: 0.95
  min_precision: 0.85
  max_false_positive_rate: 0.08
  min_evidence_completeness: 0.98
  min_replay_consistency: 0.99
  max_p95_decision_latency_ms: 300

metadata:
  owner: "ai-security-control-plane"
  created_at: "2026-06-24T15:50:00+08:00"
  updated_at: "2026-06-24T15:50:00+08:00"
```

### 10.3 Policy Match Semantics

Policy evaluation follows:

```text
1. Filter by scope.
2. Sort by priority descending.
3. Evaluate conditions.
4. Collect matched policies.
5. Resolve conflicts.
6. Emit decision candidate.
7. Bind policy version and matched rule IDs to Decision Contract.
```

### 10.4 Conflict Resolution

| Conflict                                | Resolution                                              |
| --------------------------------------- | ------------------------------------------------------- |
| allow vs deny                           | deny wins                                               |
| allow vs redact                         | redact wins                                             |
| redact vs block                         | block wins if severity critical                         |
| require\_confirmation vs deny           | deny wins for revoked or unknown privileged tool        |
| require\_confirmation vs step\_up\_auth | combine if both constraints are valid                   |
| audit\_only vs any active control       | active control wins                                     |
| multiple policies same priority         | require\_review unless deterministic tie-breaker exists |

### 10.5 Policy Lint Rules

| Lint ID | Rule                                                                                  | Severity |
| ------- | ------------------------------------------------------------------------------------- | -------- |
| PL-001  | stage must be declared                                                                | error    |
| PL-002  | decision.action must be valid for stage                                               | error    |
| PL-003  | policy must define fallback                                                           | warning  |
| PL-004  | prod policy must define gate                                                          | error    |
| PL-005  | external boundary policy must require evidence                                        | error    |
| PL-006  | tool write/external\_send policy must define approval binding if confirmation is used | error    |
| PL-007  | policy priority collision must be explicit                                            | warning  |
| PL-008  | condition field must exist in Context Schema                                          | error    |

### 10.6 Policy Unit Test Contract

```yaml
test_id: "privacy_output_external_redaction_001"
policy_id: "enterprise_external_disclosure_policy"
input:
  context:
    stage: output
    data:
      sensitivity: confidential
      data_asset_type: customer_contract
    destination:
      boundary: external
  fused_risk:
    highest_severity: high
expected:
  action: redact
  reason_code: confidential_enterprise_data_external_boundary
  evidence_required: true
```

***

## 11. Decision Contract v1.5

v1.4 identifies Decision Contract as the most important engineering interface connecting Context, Signals, Policy, Decision, Enforcement, Evidence, Evaluation, and Release Gate. 

### 11.1 Decision Contract Schema

```json
{
  "schema_version": "1.5",
  "decision_id": "dec-uuid",
  "trace_id": "trace-uuid",
  "context_id": "ctx-uuid",
  "timestamp": "2026-06-24T15:50:00+08:00",

  "stage": "input | retrieval | tool_pre_execution | output",

  "subject": {
    "user_id": "string",
    "tenant_id": "string",
    "app_id": "string",
    "session_id": "string",
    "privilege_level": "low | medium | high | admin | unknown"
  },

  "object": {
    "object_type": "input | retrieved_content | tool_action | model_output",
    "data_asset_type": "customer_contract | source_code | pii | financial_data | product_roadmap | unknown",
    "sensitivity": "public | internal | confidential | restricted | regulated | unknown",
    "tool_id": "optional",
    "server_id": "optional",
    "resource_id": "optional",
    "destination_boundary": "same_user | same_tenant | cross_tenant | external | unknown"
  },

  "signals": [
    {
      "signal_id": "sig-uuid",
      "signal_type": "enterprise_data_leakage",
      "risk_family": "PRIV",
      "severity": "high",
      "confidence": 0.91,
      "evidence_ref": "ev-uuid"
    }
  ],

  "fused_risk_summary": {
    "fused_risk_id": "fr-uuid",
    "highest_severity": "high",
    "risk_families": ["PRIV"],
    "risk_reasons": ["confidential_customer_contract_external_boundary"],
    "uncertainty": "low"
  },

  "policy": {
    "policy_bundle_version": "bundle-2026-06-24",
    "matched_policies": [
      {
        "policy_id": "enterprise_external_disclosure_policy",
        "policy_version": "1.0.0",
        "matched_rule_ids": ["rule-001"]
      }
    ]
  },

  "decision": {
    "action": "allow | deny | block | redact | sanitize | mask | restrict_scope | require_confirmation | require_review | step_up_auth | audit_only | annotate_risk",
    "reason_code": "confidential_enterprise_data_external_boundary",
    "confidence": 0.91,
    "decision_mode": "shadow | canary | prod",
    "enforcement_required": true
  },

  "constraints": {
    "redaction_profile": "optional",
    "scope_restriction": "optional",
    "confirmation_required": false,
    "step_up_auth_required": false,
    "review_queue": "optional",
    "audit_required": true,
    "user_message_template": "optional"
  },

  "approval_binding": {
    "required": false,
    "approval_id": "optional",
    "binding_hash": "optional",
    "binding_fields": [],
    "expires_at": "optional"
  },

  "evidence": {
    "evidence_required": true,
    "evidence_refs": ["ev-uuid"],
    "minimal_evidence_committed": true,
    "evidence_completeness": 0.98
  },

  "replay_binding": {
    "context_snapshot_ref": "ctx-uuid",
    "signal_snapshot_refs": ["sig-uuid"],
    "policy_bundle_version": "bundle-2026-06-24",
    "detector_versions": {
      "enterprise_data_classifier": "0.3.2"
    },
    "fusion_config_version": "deterministic_v1",
    "threshold_config_version": "threshold_v1"
  },

  "integrity": {
    "decision_hash": "sha256:...",
    "signed_by": "control-plane-runtime",
    "signature": "optional"
  }
}
```

### 11.2 Decision Correctness Criteria

A decision is correct only if:

```text
stage is valid
action is valid for stage
matched policy exists or default policy is explicitly applied
reason_code is non-empty
required evidence is committed
replay_binding is complete
enforcement adapter receives the same decision_id
```

***

## 12. Enforcement Adapter v1.5

v1.4 states that Enforcement Adapter only executes the action in Decision Contract and does not interpret detector or policy. 

### 12.1 Enforcement Interface

```json
{
  "decision_id": "dec-uuid",
  "trace_id": "trace-uuid",
  "stage": "output",
  "action": "redact",
  "constraints": {
    "redaction_profile": "enterprise_confidential_v1",
    "audit_required": true
  },
  "target": {
    "object_type": "model_output",
    "content_ref": "content-uuid"
  }
}
```

### 12.2 Enforcement Result

```json
{
  "enforcement_id": "enf-uuid",
  "decision_id": "dec-uuid",
  "status": "success | partial | failed | skipped",
  "action_executed": "redact",
  "output_ref": "content-redacted-uuid",
  "error": {
    "code": "optional",
    "message": "optional"
  },
  "timestamp": "2026-06-24T15:50:00+08:00"
}
```

### 12.3 Enforcement Failure Rules

| Failure                       | Required Behavior                 |
| ----------------------------- | --------------------------------- |
| redact failed                 | block or require\_review          |
| restrict\_scope failed        | deny retrieval result             |
| confirmation UI unavailable   | require\_review                   |
| step-up auth unavailable      | deny privileged action            |
| evidence required but missing | do not mark decision complete     |
| enforcement adapter timeout   | fail according to policy fallback |

***

## 13. Evidence Package v1.5

v1.4 defines Evidence Package with evidence\_id, trace\_id, decision\_id, stage, evidence\_type, content\_ref, context\_ref, signal\_refs, policy\_ref, decision\_ref, retention, and indexing. 

### 13.1 Evidence Types

```text
context_snapshot
content_span
retrieval_source
signal_summary
fusion_summary
policy_match
decision_record
tool_metadata
approval_record
enforcement_result
release_gate_record
```

### 13.2 Evidence Package Schema

```json
{
  "schema_version": "1.5",
  "evidence_id": "ev-uuid",
  "trace_id": "trace-uuid",
  "decision_id": "dec-uuid",
  "stage": "output",

  "evidence_type": "content_span | context_snapshot | signal_summary | policy_match | tool_metadata | approval_record | enforcement_result",

  "content_ref": {
    "source": "model_output",
    "content_id": "content-uuid",
    "span_ids": ["span-001", "span-002"],
    "redacted_preview": "Customer contract includes [REDACTED]..."
  },

  "context_ref": "ctx-uuid",
  "signal_refs": ["sig-uuid"],
  "fusion_ref": "fr-uuid",

  "policy_ref": {
    "policy_id": "enterprise_external_disclosure_policy",
    "version": "1.0.0",
    "matched_rule_ids": ["rule-001"]
  },

  "decision_ref": "dec-uuid",

  "tool_ref": {
    "tool_id": "optional",
    "server_id": "optional",
    "schema_hash": "optional",
    "manifest_hash": "optional"
  },

  "retention": {
    "classification": "audit",
    "retention_days": 180,
    "legal_hold": false
  },

  "indexing": {
    "tenant_id": "string",
    "app_id": "string",
    "risk_family": "PRIV",
    "data_asset_type": "customer_contract",
    "stage": "output"
  },

  "integrity": {
    "evidence_hash": "sha256:...",
    "parent_hash": "optional"
  }
}
```

### 13.3 Minimal Synchronous Evidence

For latency-sensitive runtime, the synchronous commit must include:

```text
trace_id
decision_id
context_ref
signal_refs
policy_ref
decision action
reason_code
stage
timestamp
```

### 13.4 Async Evidence Enrichment

Async enrichment may add:

```text
content spans
redacted previews
tool metadata snapshots
approval records
enforcement result
evaluation labels
release gate links
```

### 13.5 Evidence Completeness Score

```text
evidence_completeness =
required_fields_present / required_fields_total
```

Stage-specific required fields:

| Stage                | Required Evidence                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------- |
| input                | context, input span, signal summary, policy match, decision                                     |
| retrieval            | context, retrieval source, retrieved span, signal summary, policy match, decision               |
| tool\_pre\_execution | context, tool metadata, parameters hash, approval state, signal summary, policy match, decision |
| output               | context, output span, signal summary, policy match, decision, enforcement result                |

***

## 14. Replay-lite v1.5

v1.4 deliberately limits MVP replay to decision-level replay and does not require reproducing model generation, raw detector inference, retrieval ranking, or external tool responses. 

### 14.1 Replay Inputs

```json
{
  "trace_id": "trace-uuid",
  "decision_id": "dec-uuid",
  "context_snapshot_ref": "ctx-uuid",
  "signal_snapshot_refs": ["sig-uuid"],
  "policy_bundle_version": "bundle-2026-06-24",
  "fusion_config_version": "deterministic_v1",
  "threshold_config_version": "threshold_v1"
}
```

### 14.2 Replay Outputs

```json
{
  "replay_id": "replay-uuid",
  "original_decision_id": "dec-uuid",
  "replayed_action": "redact",
  "replayed_reason_code": "confidential_enterprise_data_external_boundary",
  "matched_policy_ids": ["enterprise_external_disclosure_policy"],
  "consistency": "match | mismatch | partial",
  "diff": []
}
```

### 14.3 Replay Non-goals

MVP replay does not reproduce:

* model token generation;
* detector raw inference;
* RAG ranking;
* external tool response;
* human reviewer reasoning.

***

## 15. Tool / MCP Security v1.5

v1.4 states that MVP Tool Security focuses on Tool Pre-Execution Decision, Tool Metadata Snapshot, Confirmation Binding, Schema Hash Drift Detection, and Approval Invalidation. 

### 15.1 ToolActionContext

```json
{
  "tool_action_id": "ta-uuid",
  "tool_id": "send_email",
  "server_id": "mcp-email-server-prod",
  "tool_version": "1.2.0",
  "manifest_hash": "sha256:...",
  "schema_hash": "sha256:...",
  "description_hash": "sha256:...",
  "permission_class": "external_send",
  "trust_state": "approved | pinned | drifted | revoked | unknown",

  "action": {
    "operation": "send",
    "parameters_hash": "sha256:...",
    "target_resource_id": "email-recipient-hash",
    "destination_boundary": "external"
  },

  "data": {
    "sensitivity": "confidential",
    "data_asset_type": "customer_contract"
  },

  "approval_state": {
    "approval_id": "optional",
    "binding_hash": "optional",
    "approved_at": "optional",
    "expires_at": "optional"
  }
}
```

### 15.2 Tool Metadata Snapshot

v1.4 already includes Tool Metadata Snapshot fields such as tool\_id, server\_id, tool\_version, manifest\_hash, schema\_hash, description\_hash, permission\_class, trust\_state, owner, and last\_reviewed\_at. v1.5 formalizes this as registry-backed immutable snapshot per decision. 

### 15.3 Confirmation Binding

v1.4 requires human confirmation to bind tool\_id, server\_id, manifest\_hash, schema\_hash, action parameters hash, target resource, destination boundary, time window, and approver identity. 

v1.5 binding hash:

```text
binding_hash = hash(
  tool_id,
  server_id,
  manifest_hash,
  schema_hash,
  parameters_hash,
  target_resource_id,
  destination_boundary,
  approver_id,
  approval_time_window
)
```

### 15.4 Approval Invalidation

```text
If schema_hash changes after approval → invalidate approval.
If manifest_hash changes after approval → invalidate approval.
If parameters_hash changes after approval → invalidate approval.
If target_resource_id changes after approval → invalidate approval.
If destination_boundary changes after approval → invalidate approval.
If approval expires → invalidate approval.
```

### 15.5 Tool Trust State Rules

| Trust State | Behavior                                                    |
| ----------- | ----------------------------------------------------------- |
| approved    | evaluate normal policy                                      |
| pinned      | require exact hash match                                    |
| drifted     | require\_confirmation or deny                               |
| revoked     | deny                                                        |
| unknown     | require\_review or deny for privileged/write/external\_send |

***

## 16. Runtime APIs v1.5

## 16.1 Decision Evaluation API

```http
POST /v1/decisions:evaluate
```

### Request

```json
{
  "context": {},
  "signals": [],
  "mode": "shadow | canary | prod",
  "options": {
    "require_evidence_commit": true,
    "timeout_ms": 300
  }
}
```

### Response

```json
{
  "decision": {},
  "evidence_commit_status": "committed | pending | failed",
  "latency_ms": 123
}
```

### Idempotency

Clients must include:

```text
trace_id + request_id + stage
```

The server must return the same decision for the same idempotency key if all version bindings are unchanged.

***

## 16.2 Evidence Commit API

```http
POST /v1/evidence:commit
```

```json
{
  "trace_id": "trace-uuid",
  "decision_id": "dec-uuid",
  "evidence": {}
}
```

***

## 16.3 Policy Dry-run API

```http
POST /v1/policies:dryRun
```

```json
{
  "policy_bundle_version": "candidate",
  "evaluation_set_id": "privacy_output_control_v1",
  "mode": "shadow"
}
```

***

## 16.4 Decision Replay API

```http
POST /v1/replay:decision
```

```json
{
  "decision_id": "dec-uuid",
  "replay_binding": {}
}
```

***

## 16.5 Release Gate API

```http
POST /v1/release-gates:evaluate
```

```json
{
  "gate_id": "privacy_output_control_release_gate_v1",
  "target": {
    "target_type": "policy_update | detector_update | threshold_update | tool_metadata_update | approval_workflow_update",
    "target_id": "string",
    "from_version": "string",
    "to_version": "string"
  },
  "artifacts": {
    "offline_eval_report_ref": "string",
    "replay_regression_report_ref": "string",
    "policy_diff_report_ref": "string",
    "evidence_sampling_report_ref": "string",
    "latency_report_ref": "string"
  }
}
```

***

## 17. Evaluation v1.5

v1.4 states that evaluation must assess control effectiveness, not only detector accuracy. It asks whether the system made the right control decision, enforced the correct action, generated sufficient evidence, and would pass production release gate. 

### 17.1 Evaluation Dimensions

```text
risk family: SEC, SAF, PRIV, REL, COMP
stage: input, retrieval, tool_pre_execution, output
action: allow, deny, redact, require_confirmation, require_review, restrict_scope
environment: shadow, canary, prod
```

v1.4 already defines evaluation by risk family, stage, action, and environment. 

### 17.2 Metrics

| Metric                     | Meaning                                 |
| -------------------------- | --------------------------------------- |
| risk\_family\_recall       | ability to catch target risk            |
| risk\_family\_precision    | quality of risk detection/control       |
| action\_correctness        | whether action matches expected control |
| reason\_correctness        | whether reason\_code is correct         |
| evidence\_completeness     | required evidence present               |
| replay\_consistency        | decision replay matches original        |
| p95\_decision\_latency\_ms | runtime latency                         |
| false\_positive\_rate      | unnecessary intervention                |
| false\_negative\_rate      | missed control                          |
| confirmation\_burden       | human confirmation overhead             |
| policy\_behavior\_drift    | behavior delta after policy update      |

v1.4 already lists per-risk-family recall/precision, per-stage action correctness, false positive/false negative rate, decision latency, evidence completeness, replay-lite consistency, confirmation burden, and policy behavior drift as MVP metrics. 

***

## 18. Release Gate v1.5

v1.4 defines Release Gate objects as policy update, detector version update, threshold update, tool metadata baseline change, and approval workflow change. 

### 18.1 Gate Target Types

```text
policy_update
detector_update
threshold_update
tool_metadata_update
approval_workflow_update
fusion_config_update
stage_action_matrix_update
```

### 18.2 Gate Decision Schema

```json
{
  "gate_evaluation_id": "gate-eval-uuid",
  "gate_id": "privacy_output_control_release_gate_v1",
  "target": {
    "target_type": "policy_update",
    "target_id": "enterprise_external_disclosure_policy",
    "from_version": "1.0.0",
    "to_version": "1.1.0"
  },

  "metrics": {
    "privacy_recall": 0.97,
    "privacy_precision": 0.88,
    "false_positive_rate": 0.06,
    "evidence_completeness": 0.99,
    "replay_consistency": 0.995,
    "p95_decision_latency_ms": 240
  },

  "policy_diff_risk": "low | medium | high | critical",
  "blast_radius": {
    "affected_stages": ["output"],
    "affected_actions": ["redact"],
    "affected_apps": ["*"]
  },

  "decision": "pass | pass_with_warning | block | shadow_only | canary_only | rollback_required",

  "required_followups": [
    "monitor false positive rate in canary"
  ]
}
```

v1.4 already lists gate outputs as pass, pass\_with\_warning, block, shadow\_only, canary\_only, and rollback\_required. 

***

## 19. Golden Scenarios v1.5

v1.4 defines three golden scenarios: Enterprise Data Leakage Output Control, Prompt Injection Input / Retrieval Control, and Tool Pre-Execution Confirmation. v1.5 keeps them but adds engineering acceptance criteria. 

***

### Scenario 1: Enterprise Data Leakage Output Control

#### Flow

```text
User asks AI to summarize a customer contract.
Model output contains confidential contract terms.
Destination is external.
Output detector emits enterprise_data_leakage signal.
Fusion upgrades risk to high or critical.
Policy matches confidential enterprise data crossing external boundary.
Decision = redact.
Enforcement redacts output.
Evidence package is committed.
Evaluation record is emitted.
Release gate consumes evaluation result.
```

#### Expected Decision

```json
{
  "stage": "output",
  "action": "redact",
  "reason_code": "confidential_enterprise_data_external_boundary",
  "evidence_required": true,
  "audit_required": true
}
```

#### DoD

* Decision Contract generated.
* Redaction applied through Enforcement Adapter.
* Evidence completeness ≥ configured gate threshold.
* Replay-lite reproduces same action and reason\_code.
* Evaluation record includes action\_correctness and evidence\_completeness.

***

### Scenario 2: Prompt Injection Input / Retrieval Control

#### Flow

```text
RAG retrieves an external document.
Document contains hidden instruction attempting to override system policy.
Prompt injection detector emits signal.
Source trust detector marks source as untrusted.
Fusion produces high SEC risk.
Policy restricts retrieval scope or requires review.
Evidence captures span and source metadata.
```

#### Expected Decision

```json
{
  "stage": "retrieval",
  "action": "restrict_scope",
  "reason_code": "untrusted_retrieval_prompt_injection",
  "evidence_required": true
}
```

#### DoD

* Retrieved span is captured.
* Source trust metadata is included.
* Restricted context excludes malicious instruction.
* Decision is replayable without rerunning retrieval ranking.
* Policy dry-run can compare restrict\_scope vs require\_review behavior.

***

### Scenario 3: Tool Pre-Execution Confirmation

#### Flow

```text
Agent attempts to call send_email.
Recipient is external.
Content contains confidential customer data.
Tool schema hash matches registered version.
Policy requires explicit confirmation.
Approval binds tool identity, schema, parameters, target, destination, and time window.
Decision and approval binding are recorded.
```

v1.4 already gives this scenario and expected outcome. 

#### Expected Decision

```json
{
  "stage": "tool_pre_execution",
  "action": "require_confirmation",
  "reason_code": "external_tool_action_with_sensitive_data",
  "approval_binding_required": true
}
```

#### DoD

* Tool metadata snapshot is included.
* Binding hash is generated.
* Confirmation is invalidated if schema or parameter hash changes.
* Enforcement does not call tool before confirmation.
* Replay-lite reproduces require\_confirmation decision.

***

## 20. Failure Modes and Degraded Behavior

### 20.1 Detector Timeout

| Context                                 | Behavior                          |
| --------------------------------------- | --------------------------------- |
| low-risk input, shadow                  | audit\_only                       |
| confidential data, external destination | require\_review                   |
| privileged tool action                  | deny or require\_review           |
| prod output stage                       | fail according to policy fallback |

### 20.2 Policy Runtime Error

| Environment    | Behavior                     |
| -------------- | ---------------------------- |
| shadow         | audit\_only + error evidence |
| canary         | require\_review              |
| prod high-risk | deny                         |
| prod low-risk  | policy fallback              |

### 20.3 Evidence Commit Failure

| Risk     | Behavior                                |
| -------- | --------------------------------------- |
| low      | proceed + retry async                   |
| medium   | proceed only if minimal evidence exists |
| high     | require\_review                         |
| critical | block or deny                           |

### 20.4 Registry Miss

| Object                | Behavior                                    |
| --------------------- | ------------------------------------------- |
| unknown tool + read   | require\_review                             |
| unknown tool + write  | deny                                        |
| unknown MCP server    | deny unless allowlisted by emergency policy |
| unknown policy bundle | fail closed in prod                         |

***

## 21. Developer Implementation Modules

### 21.1 Required MVP Services

| Service                  | Responsibility                  |
| ------------------------ | ------------------------------- |
| Context Normalizer       | build Context Snapshot          |
| Signal Adapter           | normalize detector output       |
| Fusion Engine            | deterministic risk aggregation  |
| Policy Runtime           | evaluate policy bundle          |
| Decision Service         | create Decision Contract        |
| Enforcement Adapter      | execute decision action         |
| Evidence Service         | commit and enrich evidence      |
| Replay Service           | decision-level replay           |
| Evaluation Harness       | compute control metrics         |
| Release Gate Service     | evaluate release eligibility    |
| Tool Registry            | store tool metadata snapshots   |
| Approval Binding Service | bind and validate confirmations |

***

## 22. Ownership Model

| Component                | Primary Owner             | Integration Owner          |
| ------------------------ | ------------------------- | -------------------------- |
| Context Schema           | Tianmu / Control Plane    | xCloud runtime             |
| Signal Contract          | Tianmu / Control Plane    | detector providers         |
| Detector Implementations | DTL / RoW / partner teams | Signal Adapter owner       |
| Fusion Engine            | Tianmu / Control Plane    | Evaluation owner           |
| Policy Runtime           | Tianmu / Control Plane    | Governance owner           |
| Decision Contract        | Tianmu / Control Plane    | all adapters               |
| Enforcement Adapter      | xCloud / app runtime      | Tianmu contract owner      |
| Evidence Service         | Tianmu / platform         | compliance / audit         |
| Evaluation Harness       | Tianmu / evaluation       | detector and policy owners |
| Release Gate             | Tianmu + governance       | release owner              |
| Tool Registry            | platform / MCP owner      | Tianmu Tool Security       |
| Approval Binding         | platform / UX owner       | Tool Security owner        |

***

## 23. Sprint-Level Engineering Plan

### Sprint 1 — Contract Foundation

**Deliverables**

* Context Schema v1.5
* Signal Schema v1.5
* Decision Contract v1.5
* Stage × Action Matrix v1.5
* Policy Schema v1.5 draft

**DoD**

* JSON schema validation passes.
* Stage/action linting implemented.
* Three golden scenarios have static fixtures.
* Decision Contract can be generated from mock context/signals.

***

### Sprint 2 — Runtime Decision MVP

**Deliverables**

* `POST /v1/decisions:evaluate`
* deterministic fusion v1
* policy evaluator v0
* enforcement mock adapter
* evidence minimal commit

**DoD**

* Golden Scenario 1 produces redact decision.
* Golden Scenario 2 produces restrict\_scope or require\_review.
* Golden Scenario 3 produces require\_confirmation.
* All decisions include reason\_code and replay\_binding.

***

### Sprint 3 — Tool Pre-Execution Slice

**Deliverables**

* ToolActionContext
* Tool Metadata Snapshot
* Approval Binding Service
* schema/manifest drift detection
* confirmation invalidation rule

**DoD**

* Tool call blocked until confirmation when required.
* Schema drift invalidates prior approval.
* Revoked tool always denies.
* Unknown privileged tool denies or requires review.

***

### Sprint 4 — Evidence / Replay / Evaluation

**Deliverables**

* Evidence Package v1.5
* replay-lite API
* evaluation card
* action correctness metric
* evidence completeness metric

**DoD**

* Replay reproduces same decision action for all golden scenarios.
* Evidence completeness score generated.
* Evaluation report includes per-stage and per-risk-family metrics.

***

### Sprint 5 — Release Gate MVP

**Deliverables**

* Release Gate API
* policy dry-run
* policy diff report
* replay regression report
* gate decision report

**DoD**

* Policy update can be blocked by failed gate.
* Canary-only gate decision supported.
* Rollback-required decision supported.
* Gate output binds to evidence and evaluation artifacts.

***

## 24. Non-functional Requirements

| Requirement               | Target                                                   |
| ------------------------- | -------------------------------------------------------- |
| p95 decision latency      | configurable; initial target ≤ 300 ms for non-judge path |
| decision API availability | production-grade target defined by hosting platform      |
| evidence minimal commit   | synchronous for high-risk decisions                      |
| replay determinism        | decision-level match for same snapshots                  |
| policy evaluation         | deterministic                                            |
| policy update             | versioned and rollbackable                               |
| schema compatibility      | backward compatible within major version                 |
| auditability              | every enforced action maps to decision\_id               |
| observability             | per-stage latency, action distribution, error rate       |
| privacy                   | evidence preview must support redaction                  |

***

## 25. Security Considerations

### 25.1 Control Plane Integrity

* Decision Contract should be signed or hashed.
* Policy bundle version must be immutable after release.
* Tool metadata snapshot must be immutable per decision.
* Evidence must include integrity hash.
* Replay must use exact version bindings.

### 25.2 Privilege Boundary

* Control Plane does not replace IAM.
* Control Plane consumes IAM context and enterprise labels.
* Tool execution remains under tool runtime authorization.
* Control Plane decides AI-mediated authorization constraints.

### 25.3 Prompt Injection Boundary

* Untrusted retrieved content must not be allowed to override system policy.
* Retrieved content should be annotated with trust state.
* Tool planning should not consume untrusted instructions as authority.

### 25.4 Human Confirmation Boundary

* Confirmation must bind concrete action, not vague intent.
* Confirmation expires.
* Confirmation invalidates on schema, manifest, parameter, target, or destination drift.

***

## 26. Open Questions for v1.5 Engineering Review

v1.4 already lists open questions around xCloud integration point, detector ownership, enterprise labels, policy engine, latency, evidence retention, release gate owner, first demo scenario, shadow mode, and rollback mechanism. v1.5 refines them into implementation decisions: 

1. Is first xCloud integration point AI Gateway, app middleware, MCP proxy, or service mesh?
2. What enterprise data labels are available at runtime?
3. Which detectors are P0 dependencies and which are optional signals?
4. What is the production p95 decision latency target by stage?
5. Is evidence storage owned by Tianmu, platform, or compliance infrastructure?
6. What is the first release gate owner?
7. Which golden scenario is the executive demo path?
8. Is shadow mode read-only audit, or does it also compute hypothetical enforcement?
9. What rollback mechanism exists for policy bundle update?
10. What is the first supported MCP server / tool class?
11. Is confirmation UX owned by xCloud, platform, or security team?
12. What is the minimum enterprise data taxonomy for MVP?
13. What is the source of tool registry truth?
14. What must be exported to audit/compliance systems?

***

## 27. Final v1.5 Positioning

v1.5 positions the system as:

```text
Enterprise AI Runtime Authorization & Trust Control Plane
```

The key product claim is:

```text
We do not build another detector.
We build the control-plane layer that turns heterogeneous AI risk signals
into policy-grounded, enforceable, auditable, replayable,
and release-gated runtime decisions.
```

The key engineering moat is:

```text
Context Schema
+ Signal Contract
+ Stage × Action Matrix
+ Policy Runtime Semantics
+ Decision Contract
+ Evidence Package
+ Replay-lite
+ Release Gate
+ Tool Pre-Execution Security Contract
```

The key MVP implementation strategy is:

```text
Contract First
Vertical Slice First
Decision-Level Replay First
Registration-Based Inventory First
Tool Pre-Execution as Agent-Readiness Bridge
Release Gate Built In
```

The v1.5 architecture should be considered ready for:

* developer review;
* API contract discussion;
* sprint planning;
* xCloud integration alignment;
* detector-provider onboarding;
* policy authoring;
* evaluation harness implementation;
* release gate pipeline design.

***

## 28. One-line Summary

**v1.5 将 Enterprise AI Security 从 v1.4 的架构基线进一步推进为工程可执行的 Runtime Security Control Plane：以严格的 Context / Signal / Fusion / Policy / Decision / Enforcement / Evidence / Replay / Gate 合同为核心，优先打穿 Input、Retrieval、Output、Tool Pre-Execution 四个 MVP stage，并通过 Tool Metadata Snapshot、Confirmation Binding、Replay-lite 和 Release Gate 建立面向 Agentic Enterprise AI 的长期安全控制面护城河。**
