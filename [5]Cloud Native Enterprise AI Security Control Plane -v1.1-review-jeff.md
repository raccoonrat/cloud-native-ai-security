下面给出一个**面向[\[5\]Cloud Native Enterprise AI Security Control Plane -v1.1.md] 的具体修订方法**：不是把 Jeff 的问题逐条贴进设计书，而是把这些问题抽象为 **Cloud Native Enterprise AI Security Control Plane 的可复用控制能力**，沉淀到 stage、context、tool risk、policy、decision、trace/evidence、release gate、SRE 等工程结构中。该文档当前已经具备核心骨架：统一 `stage`、`Action`、`RiskFamily`、Tool Pre-Execution、Tool Risk Schema、Policy Runtime、Decision Engine、Trace/Evidence、Evaluation/Release Gate、SRE Runbook 等关键模块，因此修订重点应是**补齐 MCP / tool / transport / certificate / explicit confirmation 的运行时语义**，而不是另起一套 MCP 安全设计。 

***

# 一、总修订原则：把 Jeff 的具体问题抽象成 6 类控制能力

Jeff 的问题表面上是 MCP + XClarity One 的实现细节：Northbound API authentication、HTTPS/self-signed certificate、input validation、rate limit、prompt injection、observability。真正应该抽象进当前设计的是以下 6 类能力：

| Jeff 问题                             | 应抽象成的控制能力                                                  | 应修订位置                                                      |
| ----------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- |
| Northbound API auth / public key    | **Tool-to-API Trust Chain / Service Identity Binding**     | §0、§5 Context、§6.3 Tool Enforcement、§10 API                |
| 是否只依赖 Northbound API security       | **AI-mediated Execution Boundary**                         | §2 Scope、§3 Principles、§6 Enforcement                      |
| MCP server 层额外控制                    | **Tool Pre-Execution Policy Enforcement Point**            | §6.3、§10.2、§11、§16 P2                                      |
| self-signed cert / HTTPS            | **Transport Trust & Certificate Policy**                   | §14 Security & Compliance、§15 Observability、§20 Acceptance |
| input validation / prompt injection | **Instruction/Data Separation + Tool Argument Validation** | §5 Detector/Signal、§6.3、§7 Policy、§8 Decision              |
| rate limit / logging                | **Risk-based Runtime Control + Audit Evidence**            | §13 Reliability、§15 Observability、§7 Trace                 |

当前文档已经明确：系统不是单点 detector，而是把 Enterprise AI 请求中的上下文、输入、检索内容、工具调用、模型输出、检测信号、策略、审计证据和发布门禁统一到可编排、可评估、可追溯、可回放的运行时体系中。这个定位非常适合承接 Jeff 的 MCP 问题。 

***

# 二、建议修订 1：新增 “MCP / Tool-Calling Security Boundary” 小节

## 位置建议

放在：

```text
## 2. System Scope
```

之后新增：

```text
### 2.3 MCP / Tool-Calling Security Boundary
```

## 修订目的

当前文档已经覆盖 Tool Abuse、Unauthorized Access、Unsafe Automation 等风险族，也有 `tool_pre_execution` stage 和 Tool Risk Schema。 但还需要明确一个原则： 

> MCP 不是简单 API wrapper，而是 AI-mediated execution boundary。

这句话能把 Jeff 的“能否只依赖 Northbound API security”抽象成系统设计原则。

## 可直接加入的文本

```markdown
### 2.3 MCP / Tool-Calling Security Boundary

MCP / tool-calling integration must be treated as an AI-mediated execution boundary, not as a thin wrapper over existing enterprise APIs.

Existing backend API security, such as Northbound API authentication, authorization, parameter validation, TLS, and rate limiting, remains necessary but is not sufficient. The MCP/tool layer introduces additional runtime risks:

- natural-language intent may be incorrectly translated into API calls;
- prompt injection may influence tool selection or tool arguments;
- external or retrieved content may contain malicious instructions;
- high-impact operations may be triggered without explicit user confirmation;
- tool metadata, tool schema, or tool output may become part of an unsafe agent loop;
- the same API operation may have different risk depending on user, tenant, data classification, region, tool, and resource scope.

Therefore, all MCP/tool-mediated operations must pass through the Cloud Native Enterprise AI Security Control Plane before execution, especially at `tool_pre_execution` and `agent_step_check` stages.

The control plane is responsible for:

- binding user, client, MCP server, tool, API, and resource identity;
- validating tool arguments and instruction provenance;
- classifying tool side effects and blast radius;
- applying policy-driven authorization and approval requirements;
- enforcing explicit confirmation for disruptive actions;
- generating trace and evidence for audit and replay.
```

***

# 三、建议修订 2：扩展 `RiskFamily`，加入 Transport / Credential / Confirmation 相关风险

## 当前问题

当前 `RiskFamily` 已包含：

* `PROMPT_INJECTION`
* `TOOL_ABUSE`
* `UNAUTHORIZED_ACCESS`
* `UNSAFE_AUTOMATION`
* `SYSTEM_FAILURE`
* `EVIDENCE_GAP`

这些已经能覆盖 Jeff 的大部分问题。 但 HTTPS/self-signed certificate、public key/env var、confirmation bypass 等问题需要更精细的风险族或风险类型。 

## 建议最小修改

不要大幅扩展一级 RiskFamily，避免 enum 膨胀。建议保留现有 `RiskFamily`，在 `risk_type` 层扩展。只新增一个一级风险族即可：

```yaml
RiskFamily:
  - TRANSPORT_TRUST_RISK
```

## 修改位置

在：

```text
### 0.3 Canonical Severity / RiskFamily Enum
```

和：

```text
### 11.1 Risk Family Taxonomy
```

中加入：

```yaml
TRANSPORT_TRUST_RISK
```

## 对应 risk\_type 建议

```yaml
TRANSPORT_TRUST_RISK:
  - SELF_SIGNED_CERT_IN_PRODUCTION
  - CERTIFICATE_CHAIN_UNTRUSTED
  - CERTIFICATE_EXPIRED
  - TLS_VERIFICATION_DISABLED
  - MISSING_MTLS_FOR_SERVICE_TO_SERVICE
  - CERTIFICATE_HOSTNAME_MISMATCH
  - WEAK_TLS_CONFIGURATION

UNAUTHORIZED_ACCESS:
  - MISSING_USER_IDENTITY_BINDING
  - MISSING_CLIENT_IDENTITY_BINDING
  - TOOL_PERMISSION_NOT_FOUND
  - RESOURCE_SCOPE_VIOLATION
  - NORTHBOUND_API_AUTH_CONTEXT_MISSING

TOOL_ABUSE:
  - UNSAFE_GENERIC_API_TOOL
  - TOOL_ARGUMENT_OUT_OF_SCHEMA
  - TOOL_ARGUMENT_FROM_UNTRUSTED_INSTRUCTION
  - HIGH_RISK_TOOL_WITHOUT_APPROVAL
  - DISRUPTIVE_ACTION_WITHOUT_CONFIRMATION

UNSAFE_AUTOMATION:
  - AGENT_DIRECT_EXECUTION_WITHOUT_PLAN
  - MULTI_STEP_TOOL_CHAIN_WITHOUT_POLICY_CHECK
  - CONFIRMATION_ACTION_MISMATCH
```

这样做的好处是：Jeff 的每个问题都能进入统一 Signal → Fusion → Policy → Decision，而不是散落在 MCP 实现说明里。

***

# 四、建议修订 3：把 Northbound API auth 抽象为 “Tool-to-API Trust Chain”

## 当前文档基础

当前 Context Builder 已有字段权威源矩阵，明确 `user_id` 来自 auth token，`app_id` 来自 app registry / mTLS client identity，`tool_permission` 来自 tool registry + IAM。 这正好可以扩展为 MCP trust chain。 

## 修改位置

在：

```text
##### Context Field Authority Matrix
```

之后新增：

```text
##### Tool-to-API Trust Chain Context
```

## 可直接加入的 contract

```json
{
  "tool_execution_context": {
    "mcp_client": {
      "client_id": "mcp_client_x",
      "client_identity_source": "client_certificate | oauth_client | app_registry",
      "trust_level": "trusted | enterprise_managed | external | unknown"
    },
    "mcp_server": {
      "server_id": "mcp_server_x",
      "server_identity_source": "mTLS | workload_identity | service_registry",
      "server_certificate_fingerprint_hash": "sha256_xxx"
    },
    "tool": {
      "tool_id": "xclarity_update_firmware",
      "tool_version": "1.0.0",
      "tool_registry_status": "approved | pending | revoked",
      "tool_manifest_hash": "sha256_xxx"
    },
    "northbound_api": {
      "api_id": "xclarity_northbound_api",
      "api_auth_method": "mTLS | signed_token | api_key | unknown",
      "api_identity_bound": true,
      "api_scope": ["inventory.read", "firmware.write"]
    },
    "resource": {
      "resource_type": "server | server_group | firmware_package",
      "resource_id_hash": "sha256_xxx",
      "tenant_scope": "same_tenant",
      "region": "CN"
    }
  }
}
```

## 设计解释

这能回答 Jeff 的 public key 问题：public key matching 只是 trust chain 的一环，不是完整 authorization。系统必须绑定：

```text
user → MCP client → MCP server → tool → Northbound API → resource → action
```

并且每一段都有 source、trust level、hash、scope、policy decision。

***

# 五、建议修订 4：扩展 Tool Risk Schema，覆盖 firmware update / server setting 这类运维操作

## 当前文档基础

当前文档已有 `Tool Risk Schema v0.1`，包含 `side_effect`、`reversibility`、`blast_radius`、`data_access`、`approval_policy`，并要求高风险工具具备 idempotency key、audit event、post-execution scan hook、rollback/compensation note；不可逆工具标记 `irreversible: true`。 这是非常好的基础，但 Jeff 的 XClarity One 场景需要新增 **operational infrastructure action** 维度。 

## 修改位置

在：

```text
##### Tool Risk Schema v0.1
```

中扩展 schema。

## 建议新增字段

```json
{
  "operation_profile": {
    "operation_domain": "infrastructure_management",
    "operation_type": "read_inventory | firmware_update | server_configuration | reboot | batch_operation",
    "disruptive": true,
    "requires_change_window": true,
    "requires_rollback_plan": true,
    "requires_explicit_user_confirmation": true,
    "requires_fresh_auth": true,
    "max_batch_size": 20,
    "allowed_execution_environment": ["staging", "prod_with_approval"]
  },
  "northbound_api_binding": {
    "api_id": "xclarity_northbound_api",
    "allowed_endpoints": [
      "/inventory/read",
      "/firmware/plan",
      "/firmware/execute"
    ],
    "disallowed_endpoints": [
      "*"
    ],
    "method_allowlist": ["GET", "POST"],
    "requires_api_scope": ["inventory.read", "firmware.write"]
  },
  "confirmation_policy": {
    "required": true,
    "confirmation_level": "explicit_text | approval_ticket | fresh_auth",
    "confirmation_must_bind": [
      "tool_id",
      "action",
      "target_resource",
      "target_version",
      "blast_radius",
      "user_id",
      "timestamp"
    ]
  }
}
```

## 为什么这样修订

这样 Jeff 的 disruptive action 问题就不再是“邮件中的建议”，而成为 Tool Registry 的结构化字段，进入 policy runtime 和 decision engine。当前文档已经强调 Tool registry 是 policy runtime 的输入，不得硬编码在 app 内。 

***

# 六、建议修订 5：新增 “Explicit Confirmation Contract”

## 当前问题

当前文档已有 `require_approval`，并说明它是 pending state，必须携带 `approval_ticket_id` 或 `approval_workflow_ref`。 但 Jeff 的问题是“如何确保 disruptive actions 不在没有 explicit acknowledgment 的情况下发生”。这不完全等于 approval，因为某些场景可能不需要经理审批，但一定需要用户明确确认。 

## 关键设计判断

建议区分：

```text
confirmation ≠ approval
```

* **confirmation**：用户确认自己要执行该动作；
* **approval**：第三方或审批流批准该动作。

因此需要新增 `require_confirmation` action，或者不新增 action、将其建模为 `require_approval` 的子类型。

## 推荐方案

为了避免破坏现有 Action Enum，建议暂时不新增 action，而是在 `require_approval` 中增加 `approval_type`：

```yaml
approval_type:
  - explicit_user_confirmation
  - manager_approval
  - change_ticket
  - security_review
  - fresh_auth
```

## 修改位置

在：

```text
### 0.2 Canonical Action Enum 与分类
```

中补充说明：

```markdown
`require_approval` covers both human approval and explicit user confirmation. The concrete requirement must be specified by `approval_type`.
```

## 修改 Decision Contract

在标准 Decision Contract 中新增：

```json
"required_approval": {
  "approval_type": "explicit_user_confirmation",
  "confirmation_challenge": {
    "action": "firmware_update",
    "target_resource_hash": "sha256_xxx",
    "target_version": "fw_1.2.3",
    "impact_summary": "possible service interruption",
    "confirmation_phrase": "CONFIRM firmware update for selected server group",
    "expires_at": "2026-06-16T10:00:00+08:00",
    "action_hash": "sha256_action_binding"
  }
}
```

## 增加工程红线

放入：

```text
## 19. Critical Engineering Rules
```

新增：

```markdown
### 19.8 不允许高风险工具缺少显式确认

For disruptive or irreversible tool operations, such as firmware update, reboot, server configuration change, data export, or batch infrastructure operation, the decision engine MUST return `require_approval` with `approval_type=explicit_user_confirmation` or stronger approval type before execution.

A generic "yes" is not sufficient. Confirmation must bind action, target resource, user, tool, version/configuration, blast radius, timestamp, and action hash.
```

***

# 七、建议修订 6：把 self-signed certificate 问题抽象为 “Transport Trust Policy”

## 当前文档基础

当前文档 §14.2 只写了必须支持 in-transit TLS、at-rest encryption、KMS-managed keys、region-specific key 等。 这还不足以回答 Jeff 的 self-signed certificate 问题。 

## 修改位置

在：

```text
## 14. Security and Compliance
```

下新增：

```text
### 14.5 Transport Trust and Certificate Policy
```

## 可直接加入的文本

```markdown
### 14.5 Transport Trust and Certificate Policy

All MCP/tool-mediated service-to-service traffic must use TLS in production. For high-risk tool execution, mTLS or workload identity should be preferred where supported.

Self-signed certificates are only acceptable for isolated lab or PoC environments. They must not be used as the default production pattern. Production traffic must use a valid certificate chain issued by an approved public CA or enterprise/internal CA.

The control plane must classify certificate and transport failures as `TRANSPORT_TRUST_RISK` or `SYSTEM_FAILURE`, and must not silently allow high-risk tool execution when transport trust cannot be verified.

Minimum certificate validation requirements:

- certificate chain must be trusted;
- certificate must not be expired;
- hostname / SAN must match the endpoint;
- TLS verification must not be disabled in production;
- certificate fingerprint or workload identity should be recorded in trace for MCP/tool calls;
- certificate rotation and expiry monitoring must be supported.

For PoC environments, clients may explicitly trust a self-signed certificate or internal CA bundle. This must be marked as `environment=lab|poc` and must not pass production release gate.
```

## 对应 policy 示例

加入 §7 Policy DSL 示例：

```yaml
policy_id: pol_transport_trust_prod_block
version: 1.0.0
policy_type: global
scope: { region: "*", tenant_id: "*", app_id: "*" }
rules:
  - rule_id: rule_001
    priority: 250
    when:
      all:
        - { field: context.app.environment, op: eq, value: prod }
        - { field: stage, op: in, value: [tool_pre_execution, agent_step_check] }
        - { field: transport.certificate_trust_status, op: not_in, value: [trusted_ca, enterprise_ca] }
    then:
      action: block
      severity: high
      reason_code: PRODUCTION_TOOL_EXECUTION_REQUIRES_TRUSTED_TLS_CHAIN
    audit:
      evidence_required: true
      retention_class: security
```

***

# 八、建议修订 7：把 input validation 升级为 “Tool Argument Security Contract”

## 当前文档基础

当前文档已有 `tool_pre_execution` 检查项：tool identity、user authorization、argument risk、side effect level、data access scope、approval requirement、reversibility、business impact。 但还缺一个正式的 **Tool Argument Security Contract**，用于解决 Jeff 的“Northbound API 已经 sanitize，MCP tools 是否还要 sanitize”。 

## 修改位置

放在：

```text
### 6.3 Tool Pre-Execution Enforcement
```

中 `Tool Risk Schema v0.1` 之前或之后。

## 可直接加入的 schema

```json
{
  "tool_argument_security": {
    "schema_version": "tool-argument-security/v1",
    "argument_schema_valid": true,
    "argument_source": {
      "source_type": "direct_user_input | model_generated | rag_content | tool_output | external_content",
      "trust_level": "trusted | untrusted | unknown",
      "instruction_provenance": "user_instruction | external_data | derived"
    },
    "validation": {
      "type_check": "pass",
      "enum_check": "pass",
      "range_check": "pass",
      "resource_scope_check": "pass",
      "policy_check": "pass"
    },
    "unsafe_patterns": {
      "prompt_injection_signal": "none | suspected | blocked",
      "freeform_endpoint": false,
      "arbitrary_payload": false,
      "wildcard_resource_scope": false
    },
    "normalized_argument_hash": "sha256_xxx"
  }
}
```

## 新增工程规则

```markdown
Tool arguments sent to backend APIs must be structured, typed, schema-validated, and policy-validated. Raw natural language or retrieved external content must not be directly forwarded as API parameters for high-risk tools.

Backend API validation remains mandatory, but it is not a substitute for MCP/tool-layer validation.
```

***

# 九、建议修订 8：新增 “Instruction/Data Separation” 原则，系统化处理 prompt injection

## 当前文档基础

当前文档已经覆盖 `PROMPT_INJECTION`、`RAG_INJECTION`、`RAG Chunk Security Contract`、Prompt Injection Detector、RAG Injection Detector。 但 Jeff 的问题强调 tool-level prompt injection，因此需要在设计原则中增加一条更基础的原则。 

## 修改位置

在：

```text
## 3. Design Principles
```

新增：

```text
### 3.8 Instruction/Data Separation
```

## 可直接加入的文本

```markdown
### 3.8 Instruction/Data Separation

Enterprise AI security must explicitly separate instructions from data.

User instructions, system instructions, developer policies, retrieved documents, tool outputs, device logs, API responses, and external content must not be treated as the same trust class.

The control plane must assign instruction provenance and trust level to every content source. External content, retrieved context, device logs, and tool outputs are data by default. They must not be allowed to override system policy, tool policy, authorization policy, or approval requirements.

At `tool_pre_execution` and `agent_step_check`, the system must verify whether tool selection or tool arguments were influenced by untrusted content. If high-risk tool execution depends on untrusted instruction sources, the default action should be `block`, `escalate`, or `require_approval`, depending on policy.
```

***

# 十、建议修订 9：把 rate limit 从系统容量控制升级为 “Risk-Based Action Throttling”

## 当前文档基础

当前文档 §13 有 timeout budget、failure handling、fail-open/fail-closed；§15 有 metrics/alerts/SLO。 但没有把 rate limit 建模为策略化安全控制。Jeff 的问题不是普通 API rate limit，而是 MCP/agent 误调用或滥用导致的 operational blast radius。 

## 修改位置

在：

```text
## 13. Reliability and Fail-Safe Design
```

新增：

```text
### 13.4 Risk-Based Rate Limiting and Circuit Breaker
```

## 可直接加入的文本

```markdown
### 13.4 Risk-Based Rate Limiting and Circuit Breaker

MCP/tool-layer rate limiting must be risk-based and must not simply mirror the maximum backend API rate limit.

Rate limits should be evaluated by:

- user_id / user role;
- tenant_id;
- MCP client identity;
- MCP server identity;
- tool_id and tool risk level;
- action type;
- resource scope;
- environment;
- data classification;
- burst and sustained window.

Default posture:

| Tool / Action Type | Default Rate Limit Posture |
|---|---|
| read-only inventory query | higher limit |
| low-risk metadata update | moderate limit |
| configuration change | low limit + audit |
| firmware update / reboot | very low limit + explicit confirmation |
| broad batch operation | approval / change control / circuit breaker |

For high-risk tools, rate limit breach should generate a normalized signal:

- risk_family: `TOOL_ABUSE`
- risk_type: `TOOL_RATE_LIMIT_EXCEEDED`
- recommended_mitigation: `block` or `require_approval`

Circuit breaker must be enabled for repeated high-risk tool attempts, abnormal allow-rate increase, repeated confirmation failures, and tool execution loops.
```

***

# 十一、建议修订 10：扩展 Observability，覆盖 Jeff 的最小 logging 要求

## 当前文档基础

当前文档 §15.2 已要求日志不得包含原始敏感内容，必须包含 trace\_id、request\_id、tenant\_id hash、app\_id、policy\_snapshot\_id、decision action、reason code、latency、error code。 对 Jeff 的 MCP 场景，需要扩展 tool/MCP 字段。 

## 修改位置

在：

```text
### 15.2 Logs
```

补充字段。

## 建议新增字段

```markdown
For `tool_pre_execution`, `tool_post_execution`, `agent_plan_check`, and `agent_step_check`, logs must additionally include:

- mcp_client_id;
- mcp_server_id;
- tool_id;
- tool_version;
- tool_manifest_hash;
- tool_risk_level;
- operation_type;
- resource_scope_hash;
- northbound_api_id;
- northbound_api_endpoint_pattern;
- api_auth_method;
- transport_trust_status;
- certificate_fingerprint_hash where applicable;
- confirmation_required;
- confirmation_status;
- approval_type;
- action_hash for disruptive actions;
- prompt_injection_signal;
- rate_limit_decision;
- enforcement_result.
```

## 同步扩展 Trace

在 §7 Full Trace schema 中增加：

```json
"tool_execution": {
  "mcp_client_id": "mcp_client_x",
  "mcp_server_id": "mcp_server_x",
  "tool_id": "xclarity_update_firmware",
  "tool_version": "1.0.0",
  "tool_risk_level": "high",
  "operation_type": "firmware_update",
  "resource_scope_hash": "sha256_xxx",
  "northbound_api_id": "xclarity_northbound_api",
  "confirmation_required": true,
  "confirmation_status": "confirmed | missing | expired | not_required",
  "action_hash": "sha256_xxx"
}
```

***

# 十二、建议修订 11：把 Jeff 场景加入 Evaluation / Release Gate

## 当前文档基础

当前文档 §8 已要求 Evaluation 按 risk\_family、stage、action、data\_classification、region、tenant\_policy\_profile、detector\_version、policy\_snapshot\_id 切片；§9 要求 detector、policy、tool schema、RAG pipeline、decision engine 等变更进入 release gate。 这里需要新增 MCP/tool-specific gate。 

## 修改位置

在：

```text
### 8.3 Required Slices 与分层 Critical Metrics
```

新增 tool 维度：

```yaml
required_slices:
  - tool_id
  - tool_risk_level
  - operation_type
  - mcp_client_trust_level
  - transport_trust_status
  - confirmation_required
  - confirmation_status
```

## 新增 critical metrics

```yaml
critical_metrics:
  by_stage:
    tool_pre_execution:
      high_risk_tool_without_approval_rate_max: 0
      disruptive_action_without_confirmation_rate_max: 0
      tool_argument_schema_violation_block_rate_min: 1.0
      transport_untrusted_prod_allow_rate_max: 0
      minimal_trace_coverage: 1.0

  by_risk_family:
    TOOL_ABUSE:
      critical_miss_rate_max: 0.001
    TRANSPORT_TRUST_RISK:
      production_allow_rate_for_untrusted_cert_max: 0
    PROMPT_INJECTION:
      tool_level_injection_recall_min: 0.92
```

## Release Gate 新增阻断条件

放入 §9.4 自动回滚条件或 §9.2 Gate 示例：

```markdown
Additional release blocking conditions for MCP/tool integration:

- production tool execution allowed with untrusted/self-signed certificate;
- high-risk tool schema missing approval/confirmation policy;
- disruptive action can execute without action-bound confirmation;
- generic arbitrary API execution tool exposed to agent;
- tool argument schema validation bypass detected;
- tool execution trace missing tool_id, resource_scope_hash, policy_snapshot_id, or confirmation_status;
- high-risk tool execution lacks minimal trace coverage.
```

***

# 十三、建议修订 12：P0/P1/P2 实施计划应重新切分 MCP 相关内容

## 当前文档基础

当前 P0 只覆盖 `input_precheck` 和 `model_output_check`；P2 覆盖 tool/RAG/agent readiness，包括 tool pre-execution API、tool risk schema、require approval action、tool execution trace 等。 这个阶段划分合理，但 Jeff 的问题如果是当前合作机会，建议将 MCP 的最小咨询交付前移为 P1.5，而不是等完整 P2。 

## 建议新增 P1.5：MCP / Tool Security Readiness Slice

插入在 §16.2 和 §16.3 之间：

```markdown
### 16.2.5 P1.5: MCP / Tool Security Readiness Slice

目标：在不完整实现 Agent Security 的情况下，先为 MCP / tool-calling 场景提供最小可用安全控制。

Scope:
- stage: `tool_pre_execution`
- risks:
  - TOOL_ABUSE
  - UNAUTHORIZED_ACCESS
  - PROMPT_INJECTION
  - TRANSPORT_TRUST_RISK
  - UNSAFE_AUTOMATION
  - SYSTEM_FAILURE
- actions:
  - allow
  - block
  - require_approval
  - escalate
  - log_only

必须实现:
1. Tool-to-API Trust Chain Context
2. Tool Argument Security Contract
3. Tool Risk Schema extension for operational infrastructure tools
4. Transport Trust Policy
5. Explicit Confirmation Contract
6. Risk-based rate limiting metadata
7. Tool execution minimal trace
8. Policy rules for high-risk tool approval
9. Release gate checks for tool schema update

P1.5 Exit Criteria:
1. High-risk tool cannot execute without policy decision.
2. Disruptive action cannot execute without explicit confirmation.
3. Production tool execution cannot use untrusted/self-signed certificate.
4. Tool arguments must pass schema and resource-scope validation.
5. Tool execution decision must include trace_id, policy_snapshot_id, tool_id, resource_scope_hash, and reason_code.
6. Generic arbitrary API wrapper tools are blocked unless explicitly approved by policy.
```

这个 P1.5 对你当前与 Jeff / XClarity One 的沟通最有价值：它既不抢 XClarity One 实现责任，又能给出 DTL/Tianmu 的可落地安全架构贡献。

***

# 十四、把 Jeff 具体问题映射成设计书中的“修订落点”

下面是最关键的一张设计映射表，可作为你给 Yoni / Ofek / Jeff 解释的核心：

| Jeff 具体问题                                       | 设计书修订落点                                       | 抽象后的工程机制                                                                                      |
| ----------------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| MCP clients need matching Northbound public key | Context Builder + Tool-to-API Trust Chain     | public key 只是 trust signal；必须绑定 user/client/server/tool/API/resource/action                   |
| 只依赖 Northbound API security 是否足够                | System Scope + Design Principles              | MCP 是 AI-mediated execution boundary，需要 MCP-level enforcement                                 |
| MCP server 层应做什么                                | Tool Pre-Execution Enforcement                | policy enforcement point：authz、argument validation、risk、approval、trace                        |
| public key 放 env var 是否 OK                      | Security & Compliance + Release Gate          | PoC 可接受；production 应走 secret/cert management；release gate 阻断不合规配置                             |
| HTTPS + self-signed certificate                 | Transport Trust Policy                        | lab 可用显式 trust；production 必须 trusted CA chain，不能关闭验证                                          |
| Northbound API 已 sanitize 是否足够                  | Tool Argument Security Contract               | backend validation 必须保留，但 MCP 层要验证 intent、schema、source、scope、risk                            |
| MCP tool 是否 sanitize                            | Tool Pre-Execution + Policy                   | structured typed argument，不允许 raw NL 直接进高风险 API                                               |
| prompt injection                                | Instruction/Data Separation + Detector/Policy | 外部内容默认 data，不得变 instruction；高风险工具受 prompt injection 影响时 block/escalate/approval               |
| rate limit                                      | Risk-Based Rate Limiting                      | 按 user/tenant/client/tool/resource/action/risk 分级限流                                           |
| disruptive action confirmation                  | Explicit Confirmation Contract                | confirmation 绑定 action、target、impact、user、timestamp、hash                                      |
| logging bare minimum                            | Trace/Evidence + Observability                | tool\_id、risk、policy decision、confirmation、API result、transport trust、prompt injection signal |
| tool logging 是否 common                          | Minimal Production Acceptance Criteria        | 对 enterprise infrastructure tool 必须 mandatory audit logging                                   |

***

# 十五、最终建议：不要把它写成 “MCP Security Appendix”，而要变成控制平面 v1.2 的核心增强

我建议把当前文档从 v1.1 修订到 v1.2，标题可以是：

```text
Cloud Native Enterprise AI Security Control Plane v1.2
MCP / Tool-Calling Runtime Security Hardening
```

v1.2 的 revision summary 建议这样写：

```markdown
**V1.2 修订说明（MCP / Tool-Calling Runtime Security Hardening）**

本版基于 XClarity One / MCP integration 中暴露的 concrete security questions，将 MCP client/server、Northbound API、tool invocation、self-signed certificate、prompt injection、rate limit、explicit confirmation、tool observability 等具体问题抽象为 Cloud Native Enterprise AI Security Control Plane 的通用控制能力。

核心变更：
- 新增 MCP / Tool-Calling Security Boundary，明确 MCP 是 AI-mediated execution boundary。
- 新增 Tool-to-API Trust Chain Context，绑定 user、client、server、tool、API、resource、action。
- 扩展 Tool Risk Schema，覆盖 firmware update、server configuration、reboot、batch operation 等 infrastructure operations。
- 新增 Transport Trust and Certificate Policy，禁止 production 中默认使用 self-signed certificate 或关闭 TLS verification。
- 新增 Tool Argument Security Contract，要求工具参数 schema、source、scope、policy 全链路验证。
- 新增 Instruction/Data Separation 原则，防止外部内容、RAG 内容、tool output 变成可执行指令。
- 扩展 require_approval 语义，支持 explicit_user_confirmation、fresh_auth、change_ticket 等 approval_type。
- 新增 Risk-Based Rate Limiting and Circuit Breaker。
- 扩展 Trace / Observability 字段，覆盖 mcp_client、mcp_server、tool、northbound_api、confirmation、transport_trust。
- 新增 P1.5 MCP / Tool Security Readiness Slice，支持在完整 Agent Security 前先落地 tool_pre_execution 安全闭环。
```

***

# 十六、最重要的架构判断

最后给你一个可以作为文档开头或对外沟通的核心判断：

> Jeff 的问题不应被视为 XClarity One MCP 的局部实现问题，而应被视为 Enterprise AI 从“文本生成”进入“工具执行 / 运维控制面”后暴露出的第一批真实安全需求。  
> 对 Cloud Native Enterprise AI Security Control Plane 来说，这些问题应被抽象为：身份链路、传输信任、工具风险、参数可信度、显式确认、风险限流、审计证据和发布门禁。  
> 这样设计后，XClarity One 只是第一个落地场景；同一套控制能力未来可以复用于 xCloud、Token Hub、Enterprise Agent、RAG Tooling、AI Ops 和其他 agentic workflow。

这个修订方向和[\[5\]Cloud Native Enterprise AI Security Control Plane -v1.1.md] 当前的控制平面定位完全一致：它不是单个 detector，而是面向 xCloud、Token Hub、Enterprise AI、RAG、Tool Calling、Agentic Workflow 的云原生 AI 安全基础设施。 
