# Cloud Native Enterprise AI Security Control Plane

## 企业云原生 AI 安全控制平面完整设计书 V1.2

### MCP / Tool-Calling Runtime Security Hardening

**定位**：本文档面向工程团队、平台团队、安全团队、SRE 团队与产品集成团队，定义一套可直接落地实施的 **Cloud Native Enterprise AI Security Control Plane**。  
**目标**：为企业 AI 应用、RAG、Agent、Tool Calling、模型输出等运行时链路提供统一的安全决策、策略执行、证据审计、评估门禁与持续演进能力。

> **核心架构判断（MCP / Tool-Calling）**  
> MCP / tool-calling 暴露的具体安全问题（Northbound API 认证、self-signed certificate、input validation、prompt injection、rate limit、disruptive action confirmation、logging）不应被视为某个产品（如 XClarity One）MCP 集成的局部实现问题，而应被视为 Enterprise AI 从“文本生成”进入“工具执行 / 运维控制面”后暴露出的第一批真实安全需求。对本控制平面而言，它们应被统一抽象为：**身份链路（Trust Chain）、传输信任（Transport Trust）、工具风险（Tool Risk）、参数可信度（Argument Security）、显式确认（Explicit Confirmation）、风险限流（Risk-based Throttling）、审计证据（Evidence）与发布门禁（Release Gate）**。XClarity One 只是第一个落地场景；同一套控制能力可复用于 xCloud、Token Hub、Enterprise Agent、RAG Tooling、AI Ops 及其他 agentic workflow。

> **V1.1 修订说明（工程收敛）**  
> 本版根据首席架构师工程审阅意见，将 V1.0 的“完整架构蓝图”收敛为“强 contract + 强 runtime semantics + 强验收标准”的可实现工程规格，核心变更：
> 1. 统一 **Canonical Runtime Stage Enum**，废弃 `request_type` 作为策略匹配字段（见 §0.1）。
> 2. 将 Action 从“优先级排序”升级为 **Decision Action State Machine + stage×action 合法性矩阵**（见 §0.2 与 §5 Step 8）。
> 3. Trace 拆分为 **同步最小提交（Minimal Trace Commit）+ 异步证据补充**，杜绝“无 trace 决策”工程矛盾（见 §7）。
> 4. 将 Policy DSL 从示例升级为 **Policy DSL v0.1 正式语法**，支持 validate/lint/diff（见 §6 Step 7）。
> 5. 新增 **Context Field Authority Matrix**、**Detector Failure Signal Schema**、**RAG Chunk Security Contract**、**Tool Risk Schema v0.1**。
> 6. Evaluation 增加 **分层切片与按风险族/阶段的 critical metrics**；Release Gate 增加 **Integration Spec 与 Gate API**；Observability 增加 **SLO/错误预算与 SRE Runbook**。
> 7. 将 **P0 重定义为可跑通的 vertical slice**（input_precheck + model_output_check）。

> **V1.2 修订说明（MCP / Tool-Calling Runtime Security Hardening）**  
> 本版基于 MCP / Northbound API 集成中暴露的具体安全问题，将其抽象为控制平面的通用运行时能力，核心变更：
> 1. 新增 **MCP / Tool-Calling Security Boundary**，明确 MCP 是 AI-mediated execution boundary，而非 API thin wrapper（见 §2.3）。
> 2. 新增 **Instruction/Data Separation** 设计原则，防止外部内容 / RAG 内容 / tool output 变成可执行指令（见 §3.8）。
> 3. 新增一级风险族 **TRANSPORT_TRUST_RISK**，并在 `risk_type` 层扩展 transport / credential / confirmation 风险类型（见 §0.3、§11.1）。
> 4. 新增 **Tool-to-API Trust Chain Context**，绑定 user → MCP client → MCP server → tool → Northbound API → resource → action（见 §5 Step 2）。
> 5. 新增 **Tool Argument Security Contract**，并扩展 **Tool Risk Schema** 覆盖 firmware update / reboot / configuration / batch 等 infrastructure operations（见 §6.3）。
> 6. 新增 **Transport Trust and Certificate Policy**，禁止生产环境默认使用 self-signed certificate 或关闭 TLS 校验（见 §14.5）。
> 7. 扩展 **require_approval / approval_type**，支持 `explicit_user_confirmation`、`fresh_auth`、`change_ticket` 等，并新增 confirmation_challenge（见 §0.2、§5 Decision Contract、§19.8）。
> 8. 新增 **Risk-Based Rate Limiting and Circuit Breaker**（见 §13.4）。
> 9. 扩展 **Trace / Observability** 字段，覆盖 mcp_client、mcp_server、tool、northbound_api、confirmation、transport_trust（见 §7、§15.2）。
> 10. Evaluation / Release Gate 增加 tool 维度 slice、critical metrics 与 MCP 阻断条件（见 §8.3、§9）。
> 11. 新增 **P1.5 MCP / Tool Security Readiness Slice**，在完整 Agent Security 前先落地 `tool_pre_execution` 安全闭环（见 §16.2.5）。

***

# 0. Canonical Enums, Contracts and Runtime Semantics

> 本章是全文的“硬约束源”。所有模块（API、orchestrator、policy runtime、decision engine、trace、eval、replay、dashboard）只允许消费本章定义的 canonical enum 与 contract，不得各自维护方言。

## 0.1 Canonical Runtime Stage Enum

全系统只允许使用一个字段表达运行时阶段：`stage`。`request_type` 被废弃（`deprecated`），不得再用于策略匹配、trace 标签或 eval 标签。

```yaml
stage:
  enum:
    - input_precheck
    - rag_query_precheck
    - rag_retrieved_context_check
    - rag_context_assembly_check
    - tool_pre_execution
    - tool_post_execution
    - agent_plan_check
    - agent_step_check
    - model_output_check
    - batch_eval

request_type: deprecated   # 仅作兼容映射，禁止用于策略/trace/eval 匹配
```

约束：
* 所有 API request/response 中只出现 `stage`。
* 所有 policy DSL 的 `when.stage` 使用本 enum。
* 所有 trace/eval/replay 数据集 `stage` 字段一致。
* CI 中加入 schema test：发现非 enum stage 直接 fail。

## 0.2 Canonical Action Enum 与分类

```yaml
Action:
  - allow
  - log_only
  - warn
  - redact
  - block
  - escalate
  - require_approval
  - rewrite
  - remove_chunk
  - reduce_rank
  - safe_complete

action_classes:
  terminal_actions:        # 产生最终结果
    - allow
    - block
    - safe_complete
  transform_actions:       # 改写内容后继续流转
    - redact
    - rewrite
    - remove_chunk
    - reduce_rank
  human_or_async_actions:  # 非 terminal，需人工或异步收敛
    - warn
    - escalate
    - require_approval
  observability_actions:
    - log_only
```

> 说明：原 Output Enforcement 中出现的 `regenerate` 统一收敛为 `rewrite`（见 §6.4）。`require_approval` 是 pending state，不是 terminal decision，必须携带 `approval_ticket_id` 或 `approval_workflow_ref` 方可返回业务方。

> **`require_approval` 同时覆盖人工审批与用户显式确认**（confirmation ≠ approval）。具体要求由 `approval_type` 指定，避免为“确认”新增独立 action 而破坏现有 enum：
> ```yaml
> approval_type:
>   - explicit_user_confirmation   # 用户确认自己要执行该动作
>   - manager_approval             # 第三方/经理审批
>   - change_ticket                # 变更工单
>   - security_review              # 安全审查
>   - fresh_auth                   # 重新认证/二次鉴权
> ```
> 对于 disruptive / irreversible 操作，`approval_type` 必须达到 `explicit_user_confirmation` 或更强等级，并携带 `confirmation_challenge`（见 §5 Decision Contract 与 §19.8）。

## 0.3 Canonical Severity / RiskFamily Enum

```yaml
Severity:
  - none
  - low
  - medium
  - high
  - critical

RiskFamily:
  - PROMPT_INJECTION
  - RAG_INJECTION
  - PII_LEAKAGE
  - ENTERPRISE_CONFIDENTIAL_LEAKAGE
  - IP_LEAKAGE
  - DATA_RESIDENCY_VIOLATION
  - TOOL_ABUSE
  - UNAUTHORIZED_ACCESS
  - UNSAFE_AUTOMATION
  - POLICY_VIOLATION
  - OUTPUT_UNSAFE_CONTENT
  - SOURCE_TRUST_RISK
  - MODEL_BEHAVIOR_ANOMALY
  - EVIDENCE_GAP
  - SYSTEM_FAILURE
  - TRANSPORT_TRUST_RISK
```

> 设计说明：为避免一级 RiskFamily enum 膨胀，MCP / tool / certificate / confirmation 相关风险仅新增 **一个**一级风险族 `TRANSPORT_TRUST_RISK`，其余在 `risk_type` 层扩展（见 §11.1）。这样 Jeff/MCP 的每个具体问题都能进入统一 Signal → Fusion → Policy → Decision 链路，而不是散落在 MCP 实现说明里。

## 0.4 Decision Determinism Rules（决策可复现规则）

replay consistency 成立的充要条件是 replay key 完整：

```text
Same request content hash
+ same context hash
+ same detector versions
+ same policy snapshot id
+ same fusion algorithm version
+ same decision engine version
= same decision
```

任何参与决策的版本（detector / fusion / decision engine）变更都必须纳入 replay key，否则 replay 不可判定。

## 0.5 Runtime Enforcement Mode（运行模式）

```yaml
enforcement_mode:
  monitor:
    decision_effect: no blocking, trace only        # 只记录，不拦截
  shadow:
    decision_effect: compare old/new policy, no production effect
  active:
    decision_effect: enforce allow/redact/block/approval
  canary:
    decision_effect: enforce for selected traffic only
```

## 0.6 Schema Versioning and Compatibility

所有 contract 必须带版本：

```json
{
  "schema_version": "decision-contract/v1",
  "runtime_version": "guardrail-runtime/1.0.0",
  "policy_snapshot_id": "ps_20260614_001"
}
```

兼容规则（决定是否可无 gate 发布）：

| 变更类型                    | 是否允许无 gate 发布 |
| ----------------------- | -------------:|
| add optional field      | yes           |
| add required field      | no            |
| remove field            | no            |
| enum add value          | conditional   |
| enum remove value       | no            |
| action semantics change | no            |
| stage semantics change  | no            |

***

# 1. Executive Summary

Cloud Native Enterprise AI Security Control Plane 是一套面向企业 AI 场景的运行时安全控制系统。

它不是一个单点 detector，也不是简单的 prompt filter，而是一个完整的 **AI 安全控制平面**：

> 将企业 AI 请求中的上下文、输入内容、检索内容、工具调用、模型输出、安全检测信号、策略规则、审计证据与发布门禁统一到一个可编排、可评估、可追溯、可回放的运行时体系中。

核心设计目标包括：

1. **统一控制**：为 Enterprise AI 的 input、RAG、tool、output 等关键节点提供统一安全决策。
2. **策略驱动**：通过 policy runtime 控制不同租户、区域、应用、角色、数据等级下的安全行为。
3. **多信号融合**：避免单一 detector 直接做最终判断，所有检测结果进入统一 signal fusion。
4. **可解释决策**：每一次 allow、warn、redact、block、escalate 都必须有 reason code、matched rules 和 evidence。
5. **审计级追溯**：所有决策生成 decision trace，可用于合规审计、问题复盘、offline replay 和 release gate。
6. **持续评估**：生产流量采样与离线 replay 共同驱动 precision、recall、false positive、false negative、latency 等指标。
7. **云原生可扩展**：系统以微服务、Kubernetes、sidecar/gateway/SDK 模式部署，支持多租户、多区域、多环境、多版本灰度发布。

***

# 2. System Scope

## 2.1 系统解决的问题

本系统解决 Enterprise AI 中以下典型风险：

| 风险类别                                 | 说明                   | 示例                                |
| ------------------------------------ | -------------------- | --------------------------------- |
| Prompt Injection                     | 用户或外部内容诱导模型绕过规则      | “Ignore previous instructions...” |
| RAG Injection                        | 检索文档中包含恶意指令          | 文档中隐藏 prompt 注入                   |
| PII Leakage                          | 输入或输出泄露个人信息          | 电话、身份证、地址、客户信息                    |
| Enterprise Confidential Data Leakage | 企业机密泄露               | 源码、合同、财务、路线图                      |
| IP Leakage                           | 知识产权、专利、算法、内部实现泄露    | 训练数据、内部架构、专有代码                    |
| Tool Abuse                           | 非授权工具调用、越权操作、危险参数    | 删除文件、发送邮件、访问敏感系统                  |
| Data Residency Violation             | 数据跨境、跨区域违规           | CN 数据出境                           |
| Policy Violation                     | 不同租户/区域/角色策略不一致导致违规  | 普通员工访问高敏数据                        |
| Unsafe Automation                    | Agent 多步自主行为失控       | 自动调用多个工具完成高风险操作                   |
| Compliance Evidence Gap              | 无法证明系统为何 allow/block | 缺少 trace、policy snapshot、evidence |

## 2.2 系统不解决的问题

本系统不是：

1. 不是模型训练安全平台。
2. 不是通用 IAM / RBAC 系统的替代品。
3. 不是企业 DLP 的完全替代品，而是 AI runtime 场景下的 DLP / guardrail 控制层。
4. 不是单一内容审核服务。
5. 不是只针对个人 AI 助手的轻量 guardrail，而是面向企业 AI 平台的控制平面。
6. 不是只依赖 LLM Judge 的安全系统。

## 2.3 MCP / Tool-Calling Security Boundary

MCP / tool-calling 集成必须被视为 **AI-mediated execution boundary（AI 中介执行边界）**，而不是对既有企业 API 的薄封装（thin wrapper）。

既有后端 API 安全（如 Northbound API 认证、授权、参数校验、TLS、限流）**仍然必要，但并不充分**。MCP / tool 层引入了额外的运行时风险：

- 自然语言意图可能被错误地翻译为 API 调用；
- prompt injection 可能影响工具选择或工具参数；
- 外部或检索内容可能携带恶意指令；
- 高影响操作可能在缺少用户显式确认的情况下被触发；
- tool metadata / tool schema / tool output 可能成为不安全 agent loop 的一部分；
- 同一 API 操作在不同 user / tenant / data classification / region / tool / resource scope 下风险不同。

因此，所有 MCP / tool-mediated 操作在执行前必须经过 Cloud Native Enterprise AI Security Control Plane，尤其是在 `tool_pre_execution` 与 `agent_step_check` 阶段。控制平面负责：

- 绑定 user、client、MCP server、tool、API、resource 身份（见 §5 Tool-to-API Trust Chain Context）；
- 校验工具参数与指令来源可信度（见 §6.3 Tool Argument Security Contract）；
- 对工具 side effect 与 blast radius 进行分级（见 §6.3 Tool Risk Schema）；
- 应用 policy 驱动的授权与审批要求；
- 对 disruptive 操作强制显式确认（见 §19.8）；
- 生成 trace 与 evidence 以支撑审计与回放。

> 工程含义：能否“只依赖 Northbound API security”这一问题的答案是 **不能**。Northbound API security 是 trust chain 的必要一环，但 MCP/tool 层必须独立做意图、参数、来源、范围、风险、确认与审计控制。

***

# 3. Design Principles

## 3.1 Control Plane First

Enterprise AI 安全不能只靠散落在业务代码中的 if/else 规则。

必须建立统一控制平面，使所有 AI 安全判断都进入同一套：

```text
Context → Signals → Policy → Decision → Enforcement → Trace → Evaluation → Release Gate
```

这样才能实现：

* 统一策略治理
* 统一审计证据
* 统一发布门禁
* 统一风险度量
* 统一回放复现
* 统一跨应用复用

## 3.2 Context-Aware Security

AI 安全判断不能只看 prompt 内容。  
同一句话在不同上下文中可能风险完全不同。

例如：

```text
“请总结这份客户合同中的关键条款”
```

如果用户是法务角色、合同属于同租户、数据分类允许访问，则可能 allow。  
如果用户是普通员工、合同属于其他租户、包含客户敏感信息，则必须 block 或 redact。

因此所有决策必须绑定 Enterprise Context：

```text
tenant / user role / app / workflow / data classification / region / policy profile / tool permission / request source
```

## 3.3 Detector Does Not Decide

Detector 只产生信号，不直接决定最终动作。

错误设计：

```text
PII detector hit → block
```

正确设计：

```text
PII detector hit → normalized signal → fusion → policy evaluation → decision engine → final action
```

原因：

1. detector 有误报和漏报。
2. 不同租户策略不同。
3. 不同数据类型处置不同。
4. 同一个信号在 input、RAG、tool、output 的处置不同。
5. 最终动作必须可解释、可审计、可回放。

## 3.4 Policy Is Runtime Logic, Not Hardcoded Logic

策略必须声明化、版本化、可 lint、可 dry-run、可灰度、可回滚。

业务代码不应写死：

```python
if region == "CN" and risk == "PII":
    block()
```

而应通过 policy runtime 执行：

```yaml
when:
  region: CN
  risk_family: PII
  data_classification: Restricted
then:
  action: redact
  severity: high
```

## 3.5 Decision Must Be Contract-Based

所有安全决策必须输出统一结构：

```json
{
  "decision_id": "...",
  "action": "allow | warn | redact | block | escalate | require_approval",
  "severity": "none | low | medium | high | critical",
  "confidence": 0.0,
  "reason_codes": [],
  "matched_rules": [],
  "mitigations": [],
  "trace_id": "...",
  "policy_snapshot_id": "...",
  "evidence_refs": []
}
```

任何业务系统不得依赖 detector 私有字段做安全判断。

## 3.6 Evidence Is a First-Class Artifact

在 Enterprise AI 中，“为什么这么判”与“判了什么”同等重要。

每次决策必须生成：

* request context snapshot
* detector signals
* policy snapshot
* matched rules
* decision path
* enforcement result
* model/tool metadata
* latency and runtime metadata
* evidence hash
* audit replay binding

## 3.7 Continuous Evaluation as Release Gate

AI 安全系统不能只在上线前人工验证。  
每次 detector、policy、prompt template、model、tool schema、RAG pipeline 变更，都必须经过自动评估。

评估指标包括：

* precision
* recall
* false positive rate
* false negative rate
* critical miss rate
* latency p95 / p99
* coverage
* policy conflict rate
* escalation rate
* redaction correctness
* replay consistency

## 3.8 Instruction/Data Separation

企业 AI 安全必须显式区分 **指令（instruction）** 与 **数据（data）**。

用户指令、系统指令、开发者策略、检索文档、工具输出、设备日志、API 响应、外部内容**不能被视为同一信任等级**。控制平面必须为每个内容来源赋予 **instruction provenance（指令来源）** 与 **trust level（信任等级）**。

默认规则：外部内容、检索上下文、设备日志、tool output 默认是 **data**，不得 override 系统策略、工具策略、授权策略或审批要求。

在 `tool_pre_execution` 与 `agent_step_check`，系统必须校验工具选择或工具参数是否受不可信内容影响（见 §6.3 Tool Argument Security Contract 的 `argument_source` / `instruction_provenance`）。若高风险工具执行依赖不可信指令来源，默认动作应为 `block`、`escalate` 或 `require_approval`（取决于 policy）。

***

# 4. High-Level Architecture

系统分为八个核心层：

```text
1. Enterprise Request Layer
2. Context Builder Layer
3. Detection Layer
4. Signal Normalization & Fusion Layer
5. Policy Runtime Layer
6. Decision Engine Layer
7. Enforcement Layer
8. Trace / Evidence / Evaluation / Release Gate Layer
```

整体数据流：

```text
User / Enterprise App / RAG Query
        ↓
Ingress Gateway
        ↓
Context Builder
        ↓
Request Orchestrator
        ↓
Parallel Detectors
        ↓
Normalized Signals
        ↓
Signal Fusion
        ↓
Policy Runtime
        ↓
Decision Engine
        ↓
Enforcement Point
        ↓
Model Runtime / Tool Runtime / Output Guardrail
        ↓
Final Response
        ↓
Decision Trace + Evidence Store
        ↓
Online Sampling + Offline Replay
        ↓
Evaluation
        ↓
Release Gate
        ↓
Policy / Detector / Model Feedback
```

***

# 5. Core Runtime Flow

## 5.1 End-to-End Request Flow

### Step 1: Ingress Gateway 接入请求

Ingress Gateway 负责接收来自以下来源的请求：

* 用户 prompt
* Enterprise App
* RAG query
* Agent planning step
* Tool pre-execution request
* Tool post-execution result
* Model output
* Batch evaluation request

Ingress Gateway 需要完成：

1. request authentication
2. tenant identification
3. traffic routing
4. request ID generation
5. initial metadata capture
6. timeout budget initialization
7. fail-safe policy binding

示例输入：

```json
{
  "request_id": "req_123",
  "tenant_id": "tenant_a",
  "app_id": "sales_copilot",
  "user_id": "u_456",
  "stage": "input_precheck",
  "content": "Summarize this customer contract",
  "region": "CN",
  "timestamp": "2026-06-14T22:10:00+08:00"
}
```

***

### Step 2: Context Builder 构建企业上下文

Context Builder 是安全判断的基础。  
它必须把请求转化为标准 Enterprise Context。

Context 包括：

```json
{
  "context_id": "ctx_123",
  "tenant": {
    "tenant_id": "tenant_a",
    "tenant_tier": "enterprise",
    "policy_profile": "cn_enterprise_strict"
  },
  "user": {
    "user_id_hash": "hash_xxx",
    "role": "legal_reviewer",
    "department": "legal",
    "clearance_level": "confidential"
  },
  "app": {
    "app_id": "sales_copilot",
    "app_type": "enterprise_ai_assistant",
    "environment": "prod"
  },
  "workflow": {
    "workflow_id": "contract_summary",
    "stage": "input_precheck"
  },
  "data": {
    "data_classification": "confidential",
    "data_subject": "customer",
    "data_origin": "internal_doc_repo",
    "data_residency": "CN"
  },
  "region": {
    "runtime_region": "CN",
    "storage_region": "CN",
    "compliance_tags": ["PII", "TC260", "enterprise_confidential"]
  },
  "policy": {
    "policy_namespace": "cloud_guardrail",
    "policy_version_hint": "latest"
  }
}
```

Context Builder 必须满足：

| 要求     | 说明                               |
| ------ | -------------------------------- |
| 字段完整   | 缺少关键字段不能静默 allow                 |
| 最小化    | trace 中保存最小必要上下文                 |
| 可哈希    | context\_hash 用于审计和 replay       |
| 可扩展    | 支持 agent、tool、RAG 新字段            |
| 可验证    | schema validate 不通过时进入 fail-safe |
| 不信任客户端 | 关键字段从服务端权威源解析                    |

#### Context Field Authority Matrix（字段权威源矩阵）

为防止上游伪造 role/region/clearance/tool permission 绕过策略，每个 context 字段必须明确：是否允许客户端传入、权威源、缺失时默认动作。Context Builder **不得**直接 trust request body 中的 role、region、clearance、tool permission。

| Context 字段           | 是否允许客户端传入                              | 权威源                                  | 缺失/不可解析时默认动作       |
| -------------------- | ------------------------------------:| ----------------------------------- | ----------------------- |
| tenant\_id           | limited                              | identity / token issuer             | block                   |
| user\_id             | no                                   | auth token                          | block                   |
| role                 | no                                   | IAM / directory                     | escalate / block        |
| department           | no                                   | directory                           | warn / escalate         |
| app\_id              | limited                              | app registry / mTLS client identity | block                   |
| data\_classification | no for stored data; limited for user input | data catalog / DLP classifier  | redact / escalate       |
| runtime\_region      | no                                   | deployment metadata                 | block if mismatch       |
| storage\_region      | no                                   | storage control plane               | block if regulated      |
| tool\_permission     | no                                   | tool registry + IAM                 | require\_approval / block |

每个 context 字段在内部表示中必须携带溯源元数据：

```json
{
  "value": "legal_reviewer",
  "source": "iam_directory",
  "source_trust_level": "authoritative",
  "resolved_at": "2026-06-14T22:10:00+08:00",
  "freshness_ttl_ms": 300000
}
```

约束：缺失 mandatory context 字段不得 allow；mandatory 字段权威源解析失败进入 fail-safe。

#### Tool-to-API Trust Chain Context（MCP / Tool 身份链路）

对于 MCP / tool-calling 与 Northbound API 集成，Context Builder 必须构建并绑定完整 trust chain，而不是只验证单点 public key。Northbound API public key matching 只是 trust chain 的一环，不是完整授权。系统必须绑定：

```text
user → MCP client → MCP server → tool → Northbound API → resource → action
```

每一段都必须记录 source、trust level、hash、scope 与 policy decision：

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

约束：
* trust chain 任一段缺失身份绑定，必须产生 `UNAUTHORIZED_ACCESS` 信号（如 `MISSING_CLIENT_IDENTITY_BINDING` / `NORTHBOUND_API_AUTH_CONTEXT_MISSING`），高风险工具不得 silent allow。
* `tool_registry_status != approved` 的工具默认不可执行，除非 policy 显式放行。
* trust chain 关键字段（client/server/tool/api/resource）必须进入 trace（见 §7 `tool_execution`）。

***

### Step 3: Request Orchestrator 编排检测路径

Orchestrator 根据 canonical `stage`（见 §0.1）决定执行哪些 detector。**禁止使用已废弃的 `request_type` 做编排或匹配。**

stage → 检测路径映射：

| stage                          | 检测路径                                                       |
| ------------------------------ | ---------------------------------------------------------- |
| input\_precheck                | prompt injection, PII, confidential data, policy violation |
| rag\_query\_precheck           | query safety, data access, RAG injection                   |
| rag\_retrieved\_context\_check | RAG injection, confidential data, source trust             |
| rag\_context\_assembly\_check  | context packaging, residency, source trust                 |
| tool\_pre\_execution           | tool abuse, permission, argument risk                      |
| tool\_post\_execution          | result leakage, PII, confidential data                     |
| model\_output\_check           | output leakage, compliance, hallucinated secret            |
| agent\_plan\_check             | unsafe automation, tool chain risk                         |
| agent\_step\_check             | step-level authorization, tool chain risk                  |
| batch\_eval                    | offline replay detectors                                   |

Orchestrator 不做最终安全决策，只负责：

1. detector selection
2. parallel execution
3. timeout control
4. fallback routing
5. signal collection
6. partial failure handling

***

### Step 4: Parallel Detectors 并行检测

Detection Layer 由多个 detector 组成。

基础 detector 类型：

| Detector                         | 作用                    |
| -------------------------------- | --------------------- |
| Prompt Injection Detector        | 检测直接 prompt injection |
| RAG Injection Detector           | 检测检索内容中的间接注入          |
| PII Detector                     | 检测个人敏感信息              |
| Enterprise Confidential Detector | 检测企业机密                |
| IP Detector                      | 检测知识产权、源码、专利、内部算法     |
| Tool Abuse Detector              | 检测危险工具调用和越权参数         |
| Data Residency Detector          | 检查区域、跨境、存储限制          |
| Policy Violation Detector        | 检查上下文与业务策略冲突          |
| Output Leakage Detector          | 检测模型输出泄密              |
| Agent Risk Detector              | 检测多步自主行为风险            |
| Source Trust Detector            | 检测 RAG 文档来源可信度        |

Detector 输出必须统一为 raw signal，不能直接输出 final action。

示例 raw detector result：

```json
{
  "detector_id": "pii_detector_v2",
  "detector_version": "2.1.0",
  "signal_type": "PII",
  "confidence": 0.92,
  "severity": "high",
  "matched_spans": [
    {
      "field": "content",
      "start": 20,
      "end": 38,
      "label": "phone_number"
    }
  ],
  "evidence": {
    "pattern_id": "cn_phone_regex_v3",
    "sample_hash": "sha256_xxx"
  },
  "latency_ms": 8
}
```

Detector 工程要求：

| 要求           | 说明                            |
| ------------ | ----------------------------- |
| Stateless 优先 | 便于横向扩展                        |
| 版本化          | detector\_id + version 必须记录   |
| 可回放          | 相同输入和版本应可复现                   |
| 超时可控         | 单 detector 必须有 timeout        |
| 失败可见         | 必须返回 RawDetectorSignal 或 DetectorFailureSignal，失败信号进入 trace |
| 不私自拦截        | 不得返回 final action，不得绕过 decision engine |
| 可评估          | 每个 detector 独立产出 eval metrics |

Detector 契约（红线）：

```text
Detector MUST NOT return final action.
Detector output MUST be either:
  1. RawDetectorSignal
  2. DetectorFailureSignal
DetectorFailureSignal MUST include:
  detector_id, detector_version, failure_type, timeout_ms (if applicable),
  retryable, partial_result_available, recommended_mitigation.
Any detector result failing schema validation MUST be converted into:
  risk_family = SYSTEM_FAILURE, risk_type = INVALID_DETECTOR_OUTPUT.
```

***

### Step 5: Signal Normalization 规范化信号

所有 detector 输出进入统一 signal schema。

标准 Normalized Signal：

```json
{
  "signal_id": "sig_123",
  "risk_family": "PII_LEAKAGE",
  "risk_type": "CN_PHONE_NUMBER",
  "source": {
    "detector_id": "pii_detector_v2",
    "detector_version": "2.1.0"
  },
  "scope": {
    "stage": "input_precheck",
    "field": "content",
    "span_hash": "sha256_xxx"
  },
  "severity": "high",
  "confidence": 0.92,
  "data_attributes": {
    "data_subject": "customer",
    "data_classification": "restricted",
    "business_domain": "sales"
  },
  "recommended_mitigation": ["redact"],
  "evidence_refs": ["ev_123"],
  "timestamp": "2026-06-14T22:10:00+08:00"
}
```

Normalized Signal 的作用：

1. 屏蔽 detector 私有格式。
2. 为 signal fusion 提供统一输入。
3. 为 policy runtime 提供可匹配字段。
4. 为 trace/evidence 提供标准审计对象。
5. 为 offline evaluation 提供统一标签空间。

约束：任何不符合 normalized signal schema 的 detector 输出，必须转换为
`risk_family = SYSTEM_FAILURE`、`risk_type = INVALID_DETECTOR_OUTPUT` 的失败信号，而不能被丢弃。

#### Detector Failure Signal Schema

detector 失败的安全含义因失败类型不同而不同，因此所有 detector failure 必须归一化为 `SYSTEM_FAILURE` 信号，并区分 failure type：

```json
{
  "signal_id": "sig_failure_001",
  "schema_version": "normalized-signal/v1",
  "risk_family": "SYSTEM_FAILURE",
  "risk_type": "DETECTOR_TIMEOUT",
  "stage": "model_output_check",
  "source": {
    "detector_id": "pii_detector_v2",
    "detector_version": "2.1.0"
  },
  "failure": {
    "type": "timeout",
    "timeout_ms": 20,
    "retryable": true,
    "partial_result_available": false
  },
  "severity": "high",
  "confidence": 1.0,
  "recommended_mitigation": ["escalate", "fail_safe_redact"]
}
```

`failure.type` enum（至少）：

```yaml
detector_failure_type:
  - TIMEOUT
  - CRASH
  - INVALID_OUTPUT
  - DEPENDENCY_UNAVAILABLE
  - SKIPPED_BY_POLICY
  - VERSION_MISMATCH
  - MODEL_UNAVAILABLE
```

约束：
* Decision Engine 必须包含 `failure_policy_matrix`，将 failure type × stage × context 映射到默认动作。
* 高风险 stage 中 critical detector 的 failure 不得 silent allow。

***

### Step 6: Signal Fusion 多信号融合

Signal Fusion 负责将多个 normalized signals 聚合为风险态势。

它不是简单取最高分，而是根据：

* risk family
* severity
* confidence
* detector trust level
* signal source
* context
* policy profile
* conflict rule
* stage
* affected data type

生成 fused risk view。

示例 fused signal：

```json
{
  "fusion_id": "fusion_123",
  "risk_families": [
    {
      "risk_family": "PII_LEAKAGE",
      "max_severity": "high",
      "confidence": 0.94,
      "supporting_signals": ["sig_1", "sig_2"],
      "conflict_status": "none"
    },
    {
      "risk_family": "PROMPT_INJECTION",
      "max_severity": "medium",
      "confidence": 0.78,
      "supporting_signals": ["sig_3"],
      "conflict_status": "low_confidence"
    }
  ],
  "overall_risk": {
    "severity": "high",
    "confidence": 0.91
  }
}
```

Fusion 原则：

| 原则      | 说明                                   |
| ------- | ------------------------------------ |
| 高严重度优先  | critical/high 不得被低风险信号稀释             |
| 多证据增强   | 多 detector 独立命中提高置信                  |
| 低置信降级   | 单一低置信 LLM judge 不应直接 block           |
| 规则型信号优先 | 对明确 PII、权限、区域违规等，规则信号权重高             |
| 上下文参与   | 同一 signal 在不同 role/data/region 下风险不同 |
| 冲突显式记录  | detector 结论不一致必须进入 trace             |
| 工具风险优先  | tool pre-execution 高风险应优先拦截          |

***

### Step 7: Policy Runtime 策略运行时

Policy Runtime 是系统核心。

它根据：

```text
Enterprise Context + Fused Signals + Policy Snapshot
```

计算 matched rules 和 candidate actions。

## 7.1 Policy 层级

策略分为四级：

```text
Global Policy
    ↓
Region Policy
    ↓
Tenant Policy
    ↓
Application Policy
```

优先级：

```text
Application > Tenant > Region > Global
```

但更高层不能降低强制性合规规则。  
例如 Global/Region 定义的数据出境限制，Tenant/Application 不能 override 为 allow。

## 7.2 Policy DSL v0.1 Spec（正式语法）

为支持 validate/lint/diff，Policy DSL 必须从“示例”升级为可校验的正式 grammar。v0.1 优先可实现，不追求强大。

### 7.2.1 允许的 operator（封闭集合）

```yaml
operators:
  - eq
  - neq
  - in
  - not_in
  - gte
  - lte
  - exists
  - not_exists
  - contains_any
```

### 7.2.2 固定 policy 结构

```yaml
policy_id: string
version: semver
policy_type: global | region | tenant | application
scope:
  region: string | "*"
  tenant_id: string | "*"
  app_id: string | "*"
rules:
  - rule_id: string
    priority: int
    when:
      all:                         # all / any 组合；叶子为 {field, op, value}
        - field: stage
          op: eq
          value: model_output_check
        - field: fused_risk.risk_families
          op: contains_any
          value: [PII_LEAKAGE]
    then:
      action: redact
      severity: high
      reason_code: CN_PII_OUTPUT_REDACTION_REQUIRED
      mitigation:
        type: structured_redaction
    audit:
      evidence_required: true
      retention_class: regulated
```

约束：
* `when` 仅由 `all` / `any` 嵌套，叶子节点为 `{field, op, value}`，`op` 必须取自 7.2.1。
* 多条 rule 命中时，先按 `priority` 排序；同优先级冲突按 Step 8-A 严重度排序收敛；region/global 强制规则不可被下层 policy 降级。
* enum 字段（stage/action/severity/risk_family）按 §0 校验。

### 7.2.3 示例（canonical stage）

```yaml
# PII 输出脱敏
policy_id: pol_cn_pii_output_redact
version: 1.0.0
policy_type: region
scope: { region: CN, tenant_id: "*", app_id: "*" }
rules:
  - rule_id: rule_001
    priority: 100
    when:
      all:
        - { field: stage, op: eq, value: model_output_check }
        - { field: fused_risk.risk_families, op: contains_any, value: [PII_LEAKAGE] }
        - { field: context.data.data_classification, op: in, value: [confidential, restricted] }
    then:
      action: redact
      severity: high
      reason_code: CN_PII_OUTPUT_REDACTION_REQUIRED
      mitigation: { type: structured_redaction, preserve_semantics: true }
    audit: { evidence_required: true, retention_class: regulated }
---
# 高风险工具需审批
policy_id: pol_tool_pre_exec_high_risk_block
version: 1.0.0
policy_type: global
scope: { region: "*", tenant_id: "*", app_id: "*" }
rules:
  - rule_id: rule_001
    priority: 200
    when:
      all:
        - { field: stage, op: eq, value: tool_pre_execution }
        - { field: tool.risk_level, op: in, value: [high, critical] }
        - { field: user.approval_status, op: not_in, value: [approved] }
    then:
      action: require_approval
      severity: high
      reason_code: TOOL_EXECUTION_REQUIRES_APPROVAL
---
# critical prompt injection 拦截
policy_id: pol_prompt_injection_block_critical
version: 1.0.0
policy_type: global
scope: { region: "*", tenant_id: "*", app_id: "*" }
rules:
  - rule_id: rule_001
    priority: 300
    when:
      all:
        - { field: fused_risk.risk_families, op: contains_any, value: [PROMPT_INJECTION] }
        - { field: fused_risk.overall.severity, op: in, value: [critical] }
        - { field: fused_risk.overall.confidence, op: gte, value: 0.85 }
    then:
      action: block
      severity: critical
      reason_code: CRITICAL_PROMPT_INJECTION_BLOCKED
```

### 7.2.4 Linter 规则（最小集）

| 规则   | 检查项                                                      | 级别  |
| ---- | -------------------------------------------------------- | --- |
| L001 | 非 allow action 必须有 reason_code                           | error |
| L002 | action 对该 stage 合法（见 Step 8-B）                          | error |
| L003 | high/critical action 必须 `evidence_required: true`        | error |
| L004 | region/global mandatory rule 不可被 tenant/app 降级 override  | error |
| L005 | duplicate rule priority                                  | warn  |
| L006 | unreachable rule（被前序规则完全覆盖）                              | warn  |

### 7.2.5 Diff 输出要求

policy diff 必须输出：added rules / removed rules / changed conditions / changed actions / affected historical trace count。

## 7.3 Policy Runtime 必须支持的能力

Policy Runtime **v0 MUST** 实现：

| 能力                      | 说明                          |
| ----------------------- | --------------------------- |
| Validate                | 基于 JSON Schema 的语法和字段校验      |
| Lint                    | 至少实现 §7.2.4 的 L001–L006     |
| Immutable Snapshot      | 每次发布生成不可变 policy\_snapshot\_id |
| Rule Matching           | all/any + operator 匹配        |
| Stage-Action Validation | 校验 Step 8-B 合法性             |
| Reason-code Enforcement | 非 allow 必须有 reason_code      |
| Region Mandatory Protect| 区域强制规则不可被降级                 |
| Dry-run                 | 在历史 trace 数据集上模拟执行          |

Policy Runtime **MAY defer**（后续版本）：

| 能力           | 说明                          |
| ------------ | --------------------------- |
| Rollback     | 回滚到指定 snapshot              |
| Diff         | 策略版本差异比较（见 §7.2.5）          |
| Canary       | 小流量灰度策略编排                   |
| Explain      | 输出命中规则和冲突处理                 |
| Replay       | 历史请求按旧/新策略重算（CLI/API 见 §8、§9） |
| Multi-region | 区域策略隔离与 self-service authoring |

***

### Step 8: Decision Engine 决策合成

Decision Engine 将 policy runtime 的候选动作合成为最终决策。

支持动作：见 §0.2 Canonical Action Enum（`allow / log_only / warn / redact / block / escalate / require_approval / rewrite / remove_chunk / reduce_rank / safe_complete`）。

#### Step 8-A: Decision Action State Machine（动作语义不只是优先级）

仅靠全局优先级不足，因为 action 语义依赖 stage（例如 input 中 `redact` 后可继续进入模型，output 中 `redact` 后返回用户，tool pre-execution 中 `redact` 无明确语义）。因此动作按 §0.2 分为四类，并约束流转：

```text
terminal_actions      : allow / block / safe_complete        # 决策到此终结
transform_actions     : redact / rewrite / remove_chunk / reduce_rank  # 改写后继续本 stage 流转
human_or_async_actions: warn / escalate / require_approval   # 非 terminal，需人工/异步收敛
observability_actions : log_only                             # 仅记录
```

关键语义：
* `require_approval` 是 **pending state**，不是 terminal decision；返回业务方前必须携带 `approval_ticket_id` 或 `approval_workflow_ref`。
* `regenerate` 不再作为独立动作，统一收敛为 `rewrite`。
* 用于冲突收敛的全局严重度排序（仅在多个合法候选动作并存时使用）：
  `block > require_approval > escalate > rewrite > redact > reduce_rank > remove_chunk > warn > allow > log_only`。

#### Step 8-B: Stage × Action 合法性矩阵

Decision Engine 必须校验 `stage × action` 合法性，非法组合返回 `POLICY_ACTION_NOT_ALLOWED_FOR_STAGE`。

| Stage                          | allow | redact                | block | require\_approval | escalate | rewrite            | remove\_chunk |
| ------------------------------ | -----:| ---------------------:| -----:| -----------------:| --------:| ------------------:| -------------:|
| input\_precheck                | ✅     | ✅                     | ✅     | ⚠️ limited        | ✅        | ❌                  | ❌            |
| rag\_retrieved\_context\_check | ✅     | ✅ redact chunk        | ✅     | ❌                 | ✅        | ❌                  | ✅            |
| tool\_pre\_execution           | ✅     | ❌ by default          | ✅     | ✅                 | ✅        | ❌                  | ❌            |
| model\_output\_check           | ✅     | ✅                     | ✅     | ❌                 | ✅        | ✅ if supported     | ❌            |
| agent\_plan\_check             | ✅     | ❌                     | ✅     | ✅                 | ✅        | ❌                  | ❌            |

stage 与 action 的典型组合示例：

* input\_precheck 中包含无法安全处理的 critical secret → block
* model\_output\_check 中包含 PII 但可精准脱敏 → redact
* tool\_pre\_execution 涉及不可逆高风险操作 → require\_approval
* detector 失败且上下文高风险 → escalate/block
* 低置信 prompt injection → warn/escalate

标准 Decision Contract：

```json
{
  "decision_id": "dec_123",
  "trace_id": "trace_123",
  "request_id": "req_123",
  "context_hash": "ctx_hash_123",
  "policy_snapshot_id": "ps_20260614_001",
  "action": "redact",
  "severity": "high",
  "confidence": 0.94,
  "reason_codes": [
    "CN_PII_OUTPUT_REDACTION_REQUIRED"
  ],
  "matched_rules": [
    {
      "policy_id": "pol_cn_pii_output_redact",
      "version": "1.0.0",
      "rule_id": "rule_001"
    }
  ],
  "risk_summary": {
    "risk_families": ["PII_LEAKAGE"],
    "data_attributes": {
      "data_subject": "customer",
      "data_classification": "restricted"
    }
  },
  "mitigations": [
    {
      "type": "redaction",
      "mode": "structured",
      "fields": ["phone_number"]
    }
  ],
  "explanation": {
    "short": "Customer PII detected in model output and must be redacted under CN enterprise policy.",
    "debug": "PII detector v2 detected CN phone number with confidence 0.92; policy pol_cn_pii_output_redact matched."
  },
  "evidence_refs": ["ev_123", "ev_124"],
  "created_at": "2026-06-14T22:10:00+08:00"
}
```

当 `action = require_approval` 时，Decision Contract 必须附带 `required_approval`；对 disruptive 操作必须附带可绑定的 `confirmation_challenge`：

```json
{
  "action": "require_approval",
  "required_approval": {
    "approval_type": "explicit_user_confirmation",
    "approval_ticket_id": null,
    "approval_workflow_ref": null,
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
}
```

> 说明：`require_approval` 仍是 pending state；`approval_ticket_id` / `approval_workflow_ref` 与 `confirmation_challenge` 至少其一必须存在。通用的 “yes” 不足以满足 disruptive 操作的确认要求，确认必须绑定 action / target / version / blast radius / user / timestamp / action_hash（见 §19.8）。

Decision Engine 必须保证：

1. 无 policy snapshot 不决策。
2. 无 context 不 allow。
3. detector failure 必须参与决策（见 §5 Step 6 Detector Failure 与 §13.2 failure policy matrix）。
4. 所有决策必须有 reason code（非 allow 决策强制）。
5. 所有非 allow 决策必须有 mitigation 或 escalation path。
6. 所有决策返回前必须完成 **Minimal Trace Commit**（见 §7.1）。
7. 非法 `stage × action` 组合必须 fail-safe 并返回 `POLICY_ACTION_NOT_ALLOWED_FOR_STAGE`（见 Step 8-B）。
8. `require_approval` 必须携带 `approval_ticket_id` 或 `approval_workflow_ref`。
9. 决策可复现：满足 §0.4 Decision Determinism Rules（replay key 完整）。

***

# 6. Enforcement Points

Enforcement Point 是决策执行层。

不同 stage 有不同执行方式。

## 6.1 Input Enforcement

处理用户输入或应用请求。

动作：

| Action            | 行为         |
| ----------------- | ---------- |
| allow             | 请求进入模型     |
| warn              | 提示用户风险但继续  |
| redact            | 对输入脱敏后进入模型 |
| block             | 拒绝请求       |
| escalate          | 转人工/安全队列   |
| require\_approval | 等待授权       |

示例：

```text
用户输入包含客户手机号 → redact 后送入模型
用户输入包含 prompt injection → block
用户输入疑似低置信攻击 → warn + log
```

## 6.2 RAG Enforcement

处理检索请求与检索结果。

控制点：

1. Query pre-check
2. Retrieval source trust check
3. Retrieved document scan
4. Context packaging check
5. Model input assembly check

典型动作：

| 风险         | 动作                                    |
| ---------- | ------------------------------------- |
| 检索文档包含隐藏指令 | remove infected chunk / block context |
| 文档来源低可信    | reduce rank / require verification    |
| 用户无权访问文档   | block retrieval                       |
| 文档包含客户敏感信息 | redact / summary-only                 |
| 跨区域数据不允许   | block                                 |

#### RAG Chunk Security Contract

为支持 chunk 级处置（remove infected chunk / reduce rank / redact span），RAG detector 与 enforcement 之间必须使用 chunk-level contract，否则即使命中也无法告知 RAG pipeline 移除哪个 chunk、降权哪个 source、哪个 span 是 hidden instruction。

```json
{
  "rag_context_id": "rag_ctx_123",
  "retrieval_id": "ret_456",
  "chunks": [
    {
      "chunk_id": "chunk_001",
      "source_doc_id_hash": "sha256_doc",
      "source_uri_hash": "sha256_uri",
      "source_trust_level": "internal_verified",
      "data_classification": "confidential",
      "region": "CN",
      "rank": 3,
      "content_hash": "sha256_content",
      "span_hash": "sha256_span",
      "security_labels": ["RAG_INJECTION_SUSPECTED"],
      "allowed_action": "remove_chunk"
    }
  ]
}
```

约束：
* RAG detector 输出必须包含 `chunk_id` 和 `span_hash`。
* Enforcement 必须支持：`remove_chunk` / `redact_chunk_span` / `reduce_rank` / `block_context` / `summary_only` / `require_source_verification`。
* Trace 中必须记录被移除 chunk 的 hash 和 reason code，而不是原文。

## 6.3 Tool Pre-Execution Enforcement

这是 Agent Security 的关键预留接口。

在工具真正执行前必须检查：

* tool identity
* user authorization
* argument risk
* side effect level
* data access scope
* approval requirement
* reversibility
* business impact
* instruction provenance（参数/工具选择是否受不可信内容影响，见 §3.8）
* transport trust（见 §14.5）

#### Tool Argument Security Contract

后端 API 已经 sanitize **不**等于 MCP/tool 层可以跳过校验：后端 validation 仍然 mandatory，但它不能替代 MCP/tool 层对意图、schema、来源、范围、风险的校验。工具参数与后端 API 之间必须使用结构化、强类型、可校验的 Tool Argument Security Contract：

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

工程规则：
* 发送到后端 API 的工具参数必须是结构化、强类型、schema 校验且 policy 校验后的；原始自然语言或检索到的外部内容**不得**作为高风险工具的 API 参数直接透传。
* 后端 API validation 仍然 mandatory，但不能替代 MCP/tool 层 validation。
* 当 `argument_source.trust_level = untrusted` 且工具为高风险时，默认动作为 `block` / `escalate` / `require_approval`（见 §3.8）。
* `freeform_endpoint` / `arbitrary_payload` / `wildcard_resource_scope` 为 true 的通用 API 执行工具默认对 agent 不可见，除非 policy 显式批准（见 §9 gate 阻断条件）。

Tool request 示例：

```json
{
  "stage": "tool_pre_execution",
  "tool": {
    "tool_id": "send_email",
    "risk_level": "medium",
    "side_effect": "external_communication"
  },
  "arguments": {
    "recipient_domain": "external.com",
    "attachment_classification": "confidential"
  }
}
```

高风险工具示例：

| Tool            | 风险       |
| --------------- | -------- |
| send\_email     | 外发信息     |
| delete\_file    | 不可逆删除    |
| execute\_code   | 任意代码执行   |
| create\_payment | 金融交易     |
| update\_crm     | 修改客户记录   |
| query\_hr\_data | 访问员工敏感数据 |
| export\_dataset | 批量数据泄露   |

默认策略：

```text
high-risk tool + sensitive data + no approval → require_approval or block
```

#### Tool Risk Schema v0.1

工具定级不能由 app 硬编码，必须由 tool registry 提供并作为 policy runtime 的输入。Tool Risk Schema 提供 side effect、reversibility、blast radius、data access、approval 的可执行模型：

```json
{
  "tool_id": "send_email",
  "tool_version": "1.0",
  "tool_category": "external_communication",
  "base_risk_level": "medium",
  "side_effect": {
    "type": "external_communication",
    "reversibility": "low",
    "blast_radius": "tenant_external",
    "requires_idempotency_key": true
  },
  "data_access": {
    "read_scope": ["email_draft", "attachments"],
    "write_scope": ["mailbox_send"],
    "sensitive_data_allowed": false
  },
  "approval_policy": {
    "required_when": [
      "attachment_classification in [confidential, restricted]",
      "recipient_domain != tenant_domain"
    ],
    "approver_role": "manager"
  }
}
```

##### Operational Infrastructure 扩展（firmware update / reboot / configuration / batch）

对运维型工具（如 XClarity One 的 firmware update、server configuration、reboot、batch operation），Tool Risk Schema 必须扩展 `operation_profile`、`northbound_api_binding` 与 `confirmation_policy`，使 disruptive action 成为 Tool Registry 的结构化字段，进入 policy runtime 与 decision engine，而不是“邮件里的建议”：

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
    "disallowed_endpoints": ["*"],
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

约束：
* Tool registry 是 policy runtime 的输入，不得硬编码在 app 内。
* tool\_pre\_execution decision 必须能返回：`allow` / `require_approval` / `block` / `argument_redaction_required`。
* 高风险工具必须具备：idempotency key、audit event、post-execution scan hook、rollback/compensation note；若不可逆则标记 `irreversible: true`。
* 参数变化可改变风险等级（如 `recipient_domain`、`attachment_classification`、`operation_type`、batch size），必须参与定级。
* `northbound_api_binding` 通过 `allowed_endpoints` / `method_allowlist` / `requires_api_scope` 限定工具可触达的 API 面，`disallowed_endpoints: ["*"]` 表示默认拒绝、显式白名单放行。
* `operation_profile.disruptive = true` 的工具必须由 decision engine 强制 `confirmation_policy`（见 §19.8）。

## 6.4 Output Enforcement

处理模型最终输出。

动作：

| Action     | 行为            |
| ---------- | ------------- |
| allow      | 原样返回          |
| warn       | 附加风险提示        |
| redact     | 脱敏后返回         |
| block      | 替换为拒绝响应       |
| escalate   | 返回处理中并进入审查    |
| rewrite    | 可选：要求模型重写安全输出（原 `regenerate` 收敛为此，见 §0.2） |

Output Guardrail 必须避免：

1. 输出个人敏感信息。
2. 输出企业机密。
3. 输出跨租户数据。
4. 输出未经授权的内部信息。
5. 输出工具执行后的敏感结果。
6. 输出受策略禁止的内容。

***

# 7. Trace and Evidence Design

## 7.1 Decision Trace 是唯一事实源（两阶段写入）

每次请求必须生成 trace。Trace 是后续所有审计、评估、debug、release gate、policy replay 的基础。

为消解“任何 decision 必须绑定 trace_id / 不允许无 trace 决策”与“trace 异步写入”之间的工程矛盾，**Trace 写入拆分为两个阶段**：

```text
1. Minimal Trace Commit（同步、强制）
   在返回 decision 前同步写入最小 trace envelope。
   至少包含：trace_id, request_id, context_hash, policy_snapshot_id,
            decision_id, action, reason_codes, timestamp。
   失败处理：高风险 stage 下 Minimal Trace Commit 失败必须 fail-closed
            （fail-safe escalate/block，reason=TRACE_MINIMAL_COMMIT_FAILED）。

2. Full Trace / Evidence Append（异步、可重试）
   detector details、redacted sample、latency breakdown、evidence objects
   异步补充；失败必须产生 EVIDENCE_APPEND_FAILED event 并告警。
```

红线：
* 100% decision 返回前完成 Minimal Trace Commit。
* High-risk decision MUST NOT be returned if Minimal Trace Commit fails。
* release gate 必须检查 `minimal_trace_coverage == 100%`。

最小 trace envelope：

```json
{
  "schema_version": "trace-minimal/v1",
  "trace_id": "trace_123",
  "request_id": "req_123",
  "context_hash": "ctx_hash_123",
  "policy_snapshot_id": "ps_20260614_001",
  "decision_id": "dec_123",
  "action": "redact",
  "reason_codes": ["CN_PII_OUTPUT_REDACTION_REQUIRED"],
  "timestamp": "2026-06-14T22:10:00+08:00"
}
```

完整（异步补充后的）trace schema：

```json
{
  "trace_id": "trace_123",
  "request_id": "req_123",
  "runtime": {
    "environment": "prod",
    "region": "CN",
    "service_version": "guardrail-runtime-1.0.0",
    "timestamp": "2026-06-14T22:10:00+08:00"
  },
  "context": {
    "context_hash": "ctx_hash_123",
    "tenant_id": "tenant_a",
    "role": "legal_reviewer",
    "app_id": "sales_copilot",
    "data_classification": "confidential",
    "region": "CN",
    "policy_profile": "cn_enterprise_strict"
  },
  "request": {
    "stage": "model_output_check",
    "content_hash": "sha256_xxx",
    "content_sample_redacted": "Customer [PHONE_REDACTED] ..."
  },
  "signals": [
    {
      "signal_id": "sig_123",
      "risk_family": "PII_LEAKAGE",
      "severity": "high",
      "confidence": 0.92,
      "detector_id": "pii_detector_v2"
    }
  ],
  "fusion": {
    "fusion_id": "fusion_123",
    "overall_severity": "high",
    "overall_confidence": 0.94
  },
  "policy": {
    "policy_snapshot_id": "ps_20260614_001",
    "matched_rules": [
      "pol_cn_pii_output_redact/rule_001"
    ]
  },
  "decision": {
    "decision_id": "dec_123",
    "action": "redact",
    "severity": "high",
    "reason_codes": [
      "CN_PII_OUTPUT_REDACTION_REQUIRED"
    ]
  },
  "enforcement": {
    "status": "success",
    "mitigation": "structured_redaction",
    "output_hash": "sha256_yyy"
  },
  "latency": {
    "total_ms": 42,
    "detector_ms": 18,
    "policy_ms": 3,
    "enforcement_ms": 6
  },
  "audit": {
    "evidence_refs": ["ev_123"],
    "trace_hash": "sha256_trace",
    "retention_class": "regulated",
    "replayable": true
  }
}
```

对 MCP / tool stage（`tool_pre_execution` / `tool_post_execution` / `agent_step_check`），Full Trace 必须附带 `tool_execution` 段：

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
  "transport_trust_status": "trusted_ca",
  "confirmation_required": true,
  "confirmation_status": "confirmed | missing | expired | not_required",
  "action_hash": "sha256_xxx"
}
```

## 7.2 Evidence Object

Evidence 是 trace 中可检索、可证明、可复盘的证据对象。

```json
{
  "evidence_id": "ev_123",
  "trace_id": "trace_123",
  "evidence_type": "detector_match",
  "source": "pii_detector_v2",
  "content_hash": "sha256_xxx",
  "redacted_sample": "[PHONE_REDACTED]",
  "matched_pattern": "cn_phone_regex_v3",
  "confidence": 0.92,
  "created_at": "2026-06-14T22:10:00+08:00",
  "integrity": {
    "hash": "sha256_ev",
    "signature": "sig_xxx"
  }
}
```

## 7.3 Trace Retention Policy

| Trace 类型              | 保留策略                            |
| --------------------- | ------------------------------- |
| allow + low risk      | 短期保留，采样                         |
| warn/redact           | 中期保留                            |
| block/escalate        | 长期保留                            |
| regulated data        | 按合规要求保留                         |
| eval replay data      | 脱敏后进入评估集                        |
| raw sensitive content | 默认不保存，保存 hash 和 redacted sample |

***

# 8. Evaluation System

Evaluation 系统用于回答：

1. detector 是否准确？
2. policy 是否过严或过松？
3. 新版本是否引入回归？
4. 线上误报/漏报是否变化？
5. release 是否可以进入生产？
6. 是否需要 rollback？

## 8.1 Evaluation Sources

| 来源                  | 用途                   |
| ------------------- | -------------------- |
| Offline benchmark   | 固定回归测试               |
| Online sampling     | 生产流量采样               |
| Human-labeled cases | 高质量标注                |
| Incident traces     | 真实问题复盘               |
| Synthetic attacks   | Prompt/RAG/Tool 攻击生成 |
| Policy replay       | 新旧策略对比               |
| Canary traffic      | 灰度发布验证               |

## 8.2 Core Metrics

| 指标                   | 说明             |
| -------------------- | -------------- |
| Precision            | 被判风险中真实风险比例    |
| Recall               | 真实风险被发现比例      |
| FPR                  | 误报率            |
| FNR                  | 漏报率            |
| Critical Miss Rate   | critical 风险漏检率 |
| Latency p50/p95/p99  | 性能             |
| Coverage             | 适用场景覆盖率        |
| Escalation Rate      | 升级审查比例         |
| Redaction Accuracy   | 脱敏正确率          |
| Policy Conflict Rate | 策略冲突率          |
| Replay Consistency   | 回放一致性          |
| Availability         | 服务可用性          |
| Timeout Rate         | 超时率            |

## 8.3 Required Slices 与分层 Critical Metrics

只看全局 precision/recall 会掩盖关键风险（如 PII recall 高但 prompt injection recall 低、整体 latency OK 但 output p99 超标）。因此 Release Gate 不允许只看 global average，Evaluation 必须按以下维度切片：

```yaml
required_slices:
  - risk_family
  - stage
  - action
  - data_classification
  - region
  - tenant_policy_profile
  - detector_version
  - policy_snapshot_id
  # MCP / tool 维度
  - tool_id
  - tool_risk_level
  - operation_type
  - mcp_client_trust_level
  - transport_trust_status
  - confirmation_required
  - confirmation_status
```

按风险族 / 阶段的 gate metric 示例：

```yaml
critical_metrics:
  by_risk_family:
    PROMPT_INJECTION:
      recall_min: 0.92
      critical_miss_rate_max: 0.003
      tool_level_injection_recall_min: 0.92
    PII_LEAKAGE:
      recall_min: 0.95
      redaction_accuracy_min: 0.98
    TOOL_ABUSE:
      critical_miss_rate_max: 0.001
    TRANSPORT_TRUST_RISK:
      production_allow_rate_for_untrusted_cert_max: 0
  by_stage:
    tool_pre_execution:
      fail_closed_coverage: 1.0
      high_risk_tool_without_approval_rate_max: 0
      disruptive_action_without_confirmation_rate_max: 0
      tool_argument_schema_violation_block_rate_min: 1.0
      transport_untrusted_prod_allow_rate_max: 0
      minimal_trace_coverage: 1.0
    model_output_check:
      latency_p95_ms_max: 80
```

约束：
* 每个 risk family 至少有独立 benchmark；每个 stage 至少有 smoke eval。
* P0 可只覆盖 prompt injection、PII、confidential data，但 Evaluation Card schema 必须预留全部 slice 字段。

## 8.4 Evaluation Card

每次 detector/policy/model/tool 变更都生成 Evaluation Card。

```yaml
evaluation_card:
  eval_id: eval_20260614_001
  target:
    component: pii_detector
    version: 2.1.0
  dataset:
    name: cn_enterprise_pii_eval
    size: 5000
  metrics:
    precision: 0.94
    recall: 0.91
    fpr: 0.03
    fnr: 0.09
    critical_miss_rate: 0.002
    latency_p95_ms: 18
  result:
    status: pass
    notes:
      - Recall improved by 3.2%
      - Latency within p95 budget
  evidence:
    report_uri: s3://...
    replay_trace_ids:
      - trace_001
      - trace_002
```

***

# 9. Release Gate

Release Gate 是生产发布前的自动门禁。

适用对象：

* detector version
* policy version
* model version
* prompt template
* RAG pipeline
* tool schema
* context builder schema
* fusion algorithm
* decision engine logic
* enforcement implementation

## 9.1 Release Gate Integration Spec（发布阻断器，而非报告）

Gate 必须接入 CI/CD 成为发布阻断器，而不是事后报告。每类变更对象都要明确 gate 触发点、阻断对象、回滚对象：

| 变更对象            | Gate 触发点                   | 阻断对象                | 回滚对象                     |
| --------------- | -------------------------- | ------------------- | ------------------------ |
| detector        | detector image promotion   | detector deployment | previous detector image  |
| policy          | policy snapshot publish    | policy activation   | previous snapshot        |
| tool schema     | tool registry update       | tool availability   | previous schema          |
| RAG pipeline    | pipeline config rollout    | traffic switch      | previous config          |
| decision engine | runtime service deployment | prod rollout        | previous service version |

Gate API：

```http
POST /v1/release/gate/evaluate
```

```json
{
  "change_id": "chg_123",
  "target_type": "policy",
  "target_version": "ps_candidate_001",
  "environment": "prod",
  "eval_cards": ["eval_001", "eval_002"],
  "replay_report_id": "replay_123",
  "canary_report_id": "canary_456",
  "decision": "FAIL",
  "blocking_reasons": [
    "PII_LEAKAGE.recall below threshold",
    "tool_pre_execution.critical_miss_rate above threshold"
  ]
}
```

约束：
* CI/CD pipeline 必须调用 release gate API；Gate `FAIL` 必须阻止 promotion。
* `ROLLBACK_REQUIRED` 必须输出 rollback target。
* Gate report 必须进入 evidence store。
* Gate 必须检查 `minimal_trace_coverage == 100%`（见 §7.1）。

## 9.2 Gate 示例

```yaml
release_gate:
  gate_id: gate_cloud_guardrail_prod
  target_env: prod
  required_metrics:
    critical_miss_rate:
      max: 0.005
    recall:
      min: 0.90
    precision:
      min: 0.85
    latency_p95_ms:
      max: 50
    policy_conflict_rate:
      max: 0.01
    replay_consistency:
      min: 0.99
  actions:
    on_pass: promote
    on_fail: block_release
    on_conditional_pass: canary_only
```

## 9.3 Gate 状态

| 状态                       | 行为         |
| ------------------------ | ---------- |
| PASS                     | 可发布        |
| CONDITIONAL\_PASS        | 仅允许 canary |
| FAIL                     | 阻止发布       |
| ROLLBACK\_REQUIRED       | 自动回滚       |
| MANUAL\_REVIEW\_REQUIRED | 人工审查       |

## 9.4 自动回滚条件

以下情况必须自动回滚：

1. critical miss rate 超阈值。
2. latency p95/p99 超阈值且影响生产。
3. block rate 异常升高。
4. allow rate 异常升高且伴随高风险漏检。
5. policy conflict rate 超阈值。
6. detector crash/timeout rate 超阈值。
7. replay consistency 低于阈值。
8. evidence generation failure。

## 9.5 MCP / Tool Integration 额外阻断条件

对 MCP / tool 集成相关变更（tool schema、tool registry、MCP server 接入等），release gate 必须额外阻断以下情况：

- 生产工具执行允许使用 untrusted / self-signed certificate；
- 高风险 tool schema 缺少 approval / confirmation policy；
- disruptive action 可在缺少 action-bound confirmation 的情况下执行；
- 向 agent 暴露了通用的任意 API 执行工具（freeform_endpoint / arbitrary_payload / wildcard_resource_scope）；
- 检测到 tool argument schema validation bypass；
- tool execution trace 缺少 tool_id、resource_scope_hash、policy_snapshot_id 或 confirmation_status；
- 高风险工具执行缺少 minimal trace coverage（`minimal_trace_coverage < 1.0`）。

***

# 10. API Design

## 10.1 Runtime Decision API

### Endpoint

```http
POST /v1/guardrail/decision
```

### Request

```json
{
  "schema_version": "decision-request/v1",
  "request_id": "req_123",
  "stage": "input_precheck",
  "tenant_id": "tenant_a",
  "app_id": "sales_copilot",
  "user": {
    "user_id": "u_456",
    "role": "legal_reviewer"
  },
  "content": {
    "type": "text",
    "value": "Please summarize this customer contract."
  },
  "metadata": {
    "region": "CN",
    "workflow_id": "contract_summary",
    "data_classification": "confidential"
  },
  "options": {
    "return_explanation": true,
    "enforcement_mode": "active"
  }
}
```

### Response

```json
{
  "decision_id": "dec_123",
  "trace_id": "trace_123",
  "action": "allow",
  "severity": "none",
  "confidence": 0.99,
  "reason_codes": [],
  "mitigations": [],
  "policy_snapshot_id": "ps_20260614_001",
  "latency_ms": 35
}
```

***

## 10.2 Tool Pre-Execution API

```http
POST /v1/guardrail/tool/pre-execution
```

```json
{
  "request_id": "req_tool_123",
  "stage": "tool_pre_execution",
  "tenant_id": "tenant_a",
  "app_id": "agent_assistant",
  "user": {
    "user_id": "u_456",
    "role": "sales"
  },
  "tool": {
    "tool_id": "send_email",
    "tool_version": "1.0",
    "risk_level": "medium"
  },
  "arguments": {
    "recipient": "external@example.com",
    "subject": "Customer contract",
    "attachment_classification": "confidential"
  },
  "context": {
    "region": "CN",
    "workflow_id": "customer_followup"
  }
}
```

Response:

```json
{
  "decision_id": "dec_tool_123",
  "action": "require_approval",
  "severity": "high",
  "reason_codes": [
    "EXTERNAL_EMAIL_WITH_CONFIDENTIAL_ATTACHMENT"
  ],
  "required_approval": {
    "approver_role": "manager",
    "approval_type": "explicit"
  }
}
```

***

## 10.3 Policy Validate API

```http
POST /v1/policy/validate
```

```json
{
  "policy_yaml": "...",
  "validation_mode": "strict"
}
```

Response:

```json
{
  "valid": false,
  "errors": [
    {
      "line": 12,
      "field": "then.action",
      "message": "Unknown action: sanitize"
    }
  ],
  "warnings": [
    {
      "message": "Policy has no reason_code"
    }
  ]
}
```

***

## 10.4 Policy Dry Run API

```http
POST /v1/policy/dry-run
```

```json
{
  "policy_snapshot_candidate": "ps_candidate_001",
  "trace_dataset": "prod_sample_last_7d",
  "compare_with": "ps_current"
}
```

Response:

```json
{
  "status": "completed",
  "summary": {
    "total_traces": 100000,
    "decision_changed": 3200,
    "new_blocks": 400,
    "new_allows": 80,
    "potential_regressions": 12
  },
  "gate_result": "conditional_pass"
}
```

***

## 10.5 Trace Ingest API

```http
POST /v1/trace/ingest
```

用于外部系统补充 tool result、human review、incident label 等信息。

***

# 11. Data Model

## 11.1 Risk Family Taxonomy

建议初始风险族：

```text
PROMPT_INJECTION
RAG_INJECTION
PII_LEAKAGE
ENTERPRISE_CONFIDENTIAL_LEAKAGE
IP_LEAKAGE
DATA_RESIDENCY_VIOLATION
TOOL_ABUSE
UNAUTHORIZED_ACCESS
UNSAFE_AUTOMATION
POLICY_VIOLATION
OUTPUT_UNSAFE_CONTENT
SOURCE_TRUST_RISK
MODEL_BEHAVIOR_ANOMALY
EVIDENCE_GAP
SYSTEM_FAILURE
TRANSPORT_TRUST_RISK
```

### 11.1.1 Risk Type 扩展（MCP / Tool / Transport / Confirmation）

为承接 MCP / Northbound API / certificate / confirmation 等具体问题，在以下风险族下扩展 `risk_type`（保持一级 RiskFamily 稳定）：

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
  - TOOL_RATE_LIMIT_EXCEEDED

UNSAFE_AUTOMATION:
  - AGENT_DIRECT_EXECUTION_WITHOUT_PLAN
  - MULTI_STEP_TOOL_CHAIN_WITHOUT_POLICY_CHECK
  - CONFIRMATION_ACTION_MISMATCH
```

## 11.2 Severity

```text
none
low
medium
high
critical
```

定义：

| Severity | 定义                       |
| -------- | ------------------------ |
| none     | 无明显风险                    |
| low      | 可记录或提示                   |
| medium   | 需要 warn/redact/escalate  |
| high     | 需要 block/redact/approval |
| critical | 默认 block 或强制 approval    |

## 11.3 Confidence

范围：

```text
0.0 - 1.0
```

建议解释：

| Confidence | 含义   |
| ---------- | ---- |
| 0.0-0.4    | 低置信  |
| 0.4-0.7    | 中等置信 |
| 0.7-0.9    | 高置信  |
| 0.9-1.0    | 极高置信 |

## 11.4 Action

完整 enum 与分类见 §0.2 Canonical Action Enum：

```text
allow
log_only
warn
redact
block
escalate
require_approval
rewrite
remove_chunk
reduce_rank
safe_complete
```

## 11.5 Data Attributes

Enterprise AI 中必须区分数据属性，而不能只用 PII 一类标签。

```json
{
  "data_subject": "employee | customer | partner | public | internal",
  "data_classification": "public | internal | confidential | restricted",
  "business_domain": "finance | hr | legal | sales | engineering | support",
  "data_origin": "user_input | internal_repo | customer_system | rag_index | tool_result",
  "residency": "CN | EU | US | GLOBAL",
  "regulatory_tags": ["PII", "TC260", "GDPR", "IP", "TradeSecret"]
}
```

***

# 12. Cloud Native Deployment Architecture

## 12.1 Microservices

建议服务拆分：

| Service              | 职责                    |
| -------------------- | --------------------- |
| guardrail-gateway    | 接入、鉴权、路由              |
| context-builder      | 构建 enterprise context |
| request-orchestrator | 编排 detector           |
| detector-service-\*  | 各类 detector           |
| signal-normalizer    | 统一 signal schema      |
| signal-fusion        | 多信号融合                 |
| policy-runtime       | 策略执行                  |
| decision-engine      | 决策合成                  |
| enforcement-service  | 执行动作                  |
| trace-service        | trace 写入              |
| evidence-service     | evidence 管理           |
| eval-service         | 在线/离线评估               |
| release-gate-service | 发布门禁                  |
| policy-management    | 策略管理                  |
| replay-service       | 历史回放                  |
| admin-console        | 管理界面                  |
| metrics-service      | 指标监控                  |

## 12.2 Deployment Modes

支持三种集成方式。

### Mode A: Gateway Mode

适合统一 AI 平台入口。

```text
Enterprise App → Guardrail Gateway → Model Gateway → Model Runtime
```

优点：

* 集中管控
* 易审计
* 易 rollout
* 业务侵入低

缺点：

* 对所有流量路径要求统一接入

### Mode B: Sidecar Mode

适合 Kubernetes 微服务架构。

```text
App Pod + Guardrail Sidecar → Model Runtime
```

优点：

* 就近拦截
* 低延迟
* 适合多团队多应用

缺点：

* sidecar 版本管理复杂

### Mode C: SDK Mode

适合应用内精细控制。

```text
App imports Guardrail SDK → Decision API
```

优点：

* 灵活
* 可嵌入业务流程
* 适合 tool calling 和 agent

缺点：

* 业务侵入较高
* 需要强制 SDK 合规接入

建议生产落地：

```text
Gateway Mode 作为默认入口
SDK Mode 用于 tool/agent 精细控制
Sidecar Mode 用于高性能或特殊隔离场景
```

***

# 13. Reliability and Fail-Safe Design

## 13.1 Timeout Budget

建议默认预算：

| 组件                    | p95 budget |
| --------------------- | ---------- |
| Context Builder       | 5ms        |
| Detector fast path    | 20ms       |
| Policy Runtime        | 5ms        |
| Decision Engine       | 3ms        |
| Minimal Trace Commit  | 5ms（同步、阻塞，纳入总预算） |
| Full Trace/Evidence Append | 非阻塞（异步） |
| Total input guardrail | 50ms       |
| Tool pre-execution    | 80ms       |
| Output guardrail      | 80ms       |

## 13.2 Failure Handling

| 失败类型                        | 默认行为                                       |
| --------------------------- | ------------------------------------------ |
| Context missing             | escalate/block                             |
| Policy snapshot unavailable | block for high-risk stage                  |
| Detector timeout            | normalize 为 SYSTEM\_FAILURE.DETECTOR\_TIMEOUT signal（见 §5 Step 6） |
| PII detector failure        | high-risk context 下 redact/block           |
| Minimal trace commit failure | high-risk stage fail-closed（escalate/block，reason=TRACE\_MINIMAL\_COMMIT\_FAILED）；low-risk 可 allow + alert |
| Full evidence append failure | 产生 EVIDENCE\_APPEND\_FAILED event 并告警，不阻塞已返回决策 |
| Evidence store failure      | block release gate                         |
| Policy conflict             | stricter action wins                       |
| Fusion error                | escalate                                   |
| Decision engine error       | fail-safe block                            |
| Enforcement failure         | block or return safe fallback              |

## 13.3 Fail-Open vs Fail-Closed

不同场景默认策略：

| 场景                             | 默认                        |
| ------------------------------ | ------------------------- |
| Public low-risk FAQ            | fail-open with log        |
| Enterprise confidential data   | fail-closed               |
| Tool execution                 | fail-closed               |
| External communication         | fail-closed               |
| Data export                    | fail-closed               |
| Regulated data                 | fail-closed               |
| Model output with unknown risk | fail-safe redact/escalate |

## 13.4 Risk-Based Rate Limiting and Circuit Breaker

MCP / tool 层的限流必须是 **risk-based**，不能简单照搬后端 API 的最大限速。这里要防的不是普通 API 流量，而是 MCP/agent 误调用或滥用导致的 operational blast radius。

限流维度应包含：

- user_id / user role；
- tenant_id；
- MCP client identity；
- MCP server identity；
- tool_id 与 tool risk level；
- action type；
- resource scope；
- environment；
- data classification；
- burst 与 sustained window。

默认姿态（default posture）：

| Tool / Action Type        | Default Rate Limit Posture                  |
| ------------------------- | ------------------------------------------- |
| read-only inventory query | higher limit                                |
| low-risk metadata update  | moderate limit                              |
| configuration change      | low limit + audit                           |
| firmware update / reboot  | very low limit + explicit confirmation      |
| broad batch operation     | approval / change control / circuit breaker |

对高风险工具，限流被突破应产生归一化信号：

- risk_family: `TOOL_ABUSE`
- risk_type: `TOOL_RATE_LIMIT_EXCEEDED`
- recommended_mitigation: `block` 或 `require_approval`

Circuit breaker 必须在以下情况启用：重复的高风险工具尝试、异常的 allow-rate 升高、重复的 confirmation 失败、tool execution loop。

***

# 14. Security and Compliance

## 14.1 数据最小化

系统不得默认存储完整原始 prompt/output。  
默认保存：

* content\_hash
* redacted sample
* span hash
* detector evidence
* policy snapshot
* context minimal fields

## 14.2 Encryption

必须支持：

* in-transit TLS
* at-rest encryption
* KMS-managed keys
* region-specific key
* tenant isolation key optional

## 14.3 Access Control

访问 trace/evidence 需要细粒度权限：

| Role               | 权限                      |
| ------------------ | ----------------------- |
| Runtime service    | 写 trace                 |
| Security engineer  | 查脱敏 trace               |
| Compliance auditor | 查 evidence metadata     |
| Incident responder | 查高风险 case               |
| Tenant admin       | 查本租户范围                  |
| Developer          | 查 eval aggregate，不查敏感内容 |

## 14.4 China Region Compliance

中国区策略建议：

1. CN 数据默认本地存储。
2. PII trace 保存脱敏样本。
3. 支持 TC260 相关分类标签。
4. 数据跨境检测作为 policy rule。
5. 审计证据按区域 retention class 管理。
6. region policy 不应由 tenant/app override 降级。

## 14.5 Transport Trust and Certificate Policy

所有 MCP / tool-mediated 的 service-to-service 流量在生产环境必须使用 TLS。对高风险工具执行，应优先使用 mTLS 或 workload identity（在支持的前提下）。

Self-signed certificate 仅在隔离的 lab / PoC 环境可接受，**不得作为生产默认模式**。生产流量必须使用由受信任的公共 CA 或企业/内部 CA 签发的有效证书链。

控制平面必须将证书与传输失败归类为 `TRANSPORT_TRUST_RISK` 或 `SYSTEM_FAILURE`，且在 transport trust 无法验证时**不得 silent allow 高风险工具执行**。

最小证书校验要求：

- 证书链必须受信任；
- 证书不得过期；
- hostname / SAN 必须与 endpoint 匹配；
- 生产环境不得关闭 TLS 校验；
- MCP/tool 调用应在 trace 中记录 certificate fingerprint 或 workload identity；
- 必须支持证书轮换与到期监控。

对 PoC 环境，客户端可显式 trust 某个 self-signed certificate 或内部 CA bundle，但必须标记 `environment=lab|poc`，且**不得通过生产 release gate**（见 §9）。

对应 policy 示例（生产工具执行要求受信任 TLS 链）：

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

# 15. Observability

## 15.1 Metrics

必须暴露：

```text
guardrail_requests_total
guardrail_decision_allow_total
guardrail_decision_block_total
guardrail_decision_redact_total
guardrail_decision_escalate_total
guardrail_latency_p95
detector_latency_p95
detector_timeout_total
policy_conflict_total
trace_write_failure_total
evidence_generation_failure_total
release_gate_fail_total
critical_miss_rate
false_positive_rate
false_negative_rate
```

## 15.2 Logs

日志不得包含原始敏感内容。  
必须包含：

* trace\_id
* request\_id
* tenant\_id hash
* app\_id
* policy\_snapshot\_id
* decision action
* reason code
* latency
* error code

对 `tool_pre_execution`、`tool_post_execution`、`agent_plan_check`、`agent_step_check`，日志必须额外包含：

* mcp_client_id
* mcp_server_id
* tool_id
* tool_version
* tool_manifest_hash
* tool_risk_level
* operation_type
* resource_scope_hash
* northbound_api_id
* northbound_api_endpoint_pattern
* api_auth_method
* transport_trust_status
* certificate_fingerprint_hash（适用时）
* confirmation_required
* confirmation_status
* approval_type
* action_hash（disruptive 操作）
* prompt_injection_signal
* rate_limit_decision
* enforcement_result

## 15.3 Alerts

必须告警：

| 告警                     | 条件                     |
| ---------------------- | ---------------------- |
| Critical miss spike    | critical miss rate 超阈值 |
| Detector timeout spike | timeout rate 超阈值       |
| Block rate anomaly     | block rate 异常升高        |
| Allow rate anomaly     | high-risk allow 异常升高   |
| Trace failure          | trace 写入失败             |
| Evidence gap           | evidence 缺失            |
| Policy conflict spike  | 策略冲突异常                 |
| Release gate fail      | 发布门禁失败                 |
| Latency breach         | p95/p99 超阈值            |

## 15.4 SLO / Error Budget

仅有 metrics/alerts 不足以支撑 SRE 值班，必须定义 SLO 与错误预算：

| SLO                              | 目标            | Error Budget（30d） |
| -------------------------------- | ------------- | ----------------- |
| Decision API availability        | ≥ 99.9%       | ~43 min           |
| Input guardrail latency p95      | < 50ms        | ≤ 1% 窗口超标         |
| Output guardrail latency p95     | < 80ms        | ≤ 1% 窗口超标         |
| Minimal trace coverage           | 100%          | 0 容忍              |
| Critical miss rate（高风险族）         | < 阈值（按 §8.3）   | 0 容忍/快速烧尽         |

Dashboard 必须支持按 `stage`、`risk_family`、`policy_snapshot_id`、`detector_version` 过滤。

## 15.5 SRE Runbook v0.1

每个 P0/P1 alert 必须有 runbook，且必须定义 impact / auto action / manual triage / rollback / exit criteria。示例：

```yaml
alert: evidence_generation_failure_spike
severity: P0
impact: high-risk decisions may lack audit evidence
auto_action:
  - block release gate
  - switch high-risk stage to fail-safe escalate
manual_triage:
  - check evidence-service error rate
  - check storage dependency
  - sample affected trace_ids
rollback:
  - rollback evidence-service image
  - rollback policy if evidence_required newly enabled
exit_criteria:
  - evidence_generation_failure_rate < threshold for 3 consecutive windows
```

告警分级与响应矩阵（最小集）：

| Alert                     | Severity | 自动降级动作                            |
| ------------------------- | -------- | --------------------------------- |
| critical_miss_spike       | P0       | block gate + 高风险 stage fail-safe |
| evidence_generation_failure_spike | P0 | block gate + 高风险 stage escalate  |
| minimal_trace_commit_failure | P0    | 高风险 stage fail-closed             |
| detector_timeout_spike    | P1       | detector 降级 + SYSTEM_FAILURE 信号   |
| policy_conflict_spike      | P1       | stricter action wins + 通知 policy owner |
| latency_breach            | P2       | 扩容 / 降级慢路径 detector              |

***

# 16. Engineering Implementation Plan

## 16.1 P0: Runtime Decision Closed Loop（Vertical Slice）

> P0 不再横向铺开各层，而是收敛为**一个可进 canary 的完整闭环**。

### Scope

```text
Stages:
- input_precheck
- model_output_check

Risks:
- PII_LEAKAGE
- PROMPT_INJECTION
- ENTERPRISE_CONFIDENTIAL_LEAKAGE
- SYSTEM_FAILURE

Actions:
- allow
- log_only
- redact
- block

Modes:
- monitor
- active

Region:
- CN enterprise strict profile
```

### P0 必须做

```text
1.  /v1/guardrail/decision（schema validation）
2.  Context Builder minimal authoritative fields（含 authority matrix）
3.  Detector plugin interface
4.  PII detector v0
5.  Prompt injection detector v0
6.  Confidential detector v0
7.  Normalized signal schema v0（含 SYSTEM_FAILURE 信号）
8.  Fusion v0：max severity + confidence rule
9.  Policy runtime v0：static immutable snapshot + YAML rules
10. Decision engine v0：action synthesis + reason code + stage×action 校验
11. Input/output enforcement
12. Minimal synchronous trace commit
13. Replay CLI
14. Evaluation card v0
15. Release gate dry-run only
```

### P0 不做（明确延后）

```text
- tool approval workflow full implementation
- RAG chunk removal full implementation
- multi-region policy isolation
- tenant admin dashboard
- advanced fusion ML model
- human review queue
- auto rollback
```

### P0 Exit Criteria

```text
1.  100% decision has trace_id（minimal commit）。
2.  100% non-allow decision has reason_code。
3.  Policy change does not require app code change。
4.  Detector cannot directly block。
5.  Replay can reproduce previous decisions with same versions（见 §0.4）。
6.  Monitor mode and active mode both work。
7.  PII redaction produces structured output。
8.  Context missing does not silently allow。
9.  Policy snapshot unavailable does not silently allow。
10. Benchmark report generated for each detector。
```

***

## 16.2 P1: Policy and Evidence Hardening

目标：策略与证据生产级化。

交付：

1. policy DSL
2. policy validate/lint
3. policy snapshot
4. matched rules trace
5. evidence service
6. PII redaction enforcement
7. policy dry-run
8. release gate basic
9. eval metrics v0

P1 验收：

| 验收项             | 标准                              |
| --------------- | ------------------------------- |
| Policy snapshot | 每次 decision 绑定 snapshot         |
| Dry-run         | 新策略可在历史 trace 上模拟               |
| Evidence        | block/redact 必有 evidence        |
| Gate            | detector/policy 发布可自动 pass/fail |
| Redaction       | PII 可结构化脱敏                      |

***

## 16.2.5 P1.5: MCP / Tool Security Readiness Slice

目标：在不完整实现 Agent Security 的情况下，先为 MCP / tool-calling 场景提供最小可用安全控制（适合作为 XClarity One / MCP 集成的最小可落地安全交付）。

Scope：

```text
stage:
- tool_pre_execution

risks:
- TOOL_ABUSE
- UNAUTHORIZED_ACCESS
- PROMPT_INJECTION
- TRANSPORT_TRUST_RISK
- UNSAFE_AUTOMATION
- SYSTEM_FAILURE

actions:
- allow
- block
- require_approval
- escalate
- log_only
```

必须实现：

```text
1. Tool-to-API Trust Chain Context
2. Tool Argument Security Contract
3. Tool Risk Schema extension for operational infrastructure tools
4. Transport Trust Policy
5. Explicit Confirmation Contract（require_approval + approval_type）
6. Risk-based rate limiting metadata
7. Tool execution minimal trace
8. Policy rules for high-risk tool approval
9. Release gate checks for tool schema update
```

P1.5 Exit Criteria：

```text
1. 高风险工具未经 policy decision 不可执行。
2. disruptive action 未经显式确认不可执行。
3. 生产工具执行不可使用 untrusted / self-signed certificate。
4. 工具参数必须通过 schema 与 resource-scope 校验。
5. tool 执行决策必须含 trace_id、policy_snapshot_id、tool_id、resource_scope_hash、reason_code。
6. 通用任意 API wrapper 工具默认 block，除非 policy 显式批准。
```

> 价值说明：P1.5 既不抢占 XClarity One 的实现责任，又能给出可落地的安全架构贡献；它复用的是控制平面通用能力，未来可直接迁移到 xCloud、Token Hub、Enterprise Agent、AI Ops 等场景。

***

## 16.3 P2: Tool/RAG/Agent Readiness

目标：覆盖 Enterprise AI 关键 runtime 控制点。

交付：

1. RAG injection detector
2. RAG source trust check
3. tool pre-execution API
4. tool risk schema
5. require approval action
6. tool execution trace
7. agent step context
8. output leakage detector
9. canary release

P2 验收：

| 验收项              | 标准                           |
| ---------------- | ---------------------------- |
| Tool 拦截          | 高风险 tool 可 require approval  |
| RAG 安全           | 恶意 retrieved chunk 可移除/block |
| Agent 预留         | agent step 有 stage/context   |
| Canary           | policy/detector 可小流量发布       |
| Output Guardrail | 输出泄密可 redact/block           |

***

## 16.4 P3: Production-Grade Continuous Control

目标：完整生产闭环。

交付：

1. online sampling
2. offline benchmark management
3. human review queue
4. release gate advanced
5. drift detection
6. auto rollback
7. compliance dashboard
8. multi-region policy isolation
9. tenant-level reporting
10. SRE runbook

P3 验收：

| 验收项  | 标准                     |
| ---- | ---------------------- |
| 自动门禁 | 所有发布必须过 gate           |
| 自动回滚 | 指标破坏自动 rollback        |
| 合规审计 | 可按 trace/evidence 出具报告 |
| 多租户  | tenant 策略隔离            |
| 多区域  | region policy 生效且不可被降级 |
| 可观测  | metrics/logs/alerts 完整 |

***

# 17. Initial Engineering Backlog

## 17.1 Runtime API

* [ ] Implement `/v1/guardrail/decision`
* [ ] Implement request schema validation
* [ ] Add trace\_id/request\_id generation
* [ ] Add timeout budget propagation
* [ ] Add enforcement mode: monitor/active

## 17.2 Context Builder

* [ ] Define context schema
* [ ] Integrate tenant metadata source
* [ ] Integrate role/permission source
* [ ] Integrate data classification
* [ ] Generate context\_hash
* [ ] Fail-safe on missing required fields

## 17.3 Detector Framework

* [ ] Define detector plugin interface
* [ ] Implement parallel execution
* [ ] Add detector timeout
* [ ] Add detector version metadata
* [ ] Implement PII detector
* [ ] Implement prompt injection detector
* [ ] Implement confidential data detector

## 17.4 Signal Layer

* [ ] Define normalized signal schema
* [ ] Implement signal normalizer
* [ ] Implement fusion algorithm v0
* [ ] Add conflict recording
* [ ] Add signal evidence refs

## 17.5 Policy Runtime

* [ ] Define policy DSL
* [ ] Implement policy parser
* [ ] Implement validate/lint
* [ ] Implement policy snapshot
* [ ] Implement rule matching
* [ ] Implement priority resolution
* [ ] Implement dry-run

## 17.6 Decision Engine

* [ ] Define decision contract
* [ ] Implement action priority
* [ ] Implement reason code requirement
* [ ] Implement matched rule output
* [ ] Implement fail-safe decision
* [ ] Add explain output

## 17.7 Enforcement

* [ ] Implement allow/warn/block
* [ ] Implement structured redaction
* [ ] Implement safe refusal template
* [ ] Implement require\_approval placeholder
* [ ] Implement output guardrail

## 17.8 Trace/Evidence

* [ ] Define trace schema
* [ ] Implement trace service
* [ ] Implement evidence service
* [ ] Add content hashing
* [ ] Add redacted sample storage
* [ ] Add policy snapshot binding
* [ ] Add replayability flag

## 17.9 Evaluation/Gate

* [ ] Define evaluation card
* [ ] Implement offline replay
* [ ] Compute precision/recall/FPR/FNR
* [ ] Implement release gate rule
* [ ] Implement gate report
* [ ] Add canary result ingestion

***

# 18. Reference Runtime Pseudocode

```python
def guardrail_decision(request):
    runtime = init_runtime(request)

    context = context_builder.build(request)
    if not context.valid:
        return fail_safe_decision(
            request=request,
            reason="INVALID_CONTEXT"
        )

    detector_plan = orchestrator.plan(
        stage=request.stage,
        context=context
    )

    raw_results = detector_executor.run_parallel(
        plan=detector_plan,
        request=request,
        context=context,
        timeout_budget=runtime.timeout_budget
    )

    normalized_signals = signal_normalizer.normalize(
        raw_results=raw_results,
        context=context
    )

    fused_risk = signal_fusion.fuse(
        signals=normalized_signals,
        context=context
    )

    policy_snapshot = policy_runtime.resolve_snapshot(
        context=context
    )

    if policy_snapshot is None:
        return fail_safe_decision(
            request=request,
            reason="POLICY_SNAPSHOT_UNAVAILABLE"
        )

    matched_rules = policy_runtime.evaluate(
        context=context,
        fused_risk=fused_risk,
        policy_snapshot=policy_snapshot
    )

    decision = decision_engine.synthesize(
        context=context,
        fused_risk=fused_risk,
        matched_rules=matched_rules,
        policy_snapshot=policy_snapshot
    )

    enforcement_result = enforcement.apply(
        decision=decision,
        request=request
    )

    # Phase 1: synchronous minimal trace commit (mandatory before returning)
    minimal_trace = trace_builder.build_minimal(
        request_id=request.id,
        context_hash=context.hash,
        policy_snapshot_id=policy_snapshot.id,
        decision_id=decision.id,
        action=decision.action,
        reason_codes=decision.reason_codes,
    )

    trace_commit_result = trace_service.commit_sync(minimal_trace)

    if not trace_commit_result.success:
        decision = decision_engine.fail_safe(
            reason="TRACE_MINIMAL_COMMIT_FAILED",
            stage=request.stage,
            context=context,
        )

    # Phase 2: asynchronous rich evidence append (retryable, non-blocking)
    full_trace = trace_builder.build(
        request=request,
        context=context,
        raw_results=raw_results,
        normalized_signals=normalized_signals,
        fused_risk=fused_risk,
        policy_snapshot=policy_snapshot,
        matched_rules=matched_rules,
        decision=decision,
        enforcement_result=enforcement_result
    )

    trace_service.append_async(full_trace)

    return decision.to_response(enforcement_result)
```

***

# 19. Critical Engineering Rules

以下规则必须作为实现红线。

## 19.1 不允许 detector 直接 block

错误：

```python
if pii_detector.detect(content):
    return block()
```

正确：

```python
signal = pii_detector.detect(content)
decision = decision_engine.decide(context, signal, policy)
```

## 19.2 不允许无 trace 决策

任何 decision 在返回业务方前必须完成 **Minimal Trace Commit** 并绑定 trace\_id（见 §7.1）。high-risk stage 下 Minimal Trace Commit 失败必须 fail-closed。

## 19.3 不允许无 reason code 的非 allow 决策

block/redact/escalate/require\_approval 必须有 reason code。

## 19.4 不允许策略写死在业务代码中

策略必须进入 policy runtime。

## 19.5 不允许高风险 failure 默认 allow

context、policy、tool、regulated data、confidential data 场景必须 fail-safe。

## 19.6 不允许存储不必要的原始敏感内容

trace/evidence 默认保存 hash、redacted sample、span metadata。

## 19.7 不允许发布绕过 release gate

detector、policy、model、RAG、tool schema 变更必须进入 gate。

## 19.8 不允许高风险工具缺少显式确认

对 disruptive 或 irreversible 工具操作（如 firmware update、reboot、server configuration change、data export、batch infrastructure operation），decision engine 在执行前**必须**返回 `require_approval`，且 `approval_type = explicit_user_confirmation` 或更强等级。

通用的 “yes” 不足以满足要求。确认必须绑定 action、target resource、user、tool、version/configuration、blast radius、timestamp 与 action_hash（见 §0.2、§5 Decision Contract、§6.3 confirmation_policy）。

## 19.9 不允许仅依赖后端 API security 执行 MCP/tool 操作

MCP/tool 是 AI-mediated execution boundary（见 §2.3）。Northbound API security 是必要的 trust chain 一环，但 MCP/tool 层必须独立完成身份链路绑定、参数可信度校验、风险定级、显式确认与审计，不得以“后端已校验”为由跳过。

## 19.10 不允许生产环境默认使用不受信任的传输

生产工具执行必须使用受信任的证书链（trusted CA / enterprise CA），不得默认使用 self-signed certificate 或关闭 TLS 校验（见 §14.5）。lab/poc 显式信任配置不得通过生产 release gate。

***

# 20. Minimal Production Acceptance Criteria

系统进入生产前必须满足：

| 类别            | 最低要求                                  |
| ------------- | ------------------------------------- |
| Runtime       | API p95 < 80ms                        |
| Reliability   | 服务可用性 ≥ 99.9%                         |
| Trace         | 100% decision 有 trace                 |
| Policy        | 100% decision 有 policy\_snapshot\_id  |
| Evidence      | 100% block/redact/escalate 有 evidence |
| Evaluation    | 核心 detector 有 benchmark               |
| Release Gate  | policy/detector 变更必须 gate             |
| Replay        | 历史 trace 可重放                          |
| Redaction     | PII 脱敏准确率达标                           |
| Tool          | 高风险 tool pre-execution 可拦截            |
| Trust Chain   | 高风险工具执行必须绑定完整 trust chain（user→client→server→tool→API→resource） |
| Transport     | 生产工具执行不得使用 untrusted/self-signed certificate |
| Confirmation  | disruptive 操作必须 action-bound explicit confirmation |
| Tool Argument | 高风险工具参数必须 schema + resource-scope + policy 校验 |
| Tool Audit    | 企业 infrastructure 工具执行必须 mandatory audit logging（tool_id/risk/policy decision/confirmation/transport trust/injection signal） |
| Compliance    | CN 区域数据策略可强制执行                        |
| Observability | metrics/logs/alerts 完整                |
| Rollback      | 支持 policy/detector rollback           |

***

# 21. Recommended First Implementation Package

为了让工程团队快速启动，建议第一阶段直接实现以下包结构：

```text
cloud-guardrail/
  api/
    decision_api.py
    tool_api.py
    policy_api.py
  context/
    context_builder.py
    context_schema.py
  detectors/
    base.py
    pii_detector.py
    prompt_injection_detector.py
    confidential_detector.py
  signals/
    normalizer.py
    schema.py
    fusion.py
  policy/
    dsl.py
    parser.py
    validator.py
    runtime.py
    snapshot.py
  decision/
    engine.py
    contract.py
    reason_codes.py
  enforcement/
    input_enforcer.py
    output_enforcer.py
    redactor.py
  trace/
    trace_schema.py
    trace_service.py
    evidence_service.py
  eval/
    replay.py
    metrics.py
    release_gate.py
  observability/
    metrics.py
    logging.py
    alerts.py
  tests/
    unit/
    integration/
    replay/
```

***

# 22. Team Ownership Model

建议职责边界：

| 模块                           | Owner                         |
| ---------------------------- | ----------------------------- |
| Architecture / Contract      | AI Security Architect         |
| Runtime API                  | Platform Engineering          |
| Context Builder              | Platform + Identity/Data Team |
| Detector Framework           | AI Security Engineering       |
| PII/IP/Confidential Detector | Security ML / Rule Team       |
| Policy Runtime               | Security Platform             |
| Decision Engine              | Security Platform             |
| Enforcement                  | App Integration Team          |
| Trace/Evidence               | Data Platform + Security      |
| Evaluation                   | AI Safety Evaluation Team     |
| Release Gate                 | DevOps/SRE + Security         |
| Compliance Policy            | Legal/Compliance + Security   |
| Tool/Agent Security          | Agent Platform + Security     |

***

# 23. Key Design Rationale

## 23.1 为什么必须是控制平面？

Enterprise AI 会快速扩散到多个业务系统。  
如果每个应用各自实现 guardrail，会出现：

* 策略不一致
* 审计不完整
* detector 重复建设
* 无法统一评估
* 无法统一回滚
* 合规不可证明

控制平面可以把运行时安全从应用逻辑中抽离出来，变成可治理的平台能力。

## 23.2 为什么必须有 Context？

AI 安全不是文本分类问题，而是上下文决策问题。  
同样内容在不同 tenant、role、region、data classification、tool permission 下会有不同决策。

没有 context 的安全系统只能做粗暴 block，最终导致高误报或高漏报。

## 23.3 为什么 detector 不能直接决策？

Detector 是感知层，不是治理层。  
最终决策需要综合：

* detector confidence
* severity
* business context
* policy
* region compliance
* tool risk
* data classification
* historical evidence

因此 detector 输出 signal，decision engine 输出 action。

## 23.4 为什么 trace/evidence 是核心？

Enterprise AI 安全不是只要“拦住”就够。  
必须能够回答：

* 为什么拦？
* 依据哪条策略？
* 哪个 detector 命中？
* 当时上下文是什么？
* 是否误报？
* 新策略会不会改变结果？
* 是否满足合规审计？

这些都依赖 trace/evidence。

## 23.5 为什么 release gate 必不可少？

AI 安全策略和 detector 会不断更新。  
任何变更都可能导致：

* 误报上升
* 漏报上升
* 延迟上升
* 合规失效
* 工具调用被错误放行
* 业务流程被错误阻断

Release gate 是防止安全系统自身引入生产风险的关键机制。

***

# 24. Final Architecture Definition

最终系统可以被压缩定义为：

```text
Cloud Native Enterprise AI Security Control Plane
= Enterprise Context
+ Parallel Risk Detection
+ Normalized Signal Fusion
+ Policy Runtime
+ Decision Contract
+ Enforcement Points
+ Decision Trace
+ Evidence Store
+ Continuous Evaluation
+ Release Gate
+ Audit Replay
```

它的最终交付不是一个 detector，而是一套企业 AI 运行时安全治理基础设施。

***

# 25. Engineering Start Checklist

工程团队可以立即按以下顺序启动：

1. 固定 `Decision Contract`。
2. 固定 `Enterprise Context Schema`。
3. 固定 `Normalized Signal Schema`。
4. 实现 `/v1/guardrail/decision`。
5. 实现 3 个基础 detector。
6. 实现 policy runtime v0。
7. 实现 decision engine v0。
8. 实现 input/output enforcement。
9. 实现 trace minimal schema。
10. 实现 offline replay。
11. 加入 evaluation metrics。
12. 加入 release gate。
13. 扩展 RAG 与 tool pre-execution。
14. 进入 canary 和 production hardening。

***

## 26. 工程附件拆分建议

为让本设计从“架构书”进入“可实施工程包”，建议在本文档之外维护 6 个工程附件，并以本文 §0 为唯一 enum/contract 源：

1. **Contract Spec**：Context Schema、Normalized Signal Schema、Decision Contract、Trace/Evidence Schema。
2. **Policy DSL Spec**：grammar、operators、examples、lint rules、conflict resolution（基于 §6 Step 7）。
3. **Runtime Semantics Spec**：stage enum、action state machine、fail-safe matrix、detector failure semantics、trace commit semantics。
4. **API Spec**：Decision API、Tool Pre-Execution API、Policy Validate/Dry-run API、Trace Ingest API、Release Gate API。
5. **Evaluation & Release Gate Spec**：evaluation card、replay report、required slices、gate blocking rules、rollback protocol。
6. **Implementation Backlog & Test Plan**：P0/P1/P2 tasks、owner、acceptance criteria、unit/integration/replay tests、SRE runbook。

***

## 27. 附录：MCP / Tool-Calling 具体问题 → 设计落点映射

下表把 MCP / Northbound API 集成中的具体安全问题映射到本文的修订落点与抽象后的工程机制，可作为对外沟通的核心说明：

| 具体问题                                       | 设计落点                                          | 抽象后的工程机制                                                                       |
| ------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------ |
| MCP client 需匹配 Northbound public key        | §5 Tool-to-API Trust Chain Context            | public key 只是 trust signal；必须绑定 user/client/server/tool/API/resource/action     |
| 只依赖 Northbound API security 是否足够            | §2.3 + §3 Principles + §19.9                   | MCP 是 AI-mediated execution boundary，需要 MCP-level enforcement                   |
| MCP server 层应做什么                            | §6.3 Tool Pre-Execution Enforcement           | policy enforcement point：authz、argument validation、risk、approval、trace          |
| public key 放 env var 是否 OK                  | §14.5 + §9 Release Gate                        | PoC 可接受；production 应走 secret/cert management；gate 阻断不合规配置                       |
| HTTPS + self-signed certificate             | §14.5 Transport Trust Policy                  | lab 可显式 trust；production 必须 trusted CA chain，不得关闭校验                            |
| Northbound API 已 sanitize 是否足够             | §6.3 Tool Argument Security Contract          | backend validation 必须保留，但 MCP 层须验证 intent/schema/source/scope/risk             |
| MCP tool 是否还要 sanitize                      | §6.3 + §7 Policy                               | structured typed argument，不允许 raw NL 直接进高风险 API                               |
| prompt injection（tool 级）                    | §3.8 Instruction/Data Separation + Detector/Policy | 外部内容默认 data，不得变 instruction；高风险工具受影响时 block/escalate/approval               |
| rate limit                                  | §13.4 Risk-Based Rate Limiting                | 按 user/tenant/client/tool/resource/action/risk 分级限流 + circuit breaker          |
| disruptive action confirmation              | §0.2 + §5 + §19.8 Explicit Confirmation        | confirmation 绑定 action/target/impact/user/timestamp/hash                       |
| logging bare minimum                        | §7 Trace + §15.2 Observability                | tool_id/risk/policy decision/confirmation/API result/transport trust/injection |
| tool logging 是否通用要求                        | §20 Minimal Production Acceptance Criteria     | enterprise infrastructure tool 必须 mandatory audit logging                       |

***

## 结论

这套设计的核心不是“多加几个检测器”，而是建立一套企业级 AI 安全控制平面。

它通过：

* **Context** 理解企业场景；
* **Signal** 统一风险表达；
* **Policy** 表达治理规则；
* **Decision** 输出确定动作；
* **Enforcement** 落地执行；
* **Trace/Evidence** 支撑审计；
* **Evaluation/Gate** 保证持续演进；

最终形成一个可以支撑 xCloud、Token Hub、Enterprise AI、RAG、Tool Calling、Agentic Workflow 的云原生 AI 安全基础设施。

工程团队应以本文档中的 **contract、schema、API、policy DSL、trace/evidence、eval/gate** 作为第一优先级实现对象，先搭建可运行闭环，再逐步扩展 detector、policy family、tool/agent control 与合规能力。
