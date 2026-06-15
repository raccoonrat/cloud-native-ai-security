# Cloud Native Enterprise AI Security Control Plane

## 企业云原生 AI 安全控制平面完整设计书 V1.0

**定位**：本文档面向工程团队、平台团队、安全团队、SRE 团队与产品集成团队，定义一套可直接落地实施的 **Cloud Native Enterprise AI Security Control Plane**。  
**目标**：为企业 AI 应用、RAG、Agent、Tool Calling、模型输出等运行时链路提供统一的安全决策、策略执行、证据审计、评估门禁与持续演进能力。

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
  "input_type": "user_prompt",
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

***

### Step 3: Request Orchestrator 编排检测路径

Orchestrator 根据 request type 决定执行哪些 detector。

请求类型包括：

| request\_type         | 检测路径                                                       |
| --------------------- | ---------------------------------------------------------- |
| user\_prompt          | prompt injection, PII, confidential data, policy violation |
| rag\_query            | query safety, data access, RAG injection                   |
| retrieved\_context    | RAG injection, confidential data, source trust             |
| tool\_pre\_execution  | tool abuse, permission, argument risk                      |
| tool\_post\_execution | result leakage, PII, confidential data                     |
| model\_output         | output leakage, compliance, hallucinated secret            |
| agent\_plan           | unsafe automation, tool chain risk                         |
| batch\_eval           | offline replay detectors                                   |

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
| 失败可见         | failure signal 也要进入 trace     |
| 不私自拦截        | 不得绕过 decision engine          |
| 可评估          | 每个 detector 独立产出 eval metrics |

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
    "stage": "input",
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

## 7.2 Policy DSL 示例

```yaml
policy_id: pol_cn_pii_output_redact
version: 1.0.0
scope:
  region: CN
  tenant: "*"
  app: "*"

when:
  stage: output
  risk_family: PII_LEAKAGE
  data_attributes:
    data_subject: customer
    data_classification:
      in: [confidential, restricted]

then:
  action: redact
  severity: high
  reason_code: CN_PII_OUTPUT_REDACTION_REQUIRED
  mitigation:
    redaction_mode: structured
    preserve_semantics: true

audit:
  evidence_required: true
  retention_class: regulated
```

Tool pre-execution policy 示例：

```yaml
policy_id: pol_tool_pre_exec_high_risk_block
version: 1.0.0
scope:
  tenant: "*"
  app: "*"

when:
  stage: tool_pre_execution
  tool:
    risk_level:
      in: [high, critical]
  user:
    approval_status:
      not_in: [approved]

then:
  action: require_approval
  severity: high
  reason_code: TOOL_EXECUTION_REQUIRES_APPROVAL
```

Prompt injection 示例：

```yaml
policy_id: pol_prompt_injection_block_critical
version: 1.0.0

when:
  risk_family: PROMPT_INJECTION
  severity:
    in: [critical]
  confidence:
    gte: 0.85

then:
  action: block
  reason_code: CRITICAL_PROMPT_INJECTION_BLOCKED
  severity: critical
```

## 7.3 Policy Runtime 必须支持的能力

| 能力           | 说明                          |
| ------------ | --------------------------- |
| Validate     | 策略语法和字段校验                   |
| Lint         | 检测冲突、不可达规则、缺失 reason code   |
| Dry-run      | 在历史 trace 上模拟执行             |
| Snapshot     | 每次发布生成 policy\_snapshot\_id |
| Rollback     | 支持回滚到指定 snapshot            |
| Diff         | 支持策略版本差异比较                  |
| Canary       | 小流量灰度策略                     |
| Explain      | 输出命中规则和冲突处理                 |
| Replay       | 历史请求按旧/新策略重算结果              |
| Multi-region | 支持区域策略隔离                    |

***

### Step 8: Decision Engine 决策合成

Decision Engine 将 policy runtime 的候选动作合成为最终决策。

支持动作：

```text
allow
warn
redact
block
escalate
require_approval
log_only
```

动作优先级：

```text
block > require_approval > escalate > redact > warn > allow > log_only
```

注意：  
在具体业务里，`redact` 与 `block` 的优先级要根据 stage 判断。

例如：

* input 中包含无法安全处理的 critical secret → block
* output 中包含 PII 但可精准脱敏 → redact
* tool pre-execution 涉及不可逆高风险操作 → require\_approval
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

Decision Engine 必须保证：

1. 无 policy snapshot 不决策。
2. 无 context 不 allow。
3. detector failure 必须参与决策。
4. 所有决策必须有 reason code。
5. 所有非 allow 决策必须有 mitigation 或 escalation path。
6. 所有决策必须写 trace。
7. 相同输入、相同上下文、相同 policy snapshot 下结果可 replay。

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
| regenerate | 可选：要求模型重写安全输出 |

Output Guardrail 必须避免：

1. 输出个人敏感信息。
2. 输出企业机密。
3. 输出跨租户数据。
4. 输出未经授权的内部信息。
5. 输出工具执行后的敏感结果。
6. 输出受策略禁止的内容。

***

# 7. Trace and Evidence Design

## 7.1 Decision Trace 是唯一事实源

每次请求必须生成 trace。  
Trace 是后续所有审计、评估、debug、release gate、policy replay 的基础。

标准 trace schema：

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
    "stage": "output",
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

## 8.3 Evaluation Card

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

## 9.1 Gate 示例

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

## 9.2 Gate 状态

| 状态                       | 行为         |
| ------------------------ | ---------- |
| PASS                     | 可发布        |
| CONDITIONAL\_PASS        | 仅允许 canary |
| FAIL                     | 阻止发布       |
| ROLLBACK\_REQUIRED       | 自动回滚       |
| MANUAL\_REVIEW\_REQUIRED | 人工审查       |

## 9.3 自动回滚条件

以下情况必须自动回滚：

1. critical miss rate 超阈值。
2. latency p95/p99 超阈值且影响生产。
3. block rate 异常升高。
4. allow rate 异常升高且伴随高风险漏检。
5. policy conflict rate 超阈值。
6. detector crash/timeout rate 超阈值。
7. replay consistency 低于阈值。
8. evidence generation failure。

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
  "request_id": "req_123",
  "stage": "input",
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

```text
allow
log_only
warn
redact
block
escalate
require_approval
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
| Trace async write     | 非阻塞        |
| Total input guardrail | 50ms       |
| Tool pre-execution    | 80ms       |
| Output guardrail      | 80ms       |

## 13.2 Failure Handling

| 失败类型                        | 默认行为                                       |
| --------------------------- | ------------------------------------------ |
| Context missing             | escalate/block                             |
| Policy snapshot unavailable | block for high-risk stage                  |
| Detector timeout            | mark detector\_failure signal              |
| PII detector failure        | high-risk context 下 redact/block           |
| Trace write failure         | allow only if low risk; high risk escalate |
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

***

# 16. Engineering Implementation Plan

## 16.1 P0: MVP Runtime Backbone

目标：跑通最小闭环。

交付：

1. `/v1/guardrail/decision` API
2. context schema
3. normalized signal schema
4. 3 个基础 detector：
   * prompt injection
   * PII
   * confidential data
5. signal fusion v0
6. policy runtime v0
7. decision contract
8. input/output enforcement
9. trace minimal schema
10. offline replay skeleton

P0 验收：

| 验收项         | 标准                               |
| ----------- | -------------------------------- |
| API 可用      | 支持 input/output 请求               |
| Trace 完整    | 每次 decision 有 trace              |
| Policy 可配置  | 不改代码可调整策略                        |
| Detector 并行 | 至少 3 个 detector 并发               |
| Replay 可跑   | 可对历史 trace 重放                    |
| Fail-safe   | context/policy failure 不默认 allow |

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

    trace = trace_builder.build(
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

    trace_service.write_async(trace)

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

任何 decision 都必须绑定 trace\_id。

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
