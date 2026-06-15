下面是我以“顶级 AI 安全团队首席架构师 + 实施官”的视角，对[\[4\]Cloud Native Enterprise AI Security Control Plane.md](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md?EntityRepresentationId=fbd323bd-d4dd-4f80-a1b9-ed42db5590ec) 做的严格工程审阅。整体判断：这份设计的方向是正确的，已经从“detector/filter”上升到“Enterprise AI runtime security control plane”，并覆盖了 Context、Signal、Policy、Decision、Enforcement、Trace/Evidence、Evaluation、Release Gate 等关键闭环；但它目前更像**完整架构蓝图**，还没有完全转化为一线开发者可直接实现、可测试、可验收、可值班运维的工程规格。文档明确把系统定位为面向企业 AI、RAG、Agent、Tool Calling、模型输出链路的统一安全决策、策略执行、证据审计、评估门禁与持续演进能力，这个定位是成立的。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

# 1. 总体评审结论

## 1.1 设计优点：架构方向正确，但需要“工程收敛”

[\[4\]Cloud Native Enterprise AI Security Control Plane.md](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md?EntityRepresentationId=fbd323bd-d4dd-4f80-a1b9-ed42db5590ec) 的最大优点是：它没有把 Cloud Guardrail 设计成单点 detector，而是明确提出了 **Context → Signals → Policy → Decision → Enforcement → Trace → Evaluation → Release Gate** 的控制平面闭环；文档也强调 detector 不应直接决策，而应输出 signal，由 fusion、policy runtime 和 decision engine 合成最终动作。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

从 DTL/Tianmu 与 xCloud 的 Cloud-Native AI Security 需求来看，这个方向非常重要：它可以把 Personal AI 中偏 input/output guardrail 的经验，扩展成 Enterprise AI 所需的多租户、多区域、多角色、多数据属性、多工具调用、多证据审计能力。文档中也已经明确区分了 input、RAG、tool pre-execution、tool post-execution、model output、agent plan 等 runtime stage。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

但是，从一线开发者角度看，当前版本仍存在一个核心问题：**概念完整，但实现边界还不够硬；模块多，但 contract、状态机、错误语义、测试入口、灰度路径和运行时降级规则还不够可执行。**

我的建议是：不要继续扩大架构范围，而是把这份设计压缩成三类工程资产：

1. **强约束 Contract**：Context Schema、Normalized Signal Schema、Decision Contract、Trace/Evidence Schema、Policy DSL Schema。
2. **强约束 Runtime Semantics**：stage/action/state machine、fail-safe matrix、detector failure semantics、policy conflict semantics、trace write semantics。
3. **强约束 Delivery Package**：P0/P1/P2 backlog、接口定义、测试用例、release gate、runbook、SLO/SLA。

***

# 2. 必须优先修改的 12 个关键问题

下面每一点都按“一线开发可执行”的方式写：**问题 → 风险 → 修改建议 → 验收标准**。

***

## 2.1 必须统一 stage 命名：现在存在 input/user\_prompt/model\_output/output 混用

### 问题

文档中同时出现了 `user_prompt`、`rag_query`、`retrieved_context`、`tool_pre_execution`、`tool_post_execution`、`model_output`、`agent_plan` 等 request type；但在 API、policy DSL、decision contract、trace schema 中又使用 `stage: input`、`stage: output`、`stage: tool_pre_execution` 等表达。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

一线开发者会产生三个实现分叉：

* detector orchestrator 用 `request_type`
* policy runtime 用 `stage`
* trace/eval 用另一套 stage 名称

这会导致：

* policy 规则匹配失败；
* replay 时无法复现；
* eval dataset 标签无法对齐；
* dashboard 上无法聚合 stage 维度。

### 修改建议

新增一节：**Canonical Runtime Stage Enum**。只允许一套字段：`stage`。

建议定义为：

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
```

并要求：

```yaml
request_type: deprecated
```

所有模块只消费 `stage`，不得再用 `request_type` 做策略匹配。

### 验收标准

* 所有 API request/response 中只出现 `stage`。
* 所有 policy DSL 的 `when.stage` 使用 canonical enum。
* 所有 trace/eval/replay 数据集中 `stage` 字段一致。
* CI 中加入 schema test：发现非 enum stage 直接 fail。

***

## 2.2 必须把 Action 语义做成状态机，而不是简单优先级排序

### 问题

文档定义了动作：`allow`、`warn`、`redact`、`block`、`escalate`、`require_approval`、`log_only`，并给出默认优先级：`block > require_approval > escalate > redact > warn > allow > log_only`。同时 Output Enforcement 又额外出现了 `regenerate`。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

仅靠全局优先级不够，因为 action 语义依赖 stage：

* input 中 `redact` 后可以继续进入模型；
* output 中 `redact` 后可以返回用户；
* tool pre-execution 中 `redact` 没有明确语义；
* `require_approval` 是 pending state，不是最终 terminal decision；
* `regenerate` 出现在 output enforcement，但没有纳入全局 action enum。

### 修改建议

新增一节：**Decision Action State Machine**。

建议将 action 分为三类：

```yaml
terminal_actions:
  - allow
  - block
  - safe_complete

transform_actions:
  - redact
  - rewrite
  - remove_chunk
  - reduce_rank

human_or_async_actions:
  - warn
  - escalate
  - require_approval

observability_actions:
  - log_only
```

并为每个 stage 定义合法动作：

| Stage                          | allow | redact                | block | require\_approval | escalate | regenerate/rewrite |
| ------------------------------ | -----:| ---------------------:| -----:| -----------------:| --------:| ------------------:|
| input\_precheck                | ✅     | ✅                     | ✅     | ⚠️ limited        | ✅        | ❌                  |
| rag\_retrieved\_context\_check | ✅     | ✅ remove/redact chunk | ✅     | ❌                 | ✅        | ❌                  |
| tool\_pre\_execution           | ✅     | ❌ by default          | ✅     | ✅                 | ✅        | ❌                  |
| model\_output\_check           | ✅     | ✅                     | ✅     | ❌                 | ✅        | ✅ if supported     |
| agent\_plan\_check             | ✅     | ❌                     | ✅     | ✅                 | ✅        | ❌                  |

### 验收标准

* Decision Engine 必须校验 `stage × action` 合法性。
* 非法组合必须返回 `POLICY_ACTION_NOT_ALLOWED_FOR_STAGE`。
* `regenerate` 要么正式进入 action enum，要么从文档移除。
* `require_approval` 必须有 `approval_ticket_id` 或 `approval_workflow_ref`，否则不能返回给业务方。

***

## 2.3 Trace “异步写入”与“无 trace 不决策”存在工程矛盾，必须补 write-ahead trace

### 问题

文档一方面强调“任何 decision 都必须绑定 trace\_id”“不允许无 trace 决策”；另一方面伪代码里是 `trace_service.write_async(trace)`，并且 Trace async write 被设计为非阻塞。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果决策已经返回业务系统，但异步 trace 写失败，就会出现：

* 有安全动作、无审计证据；
* release gate/replay 无法覆盖该 case；
* 事故复盘无法证明当时为何 allow/block；
* 与“无 trace 决策”红线冲突。

### 修改建议

必须拆成两阶段 trace：

1. **Synchronous Minimal Trace Commit**
   
   * 在返回 decision 前同步写入最小 trace envelope。
   * 至少包含：`trace_id`、`request_id`、`context_hash`、`policy_snapshot_id`、`decision_id`、`action`、`reason_codes`、`timestamp`。

2. **Asynchronous Rich Evidence Append**
   
   * detector details、redacted sample、latency breakdown、evidence objects 可以异步补充。

建议伪代码改为：

```python
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

trace_service.append_async(full_trace)
return decision
```

### 验收标准

* 100% decision 返回前完成 minimal trace commit。
* full evidence async append 失败时必须产生 `EVIDENCE_APPEND_FAILED` event。
* release gate 必须检查 `minimal_trace_coverage == 100%`。
* 高风险场景下 minimal trace commit 失败必须 fail-closed。

***

## 2.4 Policy DSL 需要从示例变成正式语法，不然无法实现 validate/lint/diff

### 问题

文档给出了 policy DSL 示例，并要求 policy runtime 支持 validate、lint、dry-run、snapshot、rollback、diff、canary、explain、replay、multi-region。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

当前 DSL 只是样例，不是严格 grammar。一线开发者无法判断：

* 支持哪些 operator；
* nested field 如何引用；
* enum 校验在哪做；
* scope 与 when 冲突如何处理；
* 多条 rule 命中后如何排序；
* region/global 强制规则如何不可降级。

### 修改建议

新增 **Policy DSL v0.1 Spec**，先不要追求强大，优先可实现。

建议限定 operator：

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

建议 policy 结构固定为：

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
      all:
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

### 验收标准

* Policy validator 基于 JSON Schema 或 OpenAPI Schema 实现。
* Linter 至少检查：
  * missing `reason_code`;
  * invalid action for stage;
  * unreachable rule;
  * duplicate priority;
  * region mandatory rule overridden by lower-level policy;
  * evidence\_required=false for high/critical action。
* Diff 输出必须包含：
  * added rules;
  * removed rules;
  * changed conditions;
  * changed actions;
  * affected historical trace count。

***

## 2.5 Context Builder 必须明确“权威源”，否则安全上下文不可信

### 问题

文档强调 Context Builder 是安全判断基础，必须包含 tenant、user、app、workflow、data、region、policy 等字段，并且要求“不信任客户端，关键字段从服务端权威源解析”。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果没有定义每个字段的 authoritative source，一线开发容易直接相信 request body：

```json
"user": {
  "role": "legal_reviewer"
}
```

这会导致用户或上游系统伪造 role、data\_classification、region，从而绕过策略。

### 修改建议

新增 **Context Field Authority Matrix**：

| Context 字段           | 是否允许客户端传入                                  | 权威源                                 | 缺失时默认动作                 |
| -------------------- | ------------------------------------------:| ----------------------------------- | ----------------------- |
| tenant\_id           | limited                                    | identity/token issuer               | block                   |
| user\_id             | no                                         | auth token                          | block                   |
| role                 | no                                         | IAM / directory                     | escalate/block          |
| department           | no                                         | directory                           | warn/escalate           |
| app\_id              | limited                                    | app registry / mTLS client identity | block                   |
| data\_classification | no for stored data; limited for user input | data catalog / DLP classifier       | redact/escalate         |
| runtime\_region      | no                                         | deployment metadata                 | block if mismatch       |
| storage\_region      | no                                         | storage control plane               | block if regulated      |
| tool\_permission     | no                                         | tool registry + IAM                 | require\_approval/block |

### 验收标准

* Context Builder 不允许直接 trust request body 中的 role、region、clearance、tool permission。
* 每个 context 字段必须包含：
  * `value`;
  * `source`;
  * `source_trust_level`;
  * `resolved_at`;
  * `freshness_ttl_ms`。
* 缺失 mandatory context 字段不得 allow。

***

## 2.6 Detector failure 不能只是 signal，必须有标准失败类型和降级策略

### 问题

文档要求 detector timeout/failure 也要进入 trace，并且 high-risk context 下 PII detector failure 要 redact/block。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果 detector failure 只是普通 signal，一线实现可能无法区分：

* detector timeout；
* detector crash；
* detector unavailable；
* detector returned invalid schema；
* detector skipped by orchestrator；
* detector disabled by config；
* detector degraded model unavailable。

这些失败类型的安全含义不同。

### 修改建议

新增 **Detector Failure Signal Schema**：

```json
{
  "signal_id": "sig_failure_001",
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

### 验收标准

* 所有 detector failure 必须归一化为 `SYSTEM_FAILURE` signal。
* Failure type enum 至少包括：
  * `TIMEOUT`;
  * `CRASH`;
  * `INVALID_OUTPUT`;
  * `DEPENDENCY_UNAVAILABLE`;
  * `SKIPPED_BY_POLICY`;
  * `VERSION_MISMATCH`;
  * `MODEL_UNAVAILABLE`。
* Decision Engine 必须包含 `failure_policy_matrix`。
* 高风险 stage 中 critical detector failure 不得 silent allow。

***

## 2.7 RAG 控制点需要补“chunk-level contract”，否则无法执行 remove infected chunk

### 问题

文档已经列出 RAG enforcement 控制点：query pre-check、retrieval source trust check、retrieved document scan、context packaging check、model input assembly check，并提出恶意 retrieved chunk 可 remove/block。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果没有 chunk-level contract，RAG detector 即使命中，也无法告诉 RAG pipeline：

* 移除哪个 chunk；
* 降权哪个 source；
* 哪个 span 是 hidden instruction；
* 是否允许 summary-only；
* 是否需要重新检索。

### 修改建议

新增 **RAG Chunk Security Contract**：

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
      "security_labels": ["RAG_INJECTION_SUSPECTED"],
      "allowed_action": "remove_chunk"
    }
  ]
}
```

### 验收标准

* RAG detector 输出必须包含 `chunk_id` 和 `span_hash`。
* Enforcement 必须支持：
  * `remove_chunk`;
  * `redact_chunk_span`;
  * `reduce_rank`;
  * `block_context`;
  * `summary_only`;
  * `require_source_verification`。
* Trace 中必须记录被移除 chunk 的 hash 和 reason code，而不是原文。

***

## 2.8 Tool Pre-Execution 需要补“side effect + reversibility + approval”正式模型

### 问题

文档已把 Tool Pre-Execution 作为 Agent Security 的关键预留接口，并要求检查 tool identity、authorization、argument risk、side effect、data access scope、approval requirement、reversibility、business impact。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

当前只是字段清单，没有可执行模型。一线开发会不知道如何给工具定级：

* `send_email` 是 medium 还是 high？
* `delete_file` 是否 critical？
* `update_crm` 何时 require approval？
* 参数变化是否改变风险等级？
* tool result 是否需要 post-execution scan？

### 修改建议

新增 **Tool Risk Schema v0.1**：

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

### 验收标准

* Tool registry 必须是 policy runtime 的输入，而不是硬编码在 app 里。
* Tool pre-execution decision 必须返回：
  * `allowed`;
  * `require_approval`;
  * `block`;
  * `argument_redaction_required`。
* 高风险工具必须有：
  * idempotency key；
  * audit event；
  * post-execution scan hook；
  * rollback/compensation note，若不可逆则标记 `irreversible=true`。

***

## 2.9 Evaluation 指标需要从“通用指标”变成“按风险族/阶段/动作分层”

### 问题

文档列出了 precision、recall、FPR、FNR、critical miss rate、latency、coverage、policy conflict rate、redaction accuracy、replay consistency 等核心指标。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果只做全局 precision/recall，会掩盖关键风险。例如：

* PII recall 高，但 prompt injection recall 低；
* input guardrail 好，但 tool pre-execution 漏检严重；
* overall latency OK，但 output p99 超标；
* redaction accuracy 高，但 structured field preservation 差。

### 修改建议

Evaluation Card 必须按以下维度切片：

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
```

新增 gate metric：

```yaml
critical_metrics:
  by_risk_family:
    PROMPT_INJECTION:
      recall_min: 0.92
      critical_miss_rate_max: 0.003
    PII_LEAKAGE:
      recall_min: 0.95
      redaction_accuracy_min: 0.98
    TOOL_ABUSE:
      critical_miss_rate_max: 0.001
  by_stage:
    tool_pre_execution:
      fail_closed_coverage: 1.0
    model_output_check:
      latency_p95_ms_max: 80
```

### 验收标准

* Release Gate 不允许只看 global average。
* 每个 risk family 至少有独立 benchmark。
* 每个 stage 至少有 smoke eval。
* P0 可以只覆盖 prompt injection、PII、confidential data，但 Evaluation Card schema 必须预留 slice 字段。

***

## 2.10 Release Gate 需要明确“谁触发、阻断什么、如何回滚”

### 问题

文档定义了 Release Gate 的对象：detector version、policy version、model version、prompt template、RAG pipeline、tool schema、context builder schema、fusion algorithm、decision engine logic、enforcement implementation，并给出 PASS、CONDITIONAL\_PASS、FAIL、ROLLBACK\_REQUIRED、MANUAL\_REVIEW\_REQUIRED 状态。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

如果不定义 gate integration point，一线团队会把 gate 做成报告，而不是发布阻断器。

### 修改建议

新增 **Release Gate Integration Spec**：

| 变更对象            | Gate 触发点                   | 阻断对象                | 回滚对象                     |
| --------------- | -------------------------- | ------------------- | ------------------------ |
| detector        | detector image promotion   | detector deployment | previous detector image  |
| policy          | policy snapshot publish    | policy activation   | previous snapshot        |
| tool schema     | tool registry update       | tool availability   | previous schema          |
| RAG pipeline    | pipeline config rollout    | traffic switch      | previous config          |
| decision engine | runtime service deployment | prod rollout        | previous service version |

Gate API 建议：

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

### 验收标准

* CI/CD pipeline 必须调用 release gate API。
* Gate FAIL 必须阻止 promotion。
* ROLLBACK\_REQUIRED 必须输出 rollback target。
* Gate report 必须进入 evidence store。

***

## 2.11 Observability 需要增加 SLO、错误预算和 runbook，而不仅是 metrics list

### 问题

文档列出了 guardrail request、decision count、latency、detector timeout、policy conflict、trace failure、evidence failure、critical miss rate 等 metrics，也列出了 alerts。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

仅有 metrics/alerts 不足以支持 SRE 值班。工程团队还需要：

* 哪些告警 P0/P1/P2；
* 谁响应；
* 自动降级动作是什么；
* 是否切换 fail-open/fail-closed；
* 如何确认是 detector 问题还是 policy 问题；
* 如何回滚。

### 修改建议

新增 **SRE Runbook v0.1**。

示例：

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

### 验收标准

* 每个 P0/P1 alert 必须有 runbook。
* 每个 runbook 必须定义：
  * impact；
  * auto action；
  * manual triage；
  * rollback；
  * exit criteria。
* SRE dashboard 必须支持按 `stage`、`risk_family`、`policy_snapshot_id`、`detector_version` 过滤。

***

## 2.12 P0 范围仍偏大，必须切成“可交付 vertical slice”

### 问题

文档 P0 包含 decision API、context schema、normalized signal schema、3 个 detector、signal fusion v0、policy runtime v0、decision contract、input/output enforcement、trace minimal schema、offline replay skeleton。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

### 风险

对一线团队来说，这仍然是横向铺开，容易每层都做一点，但没有一个完整闭环能进 canary。

### 修改建议

P0 应改为 **一个 vertical slice**：

> 只做 input\_precheck + model\_output\_check 两个 stage；只做 PII、Prompt Injection、Enterprise Confidential 三类风险；只做 allow/redact/block/log\_only 四个动作；只支持 monitor/active 两种 enforcement mode；只支持单 region CN enterprise strict policy profile。

P0 交付包：

```text
P0 Vertical Slice:
1. /v1/guardrail/decision
2. Context Builder minimal authoritative fields
3. Detector plugin interface
4. PII detector v0
5. Prompt injection detector v0
6. Confidential detector v0
7. Normalized signal schema v0
8. Fusion v0: max severity + confidence rule
9. Policy runtime v0: static snapshot + YAML rules
10. Decision engine v0: action synthesis + reason code
11. Input/output enforcement
12. Minimal synchronous trace
13. Replay CLI
14. Evaluation card v0
15. Release gate dry-run only
```

### 验收标准

* 能处理 100 条固定 benchmark cases。
* 每条 decision 有 trace。
* 每个 block/redact 有 reason code。
* Policy 修改不需要改业务代码。
* Replay 能重算同一批 trace。
* Active mode 可以真实拦截/redact。
* Monitor mode 只记录不拦截。

***

# 3. 建议直接加入文档的新章节

为了让一线开发者真正能按设计实现，我建议在[\[4\]Cloud Native Enterprise AI Security Control Plane.md](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md?EntityRepresentationId=fbd323bd-d4dd-4f80-a1b9-ed42db5590ec) 中新增以下章节。

***

## 3.1 新增章节：Canonical Enums and Contracts

必须一次性固定以下 enum：

```yaml
Stage:
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
```

这些风险族与文档中的初始 risk family taxonomy 一致，但需要从“建议列表”升级为“schema enum”。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

## 3.2 新增章节：Decision Determinism Rules

必须明确：

```text
Same request content hash
+ same context hash
+ same detector versions
+ same policy snapshot id
+ same fusion algorithm version
+ same decision engine version
= same decision
```

否则 replay consistency 无法成立。文档已经要求相同输入、相同上下文、相同 policy snapshot 下结果可 replay，但还需要把 detector/fusion/decision engine 版本也纳入 replay key。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

## 3.3 新增章节：Runtime Mode

建议增加：

```yaml
enforcement_mode:
  monitor:
    decision_effect: no blocking, trace only
  shadow:
    decision_effect: compare old/new policy, no production effect
  active:
    decision_effect: enforce allow/redact/block/approval
  canary:
    decision_effect: enforce for selected traffic only
```

当前文档 API 中已有 `enforcement_mode: active`，但没有系统定义 monitor/shadow/canary 的语义。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

## 3.4 新增章节：Schema Versioning and Compatibility

所有 contract 必须带版本：

```json
{
  "schema_version": "decision-contract/v1",
  "runtime_version": "guardrail-runtime/1.0.0",
  "policy_snapshot_id": "ps_20260614_001"
}
```

兼容规则：

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

# 4. 面向一线开发者的重写版工程任务清单

下面是我建议你直接放进文档末尾、让开发者可以开工的版本。

***

## 4.1 Runtime API Team

### Task R1：实现 `/v1/guardrail/decision`

必须支持：

```json
{
  "schema_version": "decision-request/v1",
  "request_id": "req_123",
  "stage": "input_precheck",
  "tenant_id": "tenant_a",
  "app_id": "sales_copilot",
  "content": {
    "type": "text",
    "value": "..."
  },
  "metadata": {
    "region": "CN",
    "workflow_id": "contract_summary",
    "data_classification_hint": "confidential"
  },
  "options": {
    "enforcement_mode": "monitor",
    "return_explanation": true
  }
}
```

验收：

* invalid schema 返回 400；
* invalid stage 返回 400；
* missing tenant/app/user context 不得 allow；
* 每次请求返回 `decision_id` 和 `trace_id`。

***

## 4.2 Context Team

### Task C1：实现 `context_hash`

必须保证：

```text
context_hash = hash(canonical_json(minimal_context))
```

minimal context 包含：

```json
{
  "tenant_id_hash": "...",
  "user_id_hash": "...",
  "role": "...",
  "app_id": "...",
  "workflow_id": "...",
  "data_classification": "...",
  "runtime_region": "...",
  "policy_profile": "..."
}
```

验收：

* 字段顺序变化不影响 hash；
* 原始 user id 不进入 trace；
* role/region 不信任客户端；
* context validation 失败进入 fail-safe。

***

## 4.3 Detector Team

### Task D1：实现 detector plugin interface

```python
class Detector:
    detector_id: str
    detector_version: str
    supported_stages: list[str]

    def detect(self, request, context, timeout_ms) -> RawDetectorResult:
        ...
```

验收：

* detector 不得返回 final action；
* detector timeout 必须返回 failure signal；
* detector result 必须有 version；
* raw result 必须可 normalize。

***

## 4.4 Signal Team

### Task S1：实现 normalized signal schema

```json
{
  "signal_id": "sig_123",
  "schema_version": "normalized-signal/v1",
  "risk_family": "PII_LEAKAGE",
  "risk_type": "CN_PHONE_NUMBER",
  "stage": "model_output_check",
  "source": {
    "detector_id": "pii_detector",
    "detector_version": "0.1.0"
  },
  "scope": {
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
  "evidence_refs": ["ev_123"]
}
```

验收：

* 所有 detector result 必须 normalize 成该 schema；
* 不合规 signal 进入 `SYSTEM_FAILURE.INVALID_DETECTOR_OUTPUT`；
* Fusion 只消费 normalized signal。

***

## 4.5 Policy Team

### Task P1：实现 policy validator/linter

最小 lint 规则：

```text
L001: non-allow action must have reason_code
L002: action must be valid for stage
L003: high/critical rule must require evidence
L004: region mandatory policy cannot be overridden by tenant/app
L005: duplicate rule priority
L006: unreachable rule
```

验收：

* policy validate API 可返回 line/field/message；
* lint warning 不阻断，lint error 阻断；
* policy snapshot 必须不可变。

***

## 4.6 Decision Team

### Task DE1：实现 action synthesis

输入：

```text
context + fused_risk + matched_rules + policy_snapshot
```

输出：

```text
decision contract
```

验收：

* 无 context 不 allow；
* 无 policy snapshot 不决策；
* 非 allow 必须有 reason code；
* 高风险 detector failure 必须影响 decision；
* invalid action-stage combination 必须 fail-safe；
* decision 必须绑定 trace id。

这些要求与文档中“Decision Engine 必须保证”的原则一致，但需要落实为单元测试。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

## 4.7 Trace/Evidence Team

### Task T1：实现 minimal trace sync commit

验收：

* decision 返回前必须完成 minimal trace commit；
* trace write failure 在 high-risk stage fail-safe；
* full evidence async append 失败进入 alert；
* trace 默认不保存原始敏感内容。

文档已经要求默认不保存完整原始 prompt/output，而保存 content hash、redacted sample、span hash、detector evidence、policy snapshot、context minimal fields；这应被实现为强制 schema 规则，而不是开发约定。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

## 4.8 Eval/Gate Team

### Task E1：实现 replay CLI

```bash
guardrail-replay \
  --trace-dataset prod_sample_202606 \
  --policy-snapshot ps_candidate_001 \
  --compare-with ps_current \
  --output replay_report.json
```

验收：

* 输出 changed decisions；
* 输出 new block/new allow；
* 输出 risk-family slice metrics；
* 输出 gate candidate result。

文档已有 policy dry-run API 示例，包括 total traces、decision changed、new blocks、new allows、potential regressions 和 gate\_result；建议把它落地为 CLI + API 两种入口。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

***

# 5. 对现有架构图/流程的修改建议

当前 High-Level Architecture 是线性流：

```text
Ingress Gateway
→ Context Builder
→ Request Orchestrator
→ Parallel Detectors
→ Normalized Signals
→ Signal Fusion
→ Policy Runtime
→ Decision Engine
→ Enforcement Point
→ Model Runtime / Tool Runtime / Output Guardrail
→ Final Response
→ Decision Trace + Evidence Store
→ Online Sampling + Offline Replay
→ Evaluation
→ Release Gate
→ Policy / Detector / Model Feedback
```

这个流程在文档中已经清楚表达。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

但我建议画成 **双闭环架构**，否则开发者会误以为 release gate 是在线链路的一部分。

## 建议改为：

```text
Online Runtime Path:
Ingress
  → Context Builder
  → Orchestrator
  → Detectors
  → Signal Normalizer
  → Fusion
  → Policy Runtime
  → Decision Engine
  → Enforcement
  → Minimal Trace Commit
  → Response

Async Evidence Path:
Full Trace Builder
  → Evidence Store
  → Metrics
  → Sampling

Offline Control Path:
Trace Dataset
  → Replay
  → Evaluation
  → Release Gate
  → Policy/Detector/Runtime Promotion or Rollback
```

这样一线团队能明确：

* 哪些模块在同步请求路径；
* 哪些模块可以异步；
* 哪些模块属于离线评估；
* 哪些模块参与发布门禁；
* 哪些失败影响用户请求；
* 哪些失败只影响 gate。

***

# 6. 建议重新定义 MVP：从“架构完整”改为“闭环可跑”

我建议将文档中的 P0/P1/P2/P3 保留，但 P0 改成下面这样。

## P0：Runtime Decision Closed Loop

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

### P0 不做

```text
- tool approval workflow full implementation
- RAG chunk removal full implementation
- multi-region policy isolation
- tenant admin dashboard
- advanced fusion ML model
- human review queue
- auto rollback
```

### P0 必须做

```text
- schema validation
- detector plugin interface
- three detectors
- normalized signal
- fusion v0
- policy runtime static snapshot
- decision contract
- input/output enforcement
- synchronous minimal trace
- replay CLI
- evaluation card v0
```

### P0 Exit Criteria

```text
1. 100% decision has trace_id.
2. 100% non-allow decision has reason_code.
3. Policy change does not require app code change.
4. Detector cannot directly block.
5. Replay can reproduce previous decisions with same versions.
6. Monitor mode and active mode both work.
7. PII redaction produces structured output.
8. Context missing does not silently allow.
9. Policy snapshot unavailable does not silently allow.
10. Benchmark report generated for each detector.
```

***

# 7. 文档中建议直接修改的具体表述

下面是可以直接替换进文档的“更硬”的工程化表述。

## 7.1 替换 “Detector 工程要求”

原文已经要求 detector stateless、版本化、可回放、超时可控、失败可见、不私自拦截、可评估。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

建议改成：

```text
Detector MUST NOT return final action.

Detector output MUST be either:
1. RawDetectorSignal
2. DetectorFailureSignal

DetectorFailureSignal MUST include:
- detector_id
- detector_version
- failure_type
- timeout_ms if applicable
- retryable
- partial_result_available
- recommended_mitigation

Any detector result failing schema validation MUST be converted into:
risk_family = SYSTEM_FAILURE
risk_type = INVALID_DETECTOR_OUTPUT
```

***

## 7.2 替换 “Trace async write 非阻塞”

建议改成：

```text
Trace writing is split into two phases:

1. Minimal Trace Commit:
   Synchronous and mandatory before returning decision.
   Contains trace_id, request_id, context_hash, policy_snapshot_id,
   decision_id, action, reason_codes, timestamp.

2. Full Trace/Evidence Append:
   Asynchronous and retryable.
   Contains detector details, redacted samples, evidence objects,
   latency breakdown, debug metadata.

High-risk decisions MUST NOT be returned if Minimal Trace Commit fails.
```

***

## 7.3 替换 “Policy Runtime 必须支持能力”

原文列出 validate、lint、dry-run、snapshot、rollback、diff、canary、explain、replay、multi-region。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)

建议补充：

```text
Policy Runtime v0 MUST implement:
- schema validate
- lint
- immutable snapshot
- rule matching
- stage-action validation
- reason_code enforcement
- region mandatory rule protection
- dry-run over trace dataset

Policy Runtime v0 MAY defer:
- full canary orchestration
- UI management
- tenant self-service authoring
```

***

# 8. 最终建议：把这份设计拆成 6 个工程附件

为了让[\[4\]Cloud Native Enterprise AI Security Control Plane.md](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md?EntityRepresentationId=fbd323bd-d4dd-4f80-a1b9-ed42db5590ec) 真正进入实施，我建议你不要继续只扩写主文档，而是拆出 6 个工程附件：

1. **Contract Spec**
   
   * Context Schema
   * Normalized Signal Schema
   * Decision Contract
   * Trace/Evidence Schema

2. **Policy DSL Spec**
   
   * grammar
   * operators
   * examples
   * lint rules
   * conflict resolution

3. **Runtime Semantics Spec**
   
   * stage enum
   * action state machine
   * fail-safe matrix
   * detector failure semantics
   * trace commit semantics

4. **API Spec**
   
   * Decision API
   * Tool Pre-Execution API
   * Policy Validate API
   * Policy Dry-run API
   * Trace Ingest API

5. **Evaluation & Release Gate Spec**
   
   * evaluation card
   * replay report
   * required slices
   * release gate blocking rules
   * rollback protocol

6. **Implementation Backlog & Test Plan**
   
   * P0/P1/P2 tasks
   * owner
   * acceptance criteria
   * unit/integration/replay tests
   * SRE runbook

这 6 个附件会把当前“架构设计”转成“开发可实现、测试可验证、SRE 可运行、合规可审计”的工程规格。

***

# 9. 一句话结论

[\[4\]Cloud Native Enterprise AI Security Control Plane.md](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md?EntityRepresentationId=fbd323bd-d4dd-4f80-a1b9-ed42db5590ec) 的架构方向是正确的：它已经具备企业级 AI 安全控制平面的核心骨架，而不是普通 guardrail/filter；但下一步必须从“完整设计书”收敛为“强 contract + 强 runtime semantics + 强验收标准”的工程包。最优先修改项是：统一 stage/action/schema，补 trace synchronous minimal commit，正式化 Policy DSL，明确 context authority，标准化 detector failure，细化 RAG/tool contract，并把 P0 缩成可跑通的 vertical slice。 [\[lenovo-my....epoint.com\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/%5B4%5DCloud%20Native%20Enterprise%20AI%20Security%20Control%20Plane.md)
