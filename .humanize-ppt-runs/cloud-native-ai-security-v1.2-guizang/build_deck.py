#!/usr/bin/env python3
"""Inject Chinese guizang slides into template."""
from pathlib import Path

OUT = Path(__file__).parent / "rendered" / "index.html"
TOTAL = 20

def pg(n, left, right=None):
    right = right or f"{n:02d} / {TOTAL}"
    return f'<div class="chrome"><div>{left}</div><div>{right}</div></div>'

def foot(left, right="— · —"):
    return f'<div class="foot"><div>{left}</div><div>{right}</div></div>'

SLIDES = f"""
<!-- S01 Cover -->
<section class="slide hero dark">
{pg(1, "Design Spec · V1.2", "Vol.01")}
  <div class="frame" style="display:grid;gap:4vh;align-content:center;min-height:80vh">
    <div class="kicker" data-anim>Enterprise AI Security</div>
    <h1 class="h-hero" data-anim>云原生企业<br>AI 安全控制平面</h1>
    <h2 class="h-sub" data-anim>MCP / Tool-Calling Runtime Security Hardening</h2>
    <p class="lead" style="max-width:62vw" data-anim>
      为企业 AI 应用、RAG、Agent、Tool Calling 与模型输出提供统一的安全决策、策略执行、证据审计与发布门禁。
    </p>
    <div class="meta-row" data-anim>
      <span>工程 / 平台 / 安全 / SRE</span><span>·</span><span>2026.06</span>
    </div>
  </div>
{foot("一场关于 AI 运行时安全的架构分享", "V1.2")}
</section>

<!-- S02 Hook -->
<section class="slide light">
{pg(2, "The Shift · 范式转移", "02 / {TOTAL}")}
  <div class="frame" style="padding-top:6vh">
    <div class="kicker" data-anim>从文本生成到工具执行</div>
    <h2 class="h-xl" data-anim>Enterprise AI 进入了<br>运维控制面</h2>
    <p class="lead" style="margin-top:4vh;max-width:58vw" data-anim>
      MCP 与 tool-calling 暴露的第一批真实安全需求——不是某个产品集成的局部问题，而是平台级能力。
    </p>
    <div class="callout" style="margin-top:6vh" data-anim>
      Northbound API 安全<strong>必要，但不充分</strong>。<br>
      自然语言意图可被错误翻译为带副作用的 API 调用。
      <div class="callout-src">— 核心架构判断</div>
    </div>
  </div>
{foot("Page 02 · 范式转移")}
</section>

<!-- S03 Risks -->
<section class="slide dark">
{pg(3, "Risk · 风险全景", "03 / {TOTAL}")}
  <div class="frame" style="padding-top:5vh">
    <div class="kicker" data-anim>Problem Space</div>
    <h2 class="h-xl" data-anim>十大风险 · 一个控制平面</h2>
    <div class="grid-3" style="margin-top:5vh">
      <div class="stat-card" data-anim><div class="stat-label">Injection</div><div class="stat-nb">Prompt<span class="stat-unit"> + </span>RAG</div><div class="stat-note">注入与检索污染</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Leakage</div><div class="stat-nb">PII<span class="stat-unit"> / </span>机密</div><div class="stat-note">输入输出泄密</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Tool</div><div class="stat-nb">Abuse</div><div class="stat-note">越权与危险参数</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Agent</div><div class="stat-nb">Auto</div><div class="stat-note">多步自主失控</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Transport</div><div class="stat-nb">Trust</div><div class="stat-note">TLS / 证书 / 确认</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Evidence</div><div class="stat-nb">Gap</div><div class="stat-note">无法证明 allow/block</div></div>
    </div>
  </div>
{foot("Page 03 · 风险全景")}
</section>

<!-- S04 Scope -->
<section class="slide hero light">
{pg(4, "Act I · 定位", "04 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:5vh;align-content:center;min-height:75vh">
    <div class="kicker" data-anim>Scope</div>
    <h1 class="h-hero" style="font-size:7vw" data-anim>控制平面<br>不是点状检测器</h1>
    <p class="lead" style="max-width:55vw" data-anim>
      ✓ 统一 AI 运行时安全 &nbsp;|&nbsp; ✗ 非模型训练平台 &nbsp;|&nbsp; ✗ 非 IAM 替代品 &nbsp;|&nbsp; ✗ 非 LLM Judge 独断系统
    </p>
  </div>
{foot("第一幕 · 系统定位")}
</section>

<!-- S05 V1.2 -->
<section class="slide light">
{pg(5, "V1.2 · MCP 加固", "05 / {TOTAL}")}
  <div class="frame grid-2-7-5" style="padding-top:6vh">
    <div style="display:flex;flex-direction:column;gap:3vh">
      <div>
        <div class="kicker" data-anim>V1.2 Focus</div>
        <h2 class="h-xl" data-anim>八大统一安全原语</h2>
        <p class="lead" style="margin-top:3vh" data-anim>身份链路 · 传输信任 · 工具风险 · 参数安全 · 显式确认 · 风险限流 · 审计证据 · 发布门禁</p>
      </div>
      <div class="callout" data-anim>
        XClarity One 是第一个落地场景；同一套能力可复用于 xCloud、Token Hub、Enterprise Agent、AI Ops。
      </div>
    </div>
    <figure class="frame-img r-16x10" data-anim style="background:linear-gradient(135deg,rgba(10,10,11,.08),rgba(10,10,11,.02));display:flex;align-items:center;justify-content:center;min-height:38vh">
      <svg viewBox="0 0 400 220" width="90%" aria-label="八大原语"><text x="200" y="30" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="currentColor" opacity="0.5">UNIFIED PRIMITIVES</text><circle cx="200" cy="110" r="70" fill="none" stroke="currentColor" stroke-width="1" opacity="0.3"/><text x="200" y="115" text-anchor="middle" font-family="Noto Serif SC" font-size="14" fill="currentColor">Control Plane</text></svg>
    </figure>
  </div>
{foot("Page 05 · V1.2 加固")}
</section>

<!-- S06 Control Plane -->
<section class="slide dark" data-animate="pipeline">
{pg(6, "Principle · 控制平面优先", "06 / {TOTAL}")}
  <div class="frame">
    <div class="kicker">Control Plane First</div>
    <h2 class="h-xl">统一流水线</h2>
    <div class="pipeline-section" style="margin-top:4vh">
      <div class="pipeline">
        <div class="step" data-anim="step"><div class="step-nb">01</div><div class="step-title">Context</div><div class="step-desc">企业上下文构建</div></div>
        <div class="step" data-anim="step"><div class="step-nb">02</div><div class="step-title">Signals</div><div class="step-desc">并行检测器</div></div>
        <div class="step" data-anim="step"><div class="step-nb">03</div><div class="step-title">Fusion</div><div class="step-desc">多信号融合</div></div>
        <div class="step" data-anim="step"><div class="step-nb">04</div><div class="step-title">Policy</div><div class="step-desc">策略运行时</div></div>
        <div class="step" data-anim="step"><div class="step-nb">05</div><div class="step-title">Decision</div><div class="step-desc">决策引擎</div></div>
      </div>
    </div>
    <p class="body-zh" style="margin-top:4vh" data-anim>Enforcement → Trace → Evaluation → Release Gate —— 业务代码里不再散落 if/else。</p>
  </div>
{foot("Page 06 · 控制平面")}
</section>

<!-- S07 Detector -->
<section class="slide hero dark">
{pg(7, "Principle · 检测不决策", "07 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:5vh;align-content:center;min-height:75vh">
    <div class="kicker" data-anim>Detector Does Not Decide</div>
    <h1 class="h-hero" style="font-size:6.5vw;line-height:1.12" data-anim>
      检测器产信号<br>决策引擎做合成
    </h1>
    <p class="lead" style="max-width:52vw" data-anim>PII / 注入 / 机密 / 工具风险 → 规范化 → 融合 → 策略匹配 → allow · block · redact · require_approval</p>
  </div>
{foot("Page 07 · 检测与决策分离")}
</section>

<!-- S08 Architecture -->
<section class="slide light">
{pg(8, "Architecture · 八层架构", "08 / {TOTAL}")}
  <div class="frame" style="padding-top:5vh">
    <div class="kicker" data-anim>High-Level Architecture</div>
    <h2 class="h-xl" data-anim>八个核心层</h2>
    <div class="body-zh" style="margin-top:4vh;line-height:2" data-anim>
      ① Enterprise Request &nbsp; ② Context Builder &nbsp; ③ Detection<br>
      ④ Signal Fusion &nbsp; ⑤ Policy Runtime &nbsp; ⑥ Decision Engine<br>
      ⑦ Enforcement &nbsp; ⑧ Trace / Evidence / Eval / Release Gate
    </div>
  </div>
{foot("Page 08 · 架构")}
</section>

<!-- S09 Act II -->
<section class="slide hero light">
{pg(9, "Act II · MCP 边界", "09 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:6vh;align-content:center;min-height:80vh">
    <div class="kicker" data-anim>Act II</div>
    <h1 class="h-hero" style="font-size:8vw" data-anim>MCP 安全边界</h1>
    <p class="lead" style="max-width:55vw" data-anim>AI 中介执行边界 —— 不是 API 薄封装。</p>
  </div>
{foot("第二幕 · MCP / Tool-Calling")}
</section>

<!-- S10 MCP Quote -->
<section class="slide dark" data-animate="quote">
{pg(10, "MCP · 执行边界", "10 / {TOTAL}")}
  <div class="frame" style="padding-top:8vh;display:grid;gap:6vh;align-content:center;min-height:70vh">
    <div class="kicker" data-anim>The Boundary</div>
    <blockquote class="callout q-big" style="font-size:max(22px,2.4vw);border:none;padding:0" data-anim>
      所有 MCP / tool-mediated 操作在执行前<br>必须经过控制平面 —— 尤其在 <code>tool_pre_execution</code> 阶段。
    </blockquote>
    <p class="lead" data-anim>通用 API wrapper 工具默认 block，除非 policy 显式批准。</p>
  </div>
{foot("Page 10 · MCP 边界")}
</section>

<!-- S11 Trust Chain -->
<section class="slide light" data-animate="pipeline">
{pg(11, "Trust Chain · 身份链路", "11 / {TOTAL}")}
  <div class="frame">
    <div class="kicker">Tool-to-API Trust Chain</div>
    <h2 class="h-xl">每一跳绑定身份</h2>
    <div class="pipeline-section" style="margin-top:3vh">
      <div class="pipeline">
        <div class="step" data-anim="step"><div class="step-nb">U</div><div class="step-title">User</div><div class="step-desc">用户</div></div>
        <div class="step" data-anim="step"><div class="step-nb">C</div><div class="step-title">Client</div><div class="step-desc">MCP Client</div></div>
        <div class="step" data-anim="step"><div class="step-nb">S</div><div class="step-title">Server</div><div class="step-desc">MCP Server</div></div>
        <div class="step" data-anim="step"><div class="step-nb">T</div><div class="step-title">Tool</div><div class="step-desc">工具</div></div>
        <div class="step" data-anim="step"><div class="step-nb">A</div><div class="step-title">API</div><div class="step-desc">Northbound</div></div>
      </div>
    </div>
    <p class="body-zh" style="margin-top:3vh" data-anim>参数必须通过 schema + resource-scope 校验；disruptive 操作需 explicit_user_confirmation。</p>
  </div>
{foot("Page 11 · 信任链")}
</section>

<!-- S12 Instruction/Data -->
<section class="slide dark">
{pg(12, "Separation · 指令数据分离", "12 / {TOTAL}")}
  <div class="frame grid-2-6-6" style="padding-top:6vh">
    <div>
      <div class="kicker" data-anim>Untrusted Data</div>
      <h2 class="h-xl" data-anim>不可信数据</h2>
      <p class="body-zh" style="margin-top:3vh" data-anim>用户 prompt · RAG chunk · 外部网页 · 第三方 tool output</p>
    </div>
    <div>
      <div class="kicker" data-anim>Trusted Instructions</div>
      <h2 class="h-xl" data-anim>可信指令</h2>
      <p class="body-zh" style="margin-top:3vh" data-anim>系统 prompt · policy snapshot · 批准的工具 schema · 用户显式确认</p>
    </div>
  </div>
{foot("Page 12 · 指令/数据分离")}
</section>

<!-- S13 Act III -->
<section class="slide hero light">
{pg(13, "Act III · 运行时契约", "13 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:6vh;align-content:center;min-height:80vh">
    <div class="kicker" data-anim>Act III</div>
    <h1 class="h-hero" style="font-size:8vw" data-anim>Canonical Contract</h1>
    <p class="lead" style="max-width:55vw" data-anim>硬约束源：stage · action · risk · determinism</p>
  </div>
{foot("第三幕 · 运行时语义")}
</section>

<!-- S14 Stage -->
<section class="slide light">
{pg(14, "Contract · Stage", "14 / {TOTAL}")}
  <div class="frame" style="padding-top:5vh">
    <div class="kicker" data-anim>0.1 Stage Enum</div>
    <h2 class="h-xl" data-anim>全系统只用 <code>stage</code> 一个字段</h2>
    <p class="lead" style="margin-bottom:4vh" data-anim><code>request_type</code> 已废弃 —— 禁止用于策略 / trace / eval 匹配。</p>
    <div class="body-zh" data-anim>
      input_precheck · rag_* · tool_pre/post_execution · agent_* · model_output_check · batch_eval
    </div>
  </div>
{foot("Page 14 · Stage 枚举")}
</section>

<!-- S15 Action -->
<section class="slide dark">
{pg(15, "Contract · Action", "15 / {TOTAL}")}
  <div class="frame" style="padding-top:5vh">
    <div class="kicker" data-anim>0.2 Action State Machine</div>
    <h2 class="h-xl" data-anim>动作是状态机，不是优先级列表</h2>
    <div class="grid-4" style="margin-top:4vh">
      <div class="stat-card" data-anim><div class="stat-label">Terminal</div><div class="stat-nb" style="font-size:4vw">allow block safe_complete</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Transform</div><div class="stat-nb" style="font-size:3.2vw">redact rewrite remove_chunk</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Human</div><div class="stat-nb" style="font-size:3.5vw">require_approval escalate</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Observe</div><div class="stat-nb" style="font-size:4vw">log_only warn</div></div>
    </div>
  </div>
{foot("Page 15 · Action 枚举")}
</section>

<!-- S16 Enforcement -->
<section class="slide light">
{pg(16, "Enforcement · 四类 enforcement", "16 / {TOTAL}")}
  <div class="frame" style="padding-top:5vh">
    <div class="kicker" data-anim>Enforcement Points</div>
    <h2 class="h-xl" data-anim>四个运行时控制面</h2>
    <div class="grid-4" style="margin-top:4vh">
      <div class="stat-card" data-anim><div class="stat-label">Input</div><div class="stat-nb" style="font-size:4.5vw">注入·PII</div><div class="stat-note">input_precheck</div></div>
      <div class="stat-card" data-anim><div class="stat-label">RAG</div><div class="stat-nb" style="font-size:4.5vw">Chunk</div><div class="stat-note">检索上下文检查</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Tool</div><div class="stat-nb" style="font-size:4.5vw">Pre-Exec</div><div class="stat-note">V1.2 重点</div></div>
      <div class="stat-card" data-anim><div class="stat-label">Output</div><div class="stat-nb" style="font-size:4.5vw">Leak</div><div class="stat-note">model_output_check</div></div>
    </div>
  </div>
{foot("Page 16 · Enforcement")}
</section>

<!-- S17 Policy Trace -->
<section class="slide dark">
{pg(17, "Governance · 策略与证据", "17 / {TOTAL}")}
  <div class="frame grid-2-7-5" style="padding-top:6vh">
    <div>
      <div class="kicker" data-anim>Policy + Trace</div>
      <h2 class="h-xl" data-anim>Policy DSL v0.1<br>+ 两阶段 Trace</h2>
      <p class="lead" style="margin-top:3vh" data-anim>同步最小提交保证 trace_id；异步补充完整 evidence。Release Gate 阻断指标回归发布。</p>
    </div>
    <div class="callout" data-anim>
      Replay Key = content hash + context hash + detector versions + policy snapshot + engine versions
    </div>
  </div>
{foot("Page 17 · 策略与证据")}
</section>

<!-- S18 Roadmap -->
<section class="slide hero dark">
{pg(18, "Roadmap · 实施路线", "18 / {TOTAL}")}
  <div class="frame" style="padding-top:4vh">
    <div class="kicker" data-anim>Implementation Plan</div>
    <h2 class="h-xl" data-anim>分阶段交付</h2>
    <div class="grid-3" style="margin-top:4vh">
      <div class="stat-card" data-anim><div class="stat-label">P0</div><div class="stat-nb">Slice</div><div class="stat-note">input + output 闭环</div></div>
      <div class="stat-card" data-anim><div class="stat-label">P1</div><div class="stat-nb">Policy</div><div class="stat-note">DSL + Evidence</div></div>
      <div class="stat-card" data-anim><div class="stat-label">P1.5</div><div class="stat-nb" style="color:var(--paper)">MCP</div><div class="stat-note">tool_pre_execution</div></div>
    </div>
    <p class="lead" style="margin-top:4vh" data-anim>P2 RAG/Agent · P3 生产级持续控制 —— 先跑通 P0，再 ship P1.5 给 MCP 集成。</p>
  </div>
{foot("Page 18 · 路线图")}
</section>

<!-- S19 Closing question -->
<section class="slide hero light">
{pg(19, "Question · 留给团队", "19 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:8vh;align-content:center;min-height:80vh">
    <div class="kicker" data-anim>The Question</div>
    <h1 class="h-hero" style="font-size:6.5vw;line-height:1.15" data-anim>
      <span data-anim style="display:block">你的 Enterprise AI 链路里，</span>
      <span data-anim style="display:block">哪一步还没有</span>
      <span data-anim style="display:block">可审计的决策 trace？</span>
    </h1>
  </div>
{foot("Page 19 · 收束问题")}
</section>

<!-- S20 Takeaway -->
<section class="slide hero dark">
{pg(20, "Takeaway · 核心判断", "20 / {TOTAL}")}
  <div class="frame" style="display:grid;gap:5vh;align-content:center;min-height:80vh">
    <div class="kicker" data-anim>Core Thesis</div>
    <h1 class="h-hero" style="font-size:5.8vw;line-height:1.15" data-anim>
      PPT 不是信息容器<br>是观众状态改变器
    </h1>
    <p class="lead" style="max-width:58vw" data-anim>
      控制平面负责「能决策、能审计、能回放、能门禁」—— 模板库负责「渲染得好看」，Humanize 负责「能讲、有人盯、能上台」。
    </p>
    <div class="meta-row" data-anim><span>Cloud Native Enterprise AI Security Control Plane v1.2</span></div>
  </div>
{foot("谢谢 · Thank You", "END")}
</section>
"""

def main():
    html = OUT.read_text(encoding="utf-8")
    html = html.replace("[必填] 替换为 PPT 标题 · Deck Title", "云原生企业 AI 安全控制平面 v1.2 · Ink Classic")
    if ".slide.hero.light,.slide.hero.dark{background:transparent}" not in html:
        html = html.replace(
            ".slide.dark{color:var(--paper);background:var(--ink)}",
            ".slide.dark{color:var(--paper);background:var(--ink)}\n  .slide.hero.light,.slide.hero.dark{background:transparent}",
        )
    html = html.replace("<!-- SLIDES_HERE -->", SLIDES.strip())
    OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT} ({TOTAL} slides)")

if __name__ == "__main__":
    main()
