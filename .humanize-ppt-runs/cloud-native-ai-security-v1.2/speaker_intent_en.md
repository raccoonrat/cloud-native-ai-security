## S01 Cloud Native Enterprise AI Security Control Plane

- Intent: Hook the audience — frame the stakes before diving into architecture.
- Say: "Enterprise AI is no longer just generating text. Agents call tools, MCP servers hit Northbound APIs, and every call can have side effects. This deck defines the control plane that makes that safe at scale."
- Cue: Pause after title. Let the subtitle land.

## S02 The Shift

- Intent: Create tension — the old mental model (prompt filter) is insufficient.
- Say: "When AI moves from chat to tool execution, Northbound API security alone is not enough. Prompt injection can change which tool runs and with what arguments."
- Avoid: Don't list all ten risks yet — save for slide 3.

## S03 Problem Space

- Intent: Establish shared vocabulary for runtime vs operational gaps.
- Say: "We unify ten risk categories under one control plane — injection, leakage, tool abuse, transport trust, and the compliance evidence gap."
- Cue: Point to left panel (runtime) vs right panel (operational).

## S04 Scope

- Intent: Set boundaries — what this system is and is not.
- Say: "This is a runtime control plane, not a model training platform, not IAM replacement, not LLM-judge-only guardrail."
- Avoid: Don't apologize for scope limits — state them confidently.

## S05 V1.2 Focus

- Intent: Highlight what's new in this revision.
- Say: "V1.2 hardens MCP and tool-calling: trust chain, argument contracts, explicit confirmation for disruptive ops, and transport trust policy banning self-signed certs in production."

## S06 Eight Primitives

- Intent: Show this is platform-wide, not product-local.
- Say: "XClarity One is the first landing scenario. The same eight primitives — trust chain, transport trust, tool risk, argument security, confirmation, throttling, evidence, release gate — reuse everywhere."

## S07 Control Plane First

- Intent: Teach the core pipeline mental model.
- Say: "Every security judgment flows through one pipeline: context, signals, policy, decision, enforcement, trace, evaluation, release gate. No scattered if/else in app code."

## S08 Detector Does Not Decide

- Intent: Clarify separation of concerns.
- Say: "Detectors emit signals. Only the decision engine — after fusion and policy matching — chooses allow, block, redact, or require_approval."

## S09 Architecture

- Intent: Orient the audience to the eight layers.
- Say: "Request layer at top, detection and fusion in the middle, decision and enforcement as the spine, trace and release gate at the bottom feeding continuous improvement."

## S10 Runtime Flow

- Intent: Make the abstract pipeline concrete.
- Say: "Same path for every request — prompt, RAG query, tool pre-exec, model output. Context-aware: identical text, different decision based on tenant, role, data classification."

## S11 Canonical Stage Enum

- Intent: Emphasize contract discipline.
- Say: "One field: stage. request_type is deprecated. CI fails on any non-enum value. This is the hard constraint source for policy, trace, and eval."

## S12 Action State Machine

- Intent: Actions are semantics, not priority ordering.
- Say: "Terminal, transform, human-async, observability — each class behaves differently. require_approval is pending, not terminal. Disruptive ops need explicit_user_confirmation."

## S13 Risk Families

- Intent: Introduce the taxonomy including V1.2 addition.
- Say: "Sixteen risk families. V1.2 adds TRANSPORT_TRUST_RISK as the only new top-level enum — certificate and MCP risks extend at risk_type layer to avoid enum explosion."

## S14 MCP Boundary

- Intent: Reframe MCP as execution boundary.
- Say: "MCP is not a thin API wrapper. It's an AI-mediated execution boundary. Generic API wrapper tools default block unless policy explicitly allows."

## S15 Trust Chain

- Intent: Walk through identity binding.
- Say: "User to client to MCP server to tool to Northbound API to resource to action — bind identity at every hop. Validate arguments against schema and resource scope."

## S16 Instruction / Data Separation

- Intent: Prevent injection via content channels.
- Say: "User prompts, RAG chunks, tool output — untrusted data. System prompts, policy snapshots, approved schemas, user confirmations — trusted instructions. Never let data become instructions."

## S17 Enforcement Points

- Intent: Map controls to runtime surfaces.
- Say: "Four surfaces: input, RAG, tool pre-execution — highlighted because V1.2 — and output. Each has specific actions and contracts."

## S18 Policy & Release Gate

- Intent: Connect governance to deployment safety.
- Say: "Policy DSL v0.1 with CI lint and diff. Immutable snapshots on every decision. Release gate blocks deploys on metric regression. Dry-run against historical traces before go-live."

## S19 Trace & Evidence

- Intent: Audit-grade accountability.
- Say: "Two-phase trace: sync minimal commit guarantees trace_id on every decision; async enrichment for full replay and compliance. Replay key includes all version hashes."

## S20 Implementation Roadmap

- Intent: Close with actionable phasing.
- Say: "P0: vertical slice with input and output checks. P1: policy hardening. P1.5 — highlighted — MCP tool slice before full agent security. P2 RAG and agent. P3 production loop."
- Cue: End with "Start P0, ship P1.5 for MCP integrations, then expand."
