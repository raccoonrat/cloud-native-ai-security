package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/enforcement"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

func newTestService() (*Service, *MemRegistry) {
	svc, reg, _ := NewDefault([]byte("test-key"))
	reg.Register(DetectorEntry{SourceID: "det-enterprise-data-leakage", Versions: map[string]bool{"1": true}})
	reg.Register(DetectorEntry{SourceID: "det-prompt-injection", Versions: map[string]bool{"1": true}})
	reg.Register(DetectorEntry{SourceID: "det-source-trust", Versions: map[string]bool{"1": true}})
	return svc, reg
}

func det(id, sourceID, typ string, fam model.RiskFamily, sev model.Severity, conf float64, stage model.Stage) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6", SignalID: id, TraceID: "trace-x", Stage: stage, SignalType: typ,
		RiskFamily: fam, Severity: sev, Confidence: conf,
		Source: model.SignalSource{SourceID: sourceID, SourceType: model.SourceModel, SourceVersion: "1"},
	}
}

// Golden Scenario 1: Enterprise Data Leakage Output Control -> redact.
func TestGolden1_OutputRedact(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-1", TraceID: "trace-1", RequestID: "req-1", Stage: model.StageOutput,
	}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Data.DataAssetType = "customer_contract"
	ctx.Destination.Boundary = model.BoundaryExternal

	resp, err := svc.Evaluate(EvaluateRequest{
		Context: ctx,
		Signals: []model.Signal{det("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)},
		Mode:    model.EnvProd,
		Options: Options{RequireEvidenceCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Decision
	if d.Decision.Action != model.ActionRedact {
		t.Fatalf("want redact, got %s", d.Decision.Action)
	}
	if d.Decision.ReasonCode != "confidential_enterprise_data_external_boundary" {
		t.Fatalf("unexpected reason_code %q", d.Decision.ReasonCode)
	}
	assertReplayBindingComplete(t, d)
	if resp.EvidenceCommitStatus != "committed" || !d.Evidence.MinimalEvidenceCommitted {
		t.Fatalf("evidence not committed: %s", resp.EvidenceCommitStatus)
	}
	if d.FusedRiskSummary.HighestSeverity != model.SeverityCritical {
		t.Fatalf("want fused critical (FR-002), got %s", d.FusedRiskSummary.HighestSeverity)
	}
	assertEnforceable(t, d)
}

// Golden Scenario 2: Prompt Injection Retrieval Control -> restrict_scope.
func TestGolden2_RetrievalRestrictScope(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-2", TraceID: "trace-2", RequestID: "req-2", Stage: model.StageRetrieval,
	}
	ctx.Application.Environment = model.EnvProd

	resp, err := svc.Evaluate(EvaluateRequest{
		Context: ctx,
		Signals: []model.Signal{
			det("s1", "det-prompt-injection", "prompt_injection", model.RiskSEC, model.SeverityHigh, 0.88, model.StageRetrieval),
			det("s2", "det-source-trust", "source_untrusted", model.RiskSEC, model.SeverityMedium, 0.80, model.StageRetrieval),
		},
		Mode: model.EnvProd,
	})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Decision
	if d.Decision.Action != model.ActionRestrictScope && d.Decision.Action != model.ActionRequireReview {
		t.Fatalf("want restrict_scope or require_review, got %s", d.Decision.Action)
	}
	assertReplayBindingComplete(t, d)
	assertEnforceable(t, d)
}

// Golden Scenario 3: Tool Pre-Execution Confirmation -> require_confirmation.
func TestGolden3_ToolRequireConfirmation(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-3", TraceID: "trace-3", RequestID: "req-3", Stage: model.StageToolPreExecution,
	}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Tool.ToolID = "send_email"
	ctx.Tool.ServerID = "mcp-email-server-prod"
	ctx.Tool.PermissionClass = model.PermExternalSend
	ctx.Tool.TrustState = model.TrustApproved

	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Decision
	if d.Decision.Action != model.ActionRequireConfirmation {
		t.Fatalf("want require_confirmation, got %s", d.Decision.Action)
	}
	if !d.ApprovalBinding.Required {
		t.Fatalf("require_confirmation must require approval binding")
	}
	assertReplayBindingComplete(t, d)

	// Enforcement must NOT execute the tool; it skips pending confirmation.
	res := enforceOne(t, d)
	if res.Status != "skipped" {
		t.Fatalf("tool must not execute before confirmation, got status %s", res.Status)
	}
}

// Revoked tool always denies (FR-008 -> tool_revocation_policy).
func TestGolden3b_RevokedToolDenies(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-4", TraceID: "trace-4", RequestID: "req-4", Stage: model.StageToolPreExecution,
	}
	ctx.Application.Environment = model.EnvProd
	ctx.Tool.PermissionClass = model.PermExternalSend
	ctx.Tool.TrustState = model.TrustRevoked

	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision.Decision.Action != model.ActionDeny {
		t.Fatalf("revoked tool must deny, got %s", resp.Decision.Decision.Action)
	}
}

// Idempotency: same (trace, request, stage) returns the same decision (first-write-wins).
func TestIdempotencyFirstWriteWins(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-5", TraceID: "trace-5", RequestID: "req-5", Stage: model.StageOutput,
	}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	req := EvaluateRequest{
		Context: ctx, Mode: model.EnvProd,
		Signals: []model.Signal{det("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)},
	}

	r1, _ := svc.Evaluate(req)
	if r1.IdempotentReplay {
		t.Fatalf("first call must not be a replay")
	}
	// Second call with DIFFERENT signals but same key -> original wins.
	req.Signals = nil
	r2, _ := svc.Evaluate(req)
	if !r2.IdempotentReplay {
		t.Fatalf("second call must be an idempotent replay")
	}
	if r1.Decision.DecisionID != r2.Decision.DecisionID {
		t.Fatalf("idempotent replay must return the same decision_id")
	}
}

// INV-7: an unregistered signal source is dropped and recorded.
func TestProvenanceDropsUnregisteredSource(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-6", TraceID: "trace-6", RequestID: "req-6", Stage: model.StageOutput,
	}
	ctx.Application.Environment = model.EnvProd
	resp, err := svc.Evaluate(EvaluateRequest{
		Context: ctx, Mode: model.EnvProd,
		Signals: []model.Signal{det("s1", "det-UNKNOWN", "enterprise_data_leakage", model.RiskPRIV, model.SeverityCritical, 0.99, model.StageOutput)},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Decision
	found := false
	for _, ds := range d.ReplayBinding.DroppedSignals {
		if ds.Reason == "registry_miss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unregistered source must be recorded as registry_miss, got %+v", d.ReplayBinding.DroppedSignals)
	}
	// The forged critical signal must NOT have driven the decision.
	if d.FusedRiskSummary.HighestSeverity == model.SeverityCritical {
		t.Fatalf("forged unregistered signal must not reach fusion")
	}
}

func assertReplayBindingComplete(t *testing.T, d decision.Contract) {
	t.Helper()
	rb := d.ReplayBinding
	if rb.ContextSnapshotRef == "" || rb.PolicyBundleVersion == "" || rb.FusionConfigVersion == "" || rb.MatrixVersion == "" {
		t.Fatalf("incomplete replay_binding: %+v", rb)
	}
	if d.Decision.ReasonCode == "" {
		t.Fatalf("decision must carry a reason_code")
	}
	if d.Integrity.Signature == "" || d.Integrity.DecisionHash == "" {
		t.Fatalf("decision must be signed")
	}
}

func enforceOne(t *testing.T, d decision.Contract) enforcement.Result {
	t.Helper()
	m := matrix.MustLoad()
	v := sign.NewHMAC([]byte("test-key"), "control-plane-runtime")
	adapter := enforcement.NewMockAdapter(m, v, true)
	res, _ := adapter.Execute(d)
	return res
}

func assertEnforceable(t *testing.T, d decision.Contract) {
	t.Helper()
	res := enforceOne(t, d)
	if res.Status == "failed" {
		t.Fatalf("enforcement failed for action %s: %s", d.Decision.Action, res.ErrorMessage)
	}
}
