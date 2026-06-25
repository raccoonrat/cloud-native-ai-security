package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

// P2-J: an idempotent replay must report the ORIGINAL evidence commit status,
// not a hardcoded "committed". With no evidence required and no commit forced,
// the status stays "pending" across the replay.
func TestP2_IdempotentReplayReportsRealStatus(t *testing.T) {
	svc, _ := newTestService()
	// Output stage, benign (no policy match, low risk) -> audit_only, no evidence
	// required and RequireEvidenceCommit not set -> pending.
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-j", TraceID: "trace-j", RequestID: "req-j", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd

	r1, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r1.EvidenceCommitStatus != "pending" {
		t.Fatalf("first call without required/forced commit must be pending, got %q", r1.EvidenceCommitStatus)
	}
	r2, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.IdempotentReplay {
		t.Fatalf("second identical call must be an idempotent replay")
	}
	if r2.EvidenceCommitStatus != "pending" {
		t.Fatalf("idempotent replay must echo the original status (pending), got %q", r2.EvidenceCommitStatus)
	}
}

// P2-N: an approved tool that DRIFTS (schema changed in the registry) must be
// re-confirmed even without a prior approval and regardless of data sensitivity.
func TestP2_DriftedToolRequiresConfirmation(t *testing.T) {
	svc, toolReg := toolService(t)
	// Registry now reflects a new schema (the tool drifted since review).
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s2", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
	})
	ac := sendEmailAction()
	ac.SchemaHash = "sha256:s2" // action presents the new (drifted) schema, NO approval id

	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-d", "drifted"), ToolAction: &ac, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action != model.ActionRequireConfirmation {
		t.Fatalf("a drifted tool must require confirmation, got %s", r.Decision.Decision.Action)
	}
}

// P2-N (shadow): the drift control applies in shadow too, where the fail-closed
// default would otherwise only audit.
func TestP2_DriftedToolConfirmsInShadow(t *testing.T) {
	svc, toolReg := toolService(t)
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s2", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
	})
	ac := sendEmailAction()
	ac.SchemaHash = "sha256:s2"
	ctx := toolCtx("req-ds", "drift-shadow")
	ctx.Application.Environment = model.EnvShadow

	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: ctx, ToolAction: &ac, Mode: model.EnvShadow})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action != model.ActionRequireConfirmation {
		t.Fatalf("drifted tool must require confirmation even in shadow, got %s", r.Decision.Decision.Action)
	}
}
