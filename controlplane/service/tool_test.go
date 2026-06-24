package service

import (
	"testing"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

func toolService(t *testing.T) (*Service, *tool.MemRegistry) {
	t.Helper()
	svc, _, toolReg := NewDefault([]byte("test-key"))
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", ToolVersion: "1.2.0",
		SchemaHash: "sha256:s1", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
	})
	return svc, toolReg
}

func toolCtx(req, traceSuffix string) model.Context {
	c := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-" + traceSuffix, TraceID: "trace-" + traceSuffix,
		RequestID: req, Stage: model.StageToolPreExecution,
	}
	c.Application.Environment = model.EnvProd
	c.Data.Sensitivity = "confidential"
	return c
}

func sendEmailAction() tool.ActionContext {
	return tool.ActionContext{
		ToolActionID: "ta-1", ToolID: "send_email", ServerID: "srv", ToolVersion: "1.2.0",
		SchemaHash: "sha256:s1", ManifestHash: "sha256:m1", PermissionClass: model.PermExternalSend,
		Operation: "send", ParametersHash: "sha256:p1", TargetResourceID: "rcpt-1",
		DestinationBoundary: model.BoundaryExternal, DataSensitivity: "confidential",
	}
}

// DoD: tool call blocked until confirmation; full confirm->allow lifecycle.
func TestTool_ConfirmationLifecycle(t *testing.T) {
	svc, _ := toolService(t)
	ac := sendEmailAction()

	// 1) First call: no approval -> require_confirmation, tool NOT executed.
	r1, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-1", "1"), ToolAction: &ac, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Decision.Decision.Action != model.ActionRequireConfirmation {
		t.Fatalf("want require_confirmation, got %s", r1.Decision.Decision.Action)
	}
	if !r1.Decision.ApprovalBinding.Required || r1.Decision.ApprovalBinding.BindingHash == "" {
		t.Fatalf("require_confirmation must carry a binding hash: %+v", r1.Decision.ApprovalBinding)
	}
	if res := enforceOne(t, r1.Decision); res.Status != "skipped" {
		t.Fatalf("tool must not execute before confirmation, got %s", res.Status)
	}

	// 2) Human approves the concrete action.
	b, err := svc.ApproveToolAction(ac, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 3) Agent replays with approval_id -> allow.
	ac2 := ac
	ac2.ApprovalID = b.ApprovalID
	r2, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-2", "1"), ToolAction: &ac2, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Decision.Decision.Action != model.ActionAllow {
		t.Fatalf("valid approval must allow, got %s (reason %s)", r2.Decision.Decision.Action, r2.Decision.Decision.ReasonCode)
	}
}

// DoD: schema drift invalidates a prior approval (back to require_confirmation).
func TestTool_SchemaDriftInvalidatesApproval(t *testing.T) {
	svc, toolReg := toolService(t)
	ac := sendEmailAction()
	b, _ := svc.ApproveToolAction(ac, "alice", time.Hour)

	// The tool's schema changes (registry updated) AND the action presents the new hash.
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s2", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
	})
	drifted := ac
	drifted.SchemaHash = "sha256:s2"
	drifted.ApprovalID = b.ApprovalID

	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-1", "drift"), ToolAction: &drifted, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action != model.ActionRequireConfirmation {
		t.Fatalf("schema drift must re-require confirmation, got %s", r.Decision.Decision.Action)
	}
	assertFlag(t, r.Decision.FusedRiskSummary.Flags, model.FlagApprovalInvalidated)
}

// DoD: revoked tool always denies.
func TestTool_RevokedDenies(t *testing.T) {
	svc, toolReg := toolService(t)
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s1", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustRevoked,
	})
	ac := sendEmailAction()
	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-1", "rev"), ToolAction: &ac, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action != model.ActionDeny {
		t.Fatalf("revoked tool must deny, got %s", r.Decision.Decision.Action)
	}
}

// DoD: unknown privileged tool denies; unknown read tool requires review.
func TestTool_UnknownToolDenyOrReview(t *testing.T) {
	svc, _, toolReg := NewDefault([]byte("test-key"))
	_ = toolReg // intentionally empty registry -> unknown tools

	send := sendEmailAction() // external_send (elevated)
	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-1", "unk1"), ToolAction: &send, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action != model.ActionDeny {
		t.Fatalf("unknown elevated tool must deny, got %s", r.Decision.Decision.Action)
	}

	read := sendEmailAction()
	read.PermissionClass = model.PermRead
	read.DataSensitivity = "internal"
	rr, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-2", "unk2"), ToolAction: &read, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if rr.Decision.Decision.Action != model.ActionRequireReview {
		t.Fatalf("unknown read tool must require_review, got %s", rr.Decision.Decision.Action)
	}
}

// Execution-time TOCTOU: an approval bound to one action must not authorize a
// different action presented at execution.
func TestTool_TOCTOURevalidation(t *testing.T) {
	svc, _ := toolService(t)
	ac := sendEmailAction()
	b, _ := svc.ApproveToolAction(ac, "alice", time.Hour)

	// Same approval id, but the recipient (target) changed at execution time.
	tampered := ac
	tampered.TargetResourceID = "rcpt-ATTACKER"
	tampered.ApprovalID = b.ApprovalID
	r, err := svc.EvaluateToolAction(EvaluateRequest{Context: toolCtx("req-1", "toctou"), ToolAction: &tampered, Mode: model.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.Decision.Action == model.ActionAllow {
		t.Fatalf("tampered target must NOT be allowed by the original approval")
	}
}

func assertFlag(t *testing.T, flags []string, want string) {
	t.Helper()
	for _, f := range flags {
		if f == want {
			return
		}
	}
	t.Fatalf("expected flag %q in %v", want, flags)
}
