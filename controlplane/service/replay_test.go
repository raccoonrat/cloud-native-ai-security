package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// DoD (Sprint 4): replay reproduces the same decision action for all golden scenarios.
func TestReplay_GoldenScenariosReproduce(t *testing.T) {
	svc, _ := newTestService()

	cases := []struct {
		name string
		req  EvaluateRequest
		want model.Action
	}{
		{
			name: "output_redact",
			req: func() EvaluateRequest {
				ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-1", TraceID: "trace-1", RequestID: "req-1", Stage: model.StageOutput}
				ctx.Application.Environment = model.EnvProd
				ctx.Data.Sensitivity = "confidential"
				ctx.Data.DataAssetType = "customer_contract"
				ctx.Destination.Boundary = model.BoundaryExternal
				return EvaluateRequest{Context: ctx, Mode: model.EnvProd,
					Signals: []model.Signal{det("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)}}
			}(),
			want: model.ActionRedact,
		},
		{
			name: "tool_require_confirmation",
			req: func() EvaluateRequest {
				ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-3", TraceID: "trace-3", RequestID: "req-3", Stage: model.StageToolPreExecution}
				ctx.Application.Environment = model.EnvProd
				ctx.Data.Sensitivity = "confidential"
				ctx.Tool.ToolID = "send_email"
				ctx.Tool.ServerID = "mcp-email-server-prod"
				ctx.Tool.PermissionClass = model.PermExternalSend
				ctx.Tool.TrustState = model.TrustApproved
				return EvaluateRequest{Context: ctx, Mode: model.EnvProd}
			}(),
			want: model.ActionRequireConfirmation,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.Evaluate(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Decision.Decision.Action != tc.want {
				t.Fatalf("setup: want %s, got %s", tc.want, resp.Decision.Decision.Action)
			}
			rr, err := svc.ReplayDecision(resp.Decision.DecisionID)
			if err != nil {
				t.Fatalf("replay failed: %v", err)
			}
			if rr.Consistency != "match" {
				t.Fatalf("replay inconsistent: %s diff=%v", rr.Consistency, rr.Diff)
			}
			if rr.ReplayedAction != tc.want {
				t.Fatalf("replay action %s != original %s", rr.ReplayedAction, tc.want)
			}
		})
	}
}

func TestReplay_UnknownDecisionErrors(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.ReplayDecision("does-not-exist"); err == nil {
		t.Fatalf("expected error for unknown decision id")
	}
}

func TestEvidenceCompletenessPopulated(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-ec", TraceID: "trace-ec", RequestID: "req-ec", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd,
		Signals: []model.Signal{det("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision.Evidence.EvidenceCompleteness <= 0 {
		t.Fatalf("decision must carry a synchronous evidence_completeness score, got %.3f", resp.Decision.Evidence.EvidenceCompleteness)
	}
}
