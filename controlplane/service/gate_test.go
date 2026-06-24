package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/gate"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
)

func clone(b policy.Bundle) policy.Bundle {
	ps := make([]policy.Policy, len(b.Policies))
	copy(ps, b.Policies)
	return policy.Bundle{Version: b.Version, Policies: ps}
}

func idxOf(b policy.Bundle, id string) int {
	for i, p := range b.Policies {
		if p.PolicyID == id {
			return i
		}
	}
	return -1
}

// populate one golden output decision so the runtime has a regression snapshot.
func seedOutputDecision(t *testing.T, svc *Service) {
	t.Helper()
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-g1", TraceID: "trace-g1", RequestID: "req-g1", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd,
		Signals: []model.Signal{det("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision.Decision.Action != model.ActionRedact {
		t.Fatalf("seed expected redact, got %s", resp.Decision.Decision.Action)
	}
}

// seed benign output decisions unaffected by the disclosure policy so the
// regression corpus has contained (not total) behavior drift.
func seedBenignDecisions(t *testing.T, svc *Service, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := "benign-" + string(rune('a'+i))
		ctx := model.Context{SchemaVersion: "1.6", ContextID: id, TraceID: id, RequestID: id, Stage: model.StageOutput}
		ctx.Application.Environment = model.EnvProd
		if _, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd}); err != nil {
			t.Fatal(err)
		}
	}
}

// DoD: a policy update can be blocked by a failed gate.
func TestReleaseGate_BlocksBreakingPolicyUpdate(t *testing.T) {
	svc, _ := newTestService()
	seedOutputDecision(t, svc)
	seedBenignDecisions(t, svc, 3)

	cand := clone(policy.DefaultBundle())
	cand.Version = "candidate-broken"
	i := idxOf(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Decision.Action = model.ActionAllow // remove the redact control

	rec := svc.EvaluateReleaseGate(ReleaseGateRequest{
		GateID:                       "privacy_output_control_release_gate_v1",
		Target:                       gate.Target{TargetType: "policy_update", TargetID: "enterprise_external_disclosure_policy", FromVersion: "1.0.0", ToVersion: "2.0.0"},
		CandidateBundle:              cand,
		Artifacts:                    gate.ArtifactRefs{PolicyDiffReportRef: "diff-ref", OfflineEvalReportRef: "eval-ref"},
		ObservedEvidenceCompleteness: 0.99,
		ObservedP95LatencyMs:         120,
	})

	if rec.Decision != gate.DecisionBlock {
		t.Fatalf("breaking policy update must be blocked, got %s (metrics=%+v)", rec.Decision, rec.Metrics)
	}
	if rec.PolicyDiffRisk != "critical" {
		t.Fatalf("weakening a control must be critical diff risk, got %s", rec.PolicyDiffRisk)
	}
	if rec.Artifacts.PolicyDiffReportRef != "diff-ref" {
		t.Fatalf("gate must bind artifacts")
	}
}

// An identical candidate (no behavioral change) passes the gate.
func TestReleaseGate_IdenticalCandidatePasses(t *testing.T) {
	svc, _ := newTestService()
	seedOutputDecision(t, svc)

	rec := svc.EvaluateReleaseGate(ReleaseGateRequest{
		GateID:                       "noop_gate",
		Target:                       gate.Target{TargetType: "policy_update"},
		CandidateBundle:              clone(policy.DefaultBundle()),
		ObservedEvidenceCompleteness: 0.99,
		ObservedP95LatencyMs:         100,
	})
	if rec.Decision != gate.DecisionPass {
		t.Fatalf("identical candidate must pass, got %s (risk=%s metrics=%+v)", rec.Decision, rec.PolicyDiffRisk, rec.Metrics)
	}
	if rec.Metrics.ReplayConsistency != 1.0 {
		t.Fatalf("identical candidate must have replay consistency 1.0, got %.3f", rec.Metrics.ReplayConsistency)
	}
}
