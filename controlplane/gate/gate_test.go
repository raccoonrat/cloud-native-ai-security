package gate

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/replay"
)

func outputLeakSample(expected model.Action, intervene bool) Sample {
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-g", TraceID: "trace-g", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	sig := model.Signal{
		SchemaVersion: "1.6", SignalID: "s1", TraceID: "trace-g", Stage: model.StageOutput,
		SignalType: "enterprise_data_leakage", RiskFamily: model.RiskPRIV, Severity: model.SeverityHigh, Confidence: 0.91,
		Source: model.SignalSource{SourceID: "det-x", SourceType: model.SourceModel, SourceVersion: "1"},
	}
	return Sample{
		Inputs:               replay.Inputs{Context: ctx, Signals: []model.Signal{sig}, Mode: model.EnvProd},
		ExpectedAction:       expected,
		ShouldIntervene:      intervene,
		RiskFamily:           model.RiskPRIV,
		EvidenceCompleteness: 1.0,
	}
}

// benignOutputSample is unaffected by the enterprise disclosure policy (no
// confidential data / external boundary) so it stays audit_only on both bundles.
func benignOutputSample(id string) Sample {
	ctx := model.Context{SchemaVersion: "1.6", ContextID: id, TraceID: id, Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	return Sample{
		Inputs:               replay.Inputs{Context: ctx, Mode: model.EnvProd},
		ExpectedAction:       model.ActionAuditOnly,
		ShouldIntervene:      false,
		EvidenceCompleteness: 1.0,
	}
}

func cloneBundle(b policy.Bundle) policy.Bundle {
	ps := make([]policy.Policy, len(b.Policies))
	copy(ps, b.Policies)
	return policy.Bundle{Version: b.Version, Policies: ps}
}

func findIdx(b policy.Bundle, id string) int {
	for i, p := range b.Policies {
		if p.PolicyID == id {
			return i
		}
	}
	return -1
}

// DoD: a policy update that weakens a control is blocked / not shippable.
func TestGate_BlockOnRegression(t *testing.T) {
	cur := policy.DefaultBundle()
	cand := cloneBundle(cur)
	cand.Version = "cand-1"
	i := findIdx(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Decision.Action = model.ActionAllow // breaks the golden control

	rec := Evaluate(Request{
		GateID:          "privacy_output_control_release_gate_v1",
		Target:          Target{TargetType: "policy_update", TargetID: "enterprise_external_disclosure_policy", FromVersion: "1.0.0", ToVersion: "1.1.0"},
		CurrentBundle:   cur,
		CandidateBundle: cand,
		// One regressed sample (redact->allow) among unaffected benign traffic:
		// correctness fails but the drift stays contained -> block (not rollback).
		Corpus: []Sample{
			outputLeakSample(model.ActionRedact, true),
			benignOutputSample("b1"), benignOutputSample("b2"), benignOutputSample("b3"),
		},
		FusionConfig: fusion.DefaultConfig(),
		Artifacts:    ArtifactRefs{OfflineEvalReportRef: "eval-1", PolicyDiffReportRef: "diff-1"},
	})

	if rec.Decision != DecisionBlock {
		t.Fatalf("regressing the golden control must block, got %s (metrics=%+v)", rec.Decision, rec.Metrics)
	}
	if rec.Metrics.ActionCorrectness >= DefaultThresholds().MinActionCorrectness {
		t.Fatalf("candidate must fail action correctness floor, got %.2f", rec.Metrics.ActionCorrectness)
	}
	if rec.Metrics.FalseNegativeRate == 0 {
		t.Fatalf("dropping an intervention must raise false negative rate")
	}
	// Gate output binds to artifacts (DoD).
	if rec.Artifacts.OfflineEvalReportRef == "" || rec.Artifacts.PolicyDiffReportRef == "" {
		t.Fatalf("gate record must bind evaluation/diff artifacts")
	}
	if rec.GateEvaluationID == "" {
		t.Fatalf("gate record must have an id (INV-6)")
	}
}

// DoD: canary-only decision is supported (clean metrics, elevated behavior drift).
func TestGate_CanaryOnlyOnDrift(t *testing.T) {
	cur := policy.DefaultBundle()
	cand := cloneBundle(cur)
	cand.Version = "cand-2"
	// Strengthen the retrieval control: restrict_scope -> require_review (action
	// change but NOT a weakening -> high diff risk; corpus shows behavior drift).
	i := findIdx(cand, "untrusted_retrieval_policy")
	cand.Policies[i].Decision.Action = model.ActionRequireReview

	// Retrieval sample whose current action is restrict_scope; candidate changes it.
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-r", TraceID: "trace-r", Stage: model.StageRetrieval}
	ctx.Application.Environment = model.EnvProd
	sig := model.Signal{
		SchemaVersion: "1.6", SignalID: "s1", TraceID: "trace-r", Stage: model.StageRetrieval,
		SignalType: "prompt_injection", RiskFamily: model.RiskSEC, Severity: model.SeverityHigh, Confidence: 0.9,
		Source: model.SignalSource{SourceID: "det-x", SourceType: model.SourceModel, SourceVersion: "1"},
	}
	sample := Sample{
		Inputs:               replay.Inputs{Context: ctx, Signals: []model.Signal{sig}, Mode: model.EnvProd},
		ExpectedAction:       model.ActionRequireReview, // we WANT the new behavior -> action correct
		ShouldIntervene:      true,
		EvidenceCompleteness: 1.0,
	}

	rec := Evaluate(Request{
		GateID: "retrieval_release_gate_v1", Target: Target{TargetType: "policy_update"},
		CurrentBundle: cur, CandidateBundle: cand, Corpus: []Sample{sample},
		FusionConfig: fusion.DefaultConfig(),
	})
	if rec.Decision != DecisionCanaryOnly {
		t.Fatalf("high diff risk with passing metrics must be canary_only, got %s (risk=%s metrics=%+v)", rec.Decision, rec.PolicyDiffRisk, rec.Metrics)
	}
}

// DoD: rollback-required decision is supported (failing metrics AND severe drift).
func TestGate_RollbackRequiredOnSevereRegression(t *testing.T) {
	// Every sample expected redact but the candidate weakens the control to allow:
	// correctness fails (floor) AND behavior drift is total -> rollback_required.
	mk := func(id string) Sample {
		s := outputLeakSample(model.ActionRedact, true)
		s.Inputs.Context.ContextID = id
		s.Inputs.Context.TraceID = id
		return s
	}
	cur := policy.DefaultBundle()
	cand := cloneBundle(cur)
	cand.Version = "cand-3"
	i := findIdx(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Decision.Action = model.ActionAllow // redact -> allow (weaken)

	rec := Evaluate(Request{
		GateID: "g", Target: Target{TargetType: "policy_update"},
		CurrentBundle: cur, CandidateBundle: cand,
		Corpus:       []Sample{mk("a"), mk("b"), mk("c")},
		FusionConfig: fusion.DefaultConfig(),
	})
	if rec.Metrics.BehaviorDrift < 0.5 {
		t.Fatalf("expected severe drift, got %.2f", rec.Metrics.BehaviorDrift)
	}
	if rec.Decision != DecisionRollbackRequired {
		t.Fatalf("failing metrics with severe drift must be rollback_required, got %s (metrics=%+v)", rec.Decision, rec.Metrics)
	}
}

// A behavior-preserving constraint bump passes with a warning (medium risk).
func TestGate_PassWithWarningOnConstraintBump(t *testing.T) {
	cur := policy.DefaultBundle()
	cand := cloneBundle(cur)
	cand.Version = "cand-4"
	i := findIdx(cand, "enterprise_external_disclosure_policy")
	c := cand.Policies[i].Decision.Constraints
	c.RedactionProfile = "enterprise_confidential_v2"
	cand.Policies[i].Decision.Constraints = c

	rec := Evaluate(Request{
		GateID: "g", Target: Target{TargetType: "policy_update"},
		CurrentBundle: cur, CandidateBundle: cand,
		Corpus:       []Sample{outputLeakSample(model.ActionRedact, true)},
		FusionConfig: fusion.DefaultConfig(),
	})
	if rec.Decision != DecisionPassWithWarning {
		t.Fatalf("medium-risk constraint bump must pass_with_warning, got %s (risk=%s)", rec.Decision, rec.PolicyDiffRisk)
	}
	if rec.Metrics.ActionCorrectness != 1.0 {
		t.Fatalf("behavior-preserving change must keep action correctness 1.0, got %.2f", rec.Metrics.ActionCorrectness)
	}
}

func TestGate_EmptyCorpusPassesLowRisk(t *testing.T) {
	cur := policy.DefaultBundle()
	rec := Evaluate(Request{
		GateID: "g", Target: Target{TargetType: "threshold_update"},
		CurrentBundle: cur, CandidateBundle: cloneBundle(cur),
		FusionConfig: fusion.DefaultConfig(),
	})
	if rec.Decision != DecisionPass {
		t.Fatalf("identical bundles, empty corpus must pass, got %s", rec.Decision)
	}
}
