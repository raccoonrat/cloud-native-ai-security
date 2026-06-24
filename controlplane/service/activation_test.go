package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/gate"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
)

func bumpedBundle(version string) policy.Bundle {
	b := clone(policy.DefaultBundle())
	b.Version = version
	return b
}

// A real passing gate promotes the candidate; rollback restores the previous.
func TestActivation_PassPromotesAndRollback(t *testing.T) {
	svc, _ := newTestService()
	seedOutputDecision(t, svc)
	original := svc.ActiveBundleVersion()

	cand := bumpedBundle("bundle-v2") // metadata-only change -> low risk -> pass
	rec := svc.EvaluateReleaseGate(ReleaseGateRequest{
		GateID: "g", Target: gate.Target{TargetType: "policy_update"},
		CandidateBundle: cand, ObservedEvidenceCompleteness: 0.99, ObservedP95LatencyMs: 100,
	})
	if rec.Decision != gate.DecisionPass {
		t.Fatalf("metadata-only candidate must pass, got %s", rec.Decision)
	}
	if err := svc.ActivateBundle(cand, rec, model.EnvProd); err != nil {
		t.Fatalf("pass gate must allow activation: %v", err)
	}
	if svc.ActiveBundleVersion() != "bundle-v2" {
		t.Fatalf("active bundle must be the candidate, got %s", svc.ActiveBundleVersion())
	}
	if err := svc.RollbackBundle(); err != nil {
		t.Fatalf("rollback must succeed: %v", err)
	}
	if svc.ActiveBundleVersion() != original {
		t.Fatalf("rollback must restore previous bundle %s, got %s", original, svc.ActiveBundleVersion())
	}
}

// Blocked / rollback_required gate decisions must NOT change the active bundle.
func TestActivation_BlockedGateRejected(t *testing.T) {
	svc, _ := newTestService()
	original := svc.ActiveBundleVersion()
	cand := bumpedBundle("bundle-bad")

	for _, d := range []gate.Decision{gate.DecisionBlock, gate.DecisionRollbackRequired} {
		rec := gate.GateEvaluationRecord{Decision: d}
		if err := svc.ActivateBundle(cand, rec, model.EnvProd); err == nil {
			t.Fatalf("decision %s must deny activation", d)
		}
		if svc.ActiveBundleVersion() != original {
			t.Fatalf("active bundle must be unchanged after denied activation")
		}
	}
}

// canary_only activates in canary/shadow but not prod (§18.2).
func TestActivation_CanaryOnlyEnvScoped(t *testing.T) {
	cand := bumpedBundle("bundle-canary")

	svc1, _ := newTestService()
	rec := gate.GateEvaluationRecord{Decision: gate.DecisionCanaryOnly}
	if err := svc1.ActivateBundle(cand, rec, model.EnvProd); err == nil {
		t.Fatalf("canary_only must not activate in prod")
	}

	svc2, _ := newTestService()
	if err := svc2.ActivateBundle(cand, rec, model.EnvCanary); err != nil {
		t.Fatalf("canary_only must activate in canary: %v", err)
	}
	if svc2.ActiveBundleVersion() != "bundle-canary" {
		t.Fatalf("canary activation must swap the bundle")
	}
}

// shadow_only never promotes the enforcing bundle in prod/canary (§18.2 / decision #8).
func TestActivation_ShadowOnlyNeverEnforces(t *testing.T) {
	svc, _ := newTestService()
	original := svc.ActiveBundleVersion()
	cand := bumpedBundle("bundle-shadow")
	rec := gate.GateEvaluationRecord{Decision: gate.DecisionShadowOnly}

	if err := svc.ActivateBundle(cand, rec, model.EnvProd); err == nil {
		t.Fatalf("shadow_only must not activate in prod")
	}
	if err := svc.ActivateBundle(cand, rec, model.EnvCanary); err == nil {
		t.Fatalf("shadow_only must not activate in canary")
	}
	if svc.ActiveBundleVersion() != original {
		t.Fatalf("active bundle must remain unchanged under shadow_only")
	}
}

func TestActivation_RollbackWithoutPreviousErrors(t *testing.T) {
	svc, _ := newTestService()
	if err := svc.RollbackBundle(); err == nil {
		t.Fatalf("rollback without a previous bundle must error")
	}
}
