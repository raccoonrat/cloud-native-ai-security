package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/gate"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

func hasDropped(d decision.Contract, reason string) bool {
	for _, ds := range d.ReplayBinding.DroppedSignals {
		if ds.Reason == reason {
			return true
		}
	}
	return false
}

// P1-1: in MODE-B the signature must bind the signal payload. A validly-signed
// but mismatched payload hash is rejected; a correctly-bound signal is kept.
func TestP1_ModeBSignatureBindsPayload(t *testing.T) {
	m := matrix.MustLoad()
	reg := NewMemRegistry()
	detSigner := sign.NewHMAC([]byte("det-key"), "det-x")
	reg.Register(DetectorEntry{SourceID: "det-x", Versions: map[string]bool{"1": true}, Verifier: detSigner})
	svc := New(m, policy.DefaultBundle(), reg, evidence.NewMemStore(), sign.NewHMAC([]byte("cp"), "cp"),
		Config{ProvenanceMode: model.ModeB})

	mkCtx := func(id string) model.Context {
		c := model.Context{SchemaVersion: "1.6", ContextID: id, TraceID: id, RequestID: id, Stage: model.StageOutput}
		c.Application.Environment = model.EnvProd
		c.Data.Sensitivity = "confidential"
		c.Destination.Boundary = model.BoundaryExternal
		return c
	}
	mkSig := func(ctx model.Context) model.Signal {
		return model.Signal{
			SchemaVersion: "1.6", SignalID: "s1", TraceID: ctx.TraceID, ContextID: ctx.ContextID, Stage: model.StageOutput,
			SignalType: "enterprise_data_leakage", RiskFamily: model.RiskPRIV, Severity: model.SeverityHigh, Confidence: 0.91,
			Source: model.SignalSource{SourceID: "det-x", SourceType: model.SourceModel, SourceVersion: "1"},
		}
	}

	// (A) tampered: a validly-signed but mismatched payload hash is rejected.
	ctxA := mkCtx("a")
	tampered := mkSig(ctxA)
	wrong := "sha256:deadbeef"
	sigv, by := detSigner.Sign(wrong)
	tampered.Integrity = model.SignalIntegrity{SignedPayloadHash: wrong, Signature: sigv, KeyID: by}
	respA, err := svc.Evaluate(EvaluateRequest{Context: ctxA, Mode: model.EnvProd, Signals: []model.Signal{tampered}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDropped(respA.Decision, "signature_invalid") {
		t.Fatalf("MODE-B must drop a signal whose signed hash != content hash, dropped=%+v", respA.Decision.ReplayBinding.DroppedSignals)
	}

	// (B) correctly bound: signed hash == canonical content hash -> kept and drives the decision.
	ctxB := mkCtx("b")
	good := mkSig(ctxB)
	h := model.CanonicalSignalHash(good)
	sigv2, by2 := detSigner.Sign(h)
	good.Integrity = model.SignalIntegrity{SignedPayloadHash: h, Signature: sigv2, KeyID: by2}
	respB, err := svc.Evaluate(EvaluateRequest{Context: ctxB, Mode: model.EnvProd, Signals: []model.Signal{good}})
	if err != nil {
		t.Fatal(err)
	}
	if hasDropped(respB.Decision, "signature_invalid") {
		t.Fatalf("a correctly-bound MODE-B signal must NOT be dropped")
	}
	if respB.Decision.Decision.Action != model.ActionRedact {
		t.Fatalf("the bound signal must drive the decision (redact), got %s", respB.Decision.Decision.Action)
	}
}

// P1-2: replaying a decision uses the bundle version it was made under, not the
// currently active bundle. After a blue/green activation that would change the
// outcome, the old decision still replays against its pinned (immutable) bundle.
func TestP1_ReplayUsesPinnedBundleVersion(t *testing.T) {
	svc, _ := newTestService()

	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-p2", TraceID: "trace-p2", RequestID: "req-p2", Stage: model.StageOutput}
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

	// Activate a candidate that would turn the SAME input into allow.
	cand := clone(policy.DefaultBundle())
	cand.Version = "cand-allow"
	i := idxOf(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Decision.Action = model.ActionAllow
	if err := svc.ActivateBundle(cand, gate.GateEvaluationRecord{Decision: gate.DecisionPass}, model.EnvProd); err != nil {
		t.Fatal(err)
	}

	// The old decision must replay against the pinned (default) bundle -> match.
	rr, err := svc.ReplayDecision(resp.Decision.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Consistency != "match" {
		t.Fatalf("replay must use the pinned bundle version (match), got %s diff=%v", rr.Consistency, rr.Diff)
	}
	if rr.ReplayedAction != model.ActionRedact {
		t.Fatalf("replay must reproduce the original action (redact), got %s", rr.ReplayedAction)
	}
}

// P1-3: identical logical inputs (incl. a control-synthesized registry_miss
// signal) must yield an identical Decision Contract hash, i.e. the hash is a
// pure function of the inputs and not perturbed by random synthetic signal ids.
func TestP1_DeterministicDecisionHash(t *testing.T) {
	mk := func() decision.Contract {
		svc, _ := newTestService()
		ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-h", TraceID: "trace-h", RequestID: "req-h", Stage: model.StageOutput}
		ctx.Application.Environment = model.EnvProd
		resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd,
			Signals: []model.Signal{det("s1", "det-UNREG", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.9, model.StageOutput)}})
		if err != nil {
			t.Fatal(err)
		}
		return resp.Decision
	}
	d1, d2 := mk(), mk()
	if d1.Integrity.DecisionHash != d2.Integrity.DecisionHash {
		t.Fatalf("identical inputs must yield identical decision hash:\n%s\n%s", d1.Integrity.DecisionHash, d2.Integrity.DecisionHash)
	}
	// The synthetic registry_miss must carry a deterministic id (no random hex).
	if len(d1.Signals) == 0 || d1.Signals[0].SignalID != d2.Signals[0].SignalID {
		t.Fatalf("synthetic signal id must be deterministic, got %+v vs %+v", d1.Signals, d2.Signals)
	}
}

// P1-4: the release gate must not penalize a candidate that STRENGTHENS an
// existing control. Historical snapshots are a regression corpus only (no
// incumbent-as-truth correctness labels), so a redact->block change keeps
// action_correctness at 1.0 and is not blocked (limited to canary by drift).
func TestP1_GateDoesNotPenalizeStrengthening(t *testing.T) {
	svc, _ := newTestService()
	seedOutputDecision(t, svc) // an incumbent redact decision

	cand := clone(policy.DefaultBundle())
	cand.Version = "cand-stronger"
	i := idxOf(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Decision.Action = model.ActionBlock // redact -> block (strengthen)

	rec := svc.EvaluateReleaseGate(ReleaseGateRequest{
		GateID:                       "strengthen_gate",
		Target:                       gate.Target{TargetType: "policy_update"},
		CandidateBundle:              cand,
		ObservedEvidenceCompleteness: 0.99,
		ObservedP95LatencyMs:         100,
	})
	if rec.Metrics.ActionCorrectness != 1.0 {
		t.Fatalf("strengthening must not lower action_correctness (no incumbent label), got %.2f", rec.Metrics.ActionCorrectness)
	}
	if rec.Metrics.FalseNegativeRate != 0 {
		t.Fatalf("strengthening drops no control, false_negative_rate must be 0, got %.2f", rec.Metrics.FalseNegativeRate)
	}
	if rec.Decision == gate.DecisionBlock || rec.Decision == gate.DecisionRollbackRequired {
		t.Fatalf("strengthening a control must not be blocked/rolled back, got %s", rec.Decision)
	}
}
