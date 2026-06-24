package replay

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
)

func outputLeakInputs() Inputs {
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-r1", TraceID: "trace-r1", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	sig := model.Signal{
		SchemaVersion: "1.6", SignalID: "s1", TraceID: "trace-r1", Stage: model.StageOutput,
		SignalType: "enterprise_data_leakage", RiskFamily: model.RiskPRIV, Severity: model.SeverityHigh, Confidence: 0.91,
		Source: model.SignalSource{SourceID: "det-enterprise-data-leakage", SourceType: model.SourceModel, SourceVersion: "1"},
	}
	return Inputs{Context: ctx, Signals: []model.Signal{sig}, Mode: model.EnvProd}
}

func TestReplay_MatchReproducesAction(t *testing.T) {
	in := outputLeakInputs()
	bundle := policy.DefaultBundle()
	cfg := fusion.DefaultConfig()

	// First evaluate to learn the deterministic outcome, then pin it as original.
	first := Run(in, bundle, cfg)
	in.OriginalAction = first.ReplayedAction
	in.OriginalReason = first.ReplayedReason
	in.OriginalDecisionID = "dec-1"

	got := Run(in, bundle, cfg)
	if got.Consistency != "match" {
		t.Fatalf("same versions must replay match, got %s diff=%v", got.Consistency, got.Diff)
	}
	if got.ReplayedAction != model.ActionRedact {
		t.Fatalf("want redact replay, got %s", got.ReplayedAction)
	}
	if got.OriginalDecisionID != "dec-1" {
		t.Fatalf("replay must echo original decision id")
	}
}

func TestReplay_MismatchOnActionDivergence(t *testing.T) {
	in := outputLeakInputs()
	in.OriginalAction = model.ActionAllow // claim the original allowed
	in.OriginalReason = "whatever"

	got := Run(in, policy.DefaultBundle(), fusion.DefaultConfig())
	if got.Consistency != "mismatch" {
		t.Fatalf("divergent action must be mismatch, got %s", got.Consistency)
	}
	if len(got.Diff) == 0 {
		t.Fatalf("mismatch must report a diff")
	}
}

func TestReplay_PartialOnReasonDivergence(t *testing.T) {
	in := outputLeakInputs()
	base := Run(in, policy.DefaultBundle(), fusion.DefaultConfig())
	in.OriginalAction = base.ReplayedAction
	in.OriginalReason = "different_reason_code"

	got := Run(in, policy.DefaultBundle(), fusion.DefaultConfig())
	if got.Consistency != "partial" {
		t.Fatalf("same action, different reason must be partial, got %s", got.Consistency)
	}
}
