package service

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func judgeSignal(stage model.Stage, sev model.Severity) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6", SignalID: "j1", TraceID: "trace-j", Stage: stage,
		SignalType: "judge_prompt_injection", RiskFamily: model.RiskSEC, Severity: sev, Confidence: 0.9,
		Source: model.SignalSource{SourceID: "det-judge", SourceType: model.SourceJudge, SourceVersion: "1"},
	}
}

func newJudgeService() (*Service, *MemRegistry) {
	svc, reg := newTestService()
	reg.Register(DetectorEntry{SourceID: "det-judge", Versions: map[string]bool{"1": true}})
	return svc, reg
}

// §6.1/§6.2: sync path does not block on a pending judge; the decision is
// provisional and a later judge augmentation supersedes it with a revision.
func TestJudge_ProvisionalThenRevised(t *testing.T) {
	svc, _ := newJudgeService()
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-j", TraceID: "trace-j", RequestID: "req-j", Stage: model.StageRetrieval}
	ctx.Application.Environment = model.EnvProd

	// No judge signal yet -> provisional audit_only fallback (no policy match).
	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd, Options: Options{PendingJudge: true}})
	if err != nil {
		t.Fatal(err)
	}
	orig := resp.Decision
	if orig.Decision.Stability != decision.StabilityProvisional {
		t.Fatalf("pending judge must yield provisional decision, got %q", orig.Decision.Stability)
	}
	if orig.Decision.DecisionRevision != 0 {
		t.Fatalf("original revision must be 0, got %d", orig.Decision.DecisionRevision)
	}

	// Async judge arrives with a high-severity signal -> retrieval control fires.
	revised, changed, err := svc.AugmentJudge("trace-j", model.StageRetrieval, []model.Signal{judgeSignal(model.StageRetrieval, model.SeverityHigh)})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatalf("high-severity judge must tighten the action")
	}
	if revised.Decision.Action != model.ActionRestrictScope {
		t.Fatalf("revised action want restrict_scope, got %s", revised.Decision.Action)
	}
	if revised.Decision.Stability != decision.StabilityFinal {
		t.Fatalf("revised decision must be final, got %q", revised.Decision.Stability)
	}
	if revised.Decision.DecisionRevision != 1 {
		t.Fatalf("revised revision must be 1, got %d", revised.Decision.DecisionRevision)
	}
	if revised.Decision.SupersedesID != orig.DecisionID {
		t.Fatalf("revised must supersede the original decision id")
	}

	// Enforcement must act on the latest non-superseded decision (§6.2).
	latest, ok := svc.LatestDecision("trace-j", model.StageRetrieval)
	if !ok || latest.DecisionID != revised.DecisionID {
		t.Fatalf("latest decision must be the revised one")
	}
	if res := enforceOne(t, latest); res.Status == "failed" {
		t.Fatalf("revised decision must be enforceable, got %s", res.ErrorMessage)
	}
}

// A judge signal already present within budget yields a final (not provisional)
// decision even when PendingJudge is set.
func TestJudge_PresentSignalIsFinal(t *testing.T) {
	svc, _ := newJudgeService()
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-j2", TraceID: "trace-j2", RequestID: "req-j2", Stage: model.StageRetrieval}
	ctx.Application.Environment = model.EnvProd
	sig := judgeSignal(model.StageRetrieval, model.SeverityHigh)
	sig.TraceID = "trace-j2"

	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd, Signals: []model.Signal{sig}, Options: Options{PendingJudge: true}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision.Decision.Stability != decision.StabilityFinal {
		t.Fatalf("present judge signal must yield final decision, got %q", resp.Decision.Decision.Stability)
	}
}

func TestJudge_AugmentWithoutPriorDecisionErrors(t *testing.T) {
	svc, _ := newJudgeService()
	if _, _, err := svc.AugmentJudge("nope", model.StageOutput, []model.Signal{judgeSignal(model.StageOutput, model.SeverityHigh)}); err == nil {
		t.Fatalf("augmenting an unknown decision must error")
	}
}
