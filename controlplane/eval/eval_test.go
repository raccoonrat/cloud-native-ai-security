package eval_test

import (
	"strings"
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/eval"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/service"
)

func sig(id, sourceID, typ string, fam model.RiskFamily, sev model.Severity, conf float64, stage model.Stage) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6", SignalID: id, TraceID: "t", Stage: stage, SignalType: typ,
		RiskFamily: fam, Severity: sev, Confidence: conf,
		Source: model.SignalSource{SourceID: sourceID, SourceType: model.SourceModel, SourceVersion: "1"},
	}
}

func newSvc() *service.Service {
	svc, reg, _ := service.NewDefault([]byte("eval-key"))
	reg.Register(service.DetectorEntry{SourceID: "det-enterprise-data-leakage", Versions: map[string]bool{"1": true}})
	reg.Register(service.DetectorEntry{SourceID: "det-prompt-injection", Versions: map[string]bool{"1": true}})
	reg.Register(service.DetectorEntry{SourceID: "det-source-trust", Versions: map[string]bool{"1": true}})
	return svc
}

func outputCtx() model.Context {
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-o", TraceID: "trace-o", RequestID: "req-o", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal
	return ctx
}

func benignInputCtx() model.Context {
	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-b", TraceID: "trace-b", RequestID: "req-b", Stage: model.StageInput}
	ctx.Application.Environment = model.EnvProd
	return ctx
}

func TestHarness_Report(t *testing.T) {
	svc := newSvc()
	cases := []eval.Case{
		{
			Name:           "output_leak_redact",
			Req:            service.EvaluateRequest{Context: outputCtx(), Mode: model.EnvProd, Signals: []model.Signal{sig("s1", "det-enterprise-data-leakage", "enterprise_data_leakage", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)}},
			ExpectedAction: model.ActionRedact,
			ExpectedReason: "confidential_enterprise_data_external_boundary",
			ShouldIntervene: true,
			RiskFamily:     model.RiskPRIV,
			Enrichment:     evidence.Enrichment{ContentSpanCaptured: true, EnforcementResultCommitted: true},
		},
		{
			Name:           "benign_input_allow",
			Req:            service.EvaluateRequest{Context: benignInputCtx(), Mode: model.EnvProd},
			ExpectedAction: model.ActionAuditOnly,
			ShouldIntervene: false,
			RiskFamily:     model.RiskSEC,
			Enrichment:     evidence.Enrichment{ContentSpanCaptured: true},
		},
	}

	rep := eval.Run(svc, cases)

	if rep.Total != 2 {
		t.Fatalf("want 2 cases, got %d", rep.Total)
	}
	if rep.ActionCorrectness() != 1.0 {
		t.Fatalf("want action_correctness 1.0, got %.2f (cards=%+v)", rep.ActionCorrectness(), rep.Cards)
	}
	if rep.ReplayConsistencyRate != 1.0 {
		t.Fatalf("want replay_consistency 1.0, got %.2f", rep.ReplayConsistencyRate)
	}
	if rep.FalsePositiveRate != 0 || rep.FalseNegativeRate != 0 {
		t.Fatalf("want zero fp/fn, got fpr=%.2f fnr=%.2f", rep.FalsePositiveRate, rep.FalseNegativeRate)
	}

	// Per-stage cards present (DoD: per-stage + per-risk-family metrics).
	if _, ok := rep.PerStage[model.StageOutput]; !ok {
		t.Fatalf("missing output stage bucket")
	}
	if _, ok := rep.PerStage[model.StageInput]; !ok {
		t.Fatalf("missing input stage bucket")
	}
	if rep.PerStage[model.StageOutput].ActionCorrectness() != 1.0 {
		t.Fatalf("output stage action_correctness != 1.0")
	}
	if _, ok := rep.PerRiskFamily[model.RiskPRIV]; !ok {
		t.Fatalf("missing PRIV risk family bucket")
	}

	// Enriched output evidence must be fully complete.
	var outCard eval.Card
	for _, c := range rep.Cards {
		if c.Name == "output_leak_redact" {
			outCard = c
		}
	}
	if outCard.EvidenceCompleteness != 1.0 {
		t.Fatalf("enriched output evidence completeness = %.2f want 1.0", outCard.EvidenceCompleteness)
	}
	if outCard.ReplayConsistency != "match" {
		t.Fatalf("output replay consistency = %s want match", outCard.ReplayConsistency)
	}

	if r := rep.Render(); !strings.Contains(r, "Per stage:") || !strings.Contains(r, "Per risk family:") {
		t.Fatalf("render missing breakdown sections:\n%s", r)
	}
}
