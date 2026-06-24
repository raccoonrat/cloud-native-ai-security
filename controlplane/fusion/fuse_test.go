package fusion

import (
	"reflect"
	"testing"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func sig(id string, fam model.RiskFamily, sev model.Severity, conf float64, stage model.Stage) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6",
		SignalID:      id,
		TraceID:       "trace-1",
		Stage:         stage,
		RiskFamily:    fam,
		Severity:      sev,
		Confidence:    conf,
		Source:        model.SignalSource{SourceID: "det-" + id, SourceType: model.SourceModel, SourceVersion: "1"},
	}
}

func withType(s model.Signal, t string) model.Signal { s.SignalType = t; return s }

// TV-1: high PRIV signal crossing external boundary -> critical (FR-002).
func TestTV1_FR002CriticalOnExternal(t *testing.T) {
	ctx := model.Context{Stage: model.StageOutput}
	ctx.Destination.Boundary = model.BoundaryExternal
	fr := Fuse([]model.Signal{sig("a", model.RiskPRIV, model.SeverityHigh, 0.91, model.StageOutput)}, ctx, DefaultConfig())

	if fr.HighestSeverity != model.SeverityCritical {
		t.Fatalf("want critical, got %s", fr.HighestSeverity)
	}
	if fr.Uncertainty != model.UncertaintyLow {
		t.Fatalf("want uncertainty low, got %s", fr.Uncertainty)
	}
	if len(fr.SortedFlags()) != 0 {
		t.Fatalf("want no flags, got %v", fr.SortedFlags())
	}
	if fr.ConfidenceSummary.Representative != 0.91 {
		t.Fatalf("want representative 0.91, got %v", fr.ConfidenceSummary.Representative)
	}
}

// TV-2: critical signal dominates; representative is the critical signal's conf.
func TestTV2_FR001CriticalDominates(t *testing.T) {
	ctx := model.Context{Stage: model.StageOutput}
	fr := Fuse([]model.Signal{
		sig("a", model.RiskSEC, model.SeverityCritical, 0.80, model.StageOutput),
		sig("b", model.RiskPRIV, model.SeverityLow, 0.95, model.StageOutput),
	}, ctx, DefaultConfig())

	if fr.HighestSeverity != model.SeverityCritical {
		t.Fatalf("want critical, got %s", fr.HighestSeverity)
	}
	if fr.ConfidenceSummary.Representative != 0.80 {
		t.Fatalf("want representative 0.80, got %v", fr.ConfidenceSummary.Representative)
	}
	if fr.ConfidenceSummary.Min != 0.80 || fr.ConfidenceSummary.Max != 0.95 {
		t.Fatalf("want min .80/max .95, got %v/%v", fr.ConfidenceSummary.Min, fr.ConfidenceSummary.Max)
	}
}

// TV-3: high severity below low-confidence threshold -> needs_review + high uncertainty (FR-005).
func TestTV3_FR005LowConfidenceHighSeverity(t *testing.T) {
	ctx := model.Context{Stage: model.StageInput}
	fr := Fuse([]model.Signal{sig("a", model.RiskSEC, model.SeverityHigh, 0.55, model.StageInput)}, ctx, DefaultConfig())

	if fr.HighestSeverity != model.SeverityHigh {
		t.Fatalf("want high, got %s", fr.HighestSeverity)
	}
	if !fr.HasFlag(model.FlagNeedsReview) {
		t.Fatalf("want needs_review flag")
	}
	if fr.Uncertainty != model.UncertaintyHigh {
		t.Fatalf("want uncertainty high, got %s", fr.Uncertainty)
	}
}

// TV-4: revoked tool -> critical (FR-008).
func TestTV4_FR008RevokedTool(t *testing.T) {
	ctx := model.Context{Stage: model.StageToolPreExecution}
	ctx.Tool.TrustState = model.TrustRevoked
	fr := Fuse([]model.Signal{sig("a", model.RiskSEC, model.SeverityMedium, 0.7, model.StageToolPreExecution)}, ctx, DefaultConfig())

	if fr.HighestSeverity != model.SeverityCritical {
		t.Fatalf("want critical, got %s", fr.HighestSeverity)
	}
	if !fr.HasFlag(model.FlagToolRevoked) {
		t.Fatalf("want tool_revoked flag")
	}
}

// TV-5: two medium signals -> high (FR-006).
func TestTV5_FR006MediumCluster(t *testing.T) {
	ctx := model.Context{Stage: model.StageInput}
	fr := Fuse([]model.Signal{
		sig("a", model.RiskSEC, model.SeverityMedium, 0.7, model.StageInput),
		sig("b", model.RiskPRIV, model.SeverityMedium, 0.7, model.StageInput),
	}, ctx, DefaultConfig())

	if fr.HighestSeverity != model.SeverityHigh {
		t.Fatalf("want high, got %s", fr.HighestSeverity)
	}
}

// TV-6: fusion is order-independent (the core determinism guarantee).
func TestTV6_OrderIndependence(t *testing.T) {
	ctx := model.Context{Stage: model.StageToolPreExecution}
	ctx.Destination.Boundary = model.BoundaryExternal
	ctx.Tool.PermissionClass = model.PermExternalSend
	ctx.Tool.HasPriorApproval = true

	base := []model.Signal{
		sig("a", model.RiskSEC, model.SeverityHigh, 0.92, model.StageToolPreExecution),
		withType(sig("b", model.RiskPRIV, model.SeverityLow, 0.88, model.StageToolPreExecution), "registry_miss"),
		withType(sig("c", model.RiskCOMP, model.SeverityMedium, 0.50, model.StageToolPreExecution), "tool_schema_drift"),
	}
	reversed := []model.Signal{base[2], base[1], base[0]}
	shuffled := []model.Signal{base[1], base[0], base[2]}

	cfg := DefaultConfig()
	a := Fuse(base, ctx, cfg)
	b := Fuse(reversed, ctx, cfg)
	c := Fuse(shuffled, ctx, cfg)

	if !reflect.DeepEqual(a, b) {
		t.Fatalf("fusion not order-independent (base vs reversed):\n%+v\n%+v", a, b)
	}
	if !reflect.DeepEqual(a, c) {
		t.Fatalf("fusion not order-independent (base vs shuffled):\n%+v\n%+v", a, c)
	}
}

// Expired signals are dropped and recorded, never fused.
func TestExpiredSignalDropped(t *testing.T) {
	ctx := model.Context{Stage: model.StageInput}
	cfg := DefaultConfig()
	cfg.Now = mustTime("2026-06-24T16:00:00Z")
	s := sig("a", model.RiskSEC, model.SeverityCritical, 0.9, model.StageInput)
	s.CreatedAt = mustTime("2026-06-24T15:00:00Z")
	s.TTLMs = 1000 // expired an hour ago

	fr := Fuse([]model.Signal{s}, ctx, cfg)
	if fr.HighestSeverity != model.SeverityNone {
		t.Fatalf("expired signal must not fuse, got %s", fr.HighestSeverity)
	}
	if len(fr.DroppedSignals) != 1 || fr.DroppedSignals[0].Reason != "expired" {
		t.Fatalf("want one expired dropped signal, got %+v", fr.DroppedSignals)
	}
}
