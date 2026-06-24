// Package fusion implements the deterministic fusion algorithm (Spec v1.6 §3).
//
// Determinism is guaranteed by three properties:
//  1. Input normalization into a total order (canonical sort).
//  2. Monotonic lattice merge (severity/uncertainty only escalate; flags only grow),
//     which makes the result invariant to rule evaluation order.
//  3. A fixed rule precedence, specified for human reproducibility.
//
// Fuse is a pure function: same (signals, context, config) -> identical FusedRisk.
// This is what makes replay_consistency >= 0.99 achievable by construction.
package fusion

import (
	"fmt"
	"sort"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// Config carries the versioned, gate-bound fusion thresholds (Spec v1.6 §3.4/§3.5).
type Config struct {
	Version           string
	LowConfThreshold  float64 // FR-005: severity>=high AND confidence < this -> needs_review
	HighConfThreshold float64 // FR-004: conflicting signals both >= this
	// Now is the reference time for TTL expiry. Zero disables expiry (tests).
	Now time.Time
}

// DefaultConfig returns the v1.6 default thresholds.
func DefaultConfig() Config {
	return Config{
		Version:           "deterministic_v1",
		LowConfThreshold:  0.60,
		HighConfThreshold: 0.70,
	}
}

// Fuse runs the deterministic fusion algorithm.
func Fuse(signals []model.Signal, ctx model.Context, cfg Config) model.FusedRisk {
	if cfg.Version == "" {
		cfg.Version = "deterministic_v1"
	}

	// Step 1: normalize (filter + dedup + canonical sort).
	s, dropped := normalize(signals, ctx, cfg)

	fr := model.FusedRisk{
		SchemaVersion:       "1.6",
		Flags:               map[string]bool{},
		FusionConfigVersion: cfg.Version,
		DroppedSignals:      dropped,
	}

	// Base facts derived directly from signals.
	for _, sig := range s {
		fr.HighestSeverity = fr.HighestSeverity.Join(sig.Severity)
	}
	fr.RiskFamilies = sortedFamilies(s)

	// Step 2: apply rules in fixed precedence with monotonic effects.
	applyRules(&fr, s, ctx, cfg)

	// Step 3: deterministic_v1 confidence aggregation.
	fr.ConfidenceSummary = aggregate(s, fr.HighestSeverity)

	// Output: stable reason ordering (rules append in precedence order already).
	fr.RecommendedPolicyPath = recommendPolicyPath(fr)
	return fr
}

// normalize filters invalid/expired signals (INV-7 + §8.3), dedups by signal_id,
// and sorts into the canonical total order (§3.3).
func normalize(signals []model.Signal, ctx model.Context, cfg Config) ([]model.Signal, []model.DroppedSignal) {
	var kept []model.Signal
	var dropped []model.DroppedSignal
	seen := map[string]bool{}

	for _, sig := range signals {
		// Stage match: a signal must target the context's stage.
		if sig.Stage != "" && ctx.Stage != "" && sig.Stage != ctx.Stage {
			continue
		}
		if sig.IsExpired(cfg.Now) {
			dropped = append(dropped, model.DroppedSignal{
				SourceID: sig.Source.SourceID, SignalID: sig.SignalID, Reason: "expired",
			})
			continue
		}
		if sig.SignalID == "" {
			continue // §8.3: signal_id is mandatory.
		}
		if seen[sig.SignalID] {
			continue // dedup keeping first occurrence.
		}
		seen[sig.SignalID] = true
		kept = append(kept, sig)
	}

	sort.SliceStable(kept, func(i, j int) bool {
		return canonicalLess(kept[i], kept[j])
	})
	return kept, dropped
}

// canonicalLess implements the §3.3 canonical key:
// (severity desc, risk_family order, source_type order, signal_id asc).
func canonicalLess(a, b model.Signal) bool {
	if a.Severity != b.Severity {
		return a.Severity > b.Severity // critical first
	}
	if af, bf := model.RiskFamilyOrder(a.RiskFamily), model.RiskFamilyOrder(b.RiskFamily); af != bf {
		return af < bf
	}
	if as, bs := model.SourceTypeOrder(a.Source.SourceType), model.SourceTypeOrder(b.Source.SourceType); as != bs {
		return as < bs
	}
	return a.SignalID < b.SignalID
}

// applyRules evaluates FR-008..FR-006 in fixed precedence. Effects are monotonic
// (Join on severity/uncertainty, set-insert on flags), so the final result does
// not depend on evaluation order.
func applyRules(fr *model.FusedRisk, s []model.Signal, ctx model.Context, cfg Config) {
	// FR-008 (prec 10): revoked tool -> critical.
	if ctx.Tool.TrustState == model.TrustRevoked {
		fr.HighestSeverity = fr.HighestSeverity.Join(model.SeverityCritical)
		fr.Flags[model.FlagToolRevoked] = true
		addReason(fr, "FR-008: revoked tool trust state")
	}

	// FR-001 (prec 20): any critical signal -> critical.
	for _, sig := range s {
		if sig.Severity >= model.SeverityCritical {
			fr.HighestSeverity = fr.HighestSeverity.Join(model.SeverityCritical)
			addReason(fr, fmt.Sprintf("FR-001: critical signal %s", sig.SignalID))
			break
		}
	}

	// FR-002 (prec 30): high signal + external/cross-tenant destination -> critical.
	if ctx.Destination.Boundary.IsCrossing() {
		for _, sig := range s {
			if sig.Severity >= model.SeverityHigh {
				fr.HighestSeverity = fr.HighestSeverity.Join(model.SeverityCritical)
				addReason(fr, fmt.Sprintf("FR-002: high signal %s crossing boundary %s",
					sig.SignalID, ctx.Destination.Boundary))
				break
			}
		}
	}

	// FR-003 (prec 40): schema drift + prior approval -> approval_invalidated.
	if ctx.Tool.HasPriorApproval {
		for _, sig := range s {
			if sig.SignalType == "tool_schema_drift" {
				fr.Flags[model.FlagApprovalInvalidated] = true
				addReason(fr, "FR-003: schema drift invalidates prior approval")
				break
			}
		}
	}

	// FR-007 (prec 50): registry_miss + elevated permission class -> high + needs_review.
	if ctx.Tool.PermissionClass.IsElevated() {
		for _, sig := range s {
			if sig.SignalType == "registry_miss" {
				fr.HighestSeverity = fr.HighestSeverity.Join(model.SeverityHigh)
				fr.Flags[model.FlagNeedsReview] = true
				addReason(fr, "FR-007: registry miss on elevated tool")
				break
			}
		}
	}

	// FR-004 (prec 60): two high-confidence signals that disagree -> needs_review.
	if a, b, ok := findConflict(s, cfg.HighConfThreshold); ok {
		fr.Flags[model.FlagNeedsReview] = true
		fr.Uncertainty = fr.Uncertainty.Join(model.UncertaintyMedium)
		fr.Conflicts = append(fr.Conflicts, model.Conflict{
			ConflictType: "detector_disagreement",
			SignalIDs:    []string{a, b},
			Resolution:   "escalate_to_review",
		})
		addReason(fr, fmt.Sprintf("FR-004: high-confidence disagreement %s vs %s", a, b))
	}

	// FR-005 (prec 70): high severity but low confidence -> needs_review + high uncertainty.
	for _, sig := range s {
		if sig.Severity >= model.SeverityHigh && sig.Confidence < cfg.LowConfThreshold {
			fr.Flags[model.FlagNeedsReview] = true
			fr.Uncertainty = fr.Uncertainty.Join(model.UncertaintyHigh)
			addReason(fr, fmt.Sprintf("FR-005: low-confidence high-severity signal %s", sig.SignalID))
			break
		}
	}

	// FR-006 (prec 80): >=2 medium signals in the same trace -> high.
	mediums := 0
	for _, sig := range s {
		if sig.Severity == model.SeverityMedium {
			mediums++
		}
	}
	if mediums >= 2 {
		fr.HighestSeverity = fr.HighestSeverity.Join(model.SeverityHigh)
		addReason(fr, fmt.Sprintf("FR-006: %d medium signals cluster", mediums))
	}
}

// findConflict returns the first canonical pair of high-confidence signals where
// one is severe (>=high) and another is benign (<=low). The pair is deterministic
// because s is canonically sorted.
func findConflict(s []model.Signal, highConf float64) (string, string, bool) {
	var severe, benign string
	for _, sig := range s {
		if sig.Confidence < highConf {
			continue
		}
		if sig.Severity >= model.SeverityHigh && severe == "" {
			severe = sig.SignalID
		}
		if sig.Severity <= model.SeverityLow && benign == "" {
			benign = sig.SignalID
		}
	}
	if severe != "" && benign != "" {
		// Stable ordering of the reported pair.
		if severe < benign {
			return severe, benign, true
		}
		return benign, severe, true
	}
	return "", "", false
}

// aggregate computes the deterministic_v1 confidence summary (§3.5).
func aggregate(s []model.Signal, highest model.Severity) model.ConfidenceSummary {
	cs := model.ConfidenceSummary{Aggregation: "deterministic_v1"}
	if len(s) == 0 {
		return cs
	}
	cs.HasValues = true
	cs.Min = s[0].Confidence
	cs.Max = s[0].Confidence
	for _, sig := range s {
		if sig.Confidence < cs.Min {
			cs.Min = sig.Confidence
		}
		if sig.Confidence > cs.Max {
			cs.Max = sig.Confidence
		}
	}
	// Representative: confidence of the FIRST signal (canonical order) whose
	// severity equals the final highest severity. If a rule escalated severity
	// beyond any signal, fall back to the first (highest-severity) signal.
	for _, sig := range s {
		if sig.Severity == highest {
			cs.Representative = sig.Confidence
			return cs
		}
	}
	cs.Representative = s[0].Confidence
	return cs
}

func sortedFamilies(s []model.Signal) []model.RiskFamily {
	set := map[model.RiskFamily]bool{}
	for _, sig := range s {
		if sig.RiskFamily != "" {
			set[sig.RiskFamily] = true
		}
	}
	out := make([]model.RiskFamily, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		return model.RiskFamilyOrder(out[i]) < model.RiskFamilyOrder(out[j])
	})
	return out
}

func addReason(fr *model.FusedRisk, r string) {
	fr.RiskReasons = append(fr.RiskReasons, r)
}

// recommendPolicyPath is a deterministic hint keyed by (severity, flags).
// Real deployments load this from versioned fusion_config; the skeleton uses a
// simple deterministic mapping.
func recommendPolicyPath(fr model.FusedRisk) string {
	switch {
	case fr.HasFlag(model.FlagToolRevoked):
		return "tool_revocation_policy"
	case fr.HasFlag(model.FlagApprovalInvalidated):
		return "tool_approval_invalidation_policy"
	case fr.HighestSeverity >= model.SeverityCritical:
		return "critical_risk_policy"
	case fr.HasFlag(model.FlagNeedsReview):
		return "review_routing_policy"
	default:
		return "default_policy"
	}
}
