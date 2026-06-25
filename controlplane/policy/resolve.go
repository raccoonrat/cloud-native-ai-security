// Package policy implements the deterministic conflict-resolution algorithm
// (Spec v1.6 §4): from N matched policies, select a primary action via the
// action strength total order, then union the compatible constraints.
//
// Resolve is a pure deterministic function and therefore replayable.
package policy

import (
	"sort"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// Constraints is the merged constraint set carried on a decision (Spec v1.5 §11.1).
type Constraints struct {
	AuditRequired        bool
	EvidenceRequired     bool
	ConfirmationRequired bool
	StepUpAuthRequired   bool
	ScopeRestriction     []string // union of restriction tokens (more = narrower)
	RedactionProfile     string
	RedactionRank        int
	ReviewQueue          string
	ReviewQueueSeverity  model.Severity
	UserMessageTemplate  string
}

// MatchedPolicy is a policy that matched the context conditions.
type MatchedPolicy struct {
	PolicyID       string
	Priority       int
	Action         model.Action
	ReasonCode     string
	Constraints    Constraints
	MatchedRuleIDs []string
}

// Resolution is the deterministic output of Resolve.
type Resolution struct {
	Action         model.Action
	Constraints    Constraints
	ReasonCodes    []string
	MatchedRuleIDs []string
	Confidence     float64
	// EscalatedReason explains a forced escalation (e.g., redaction-profile tie).
	EscalatedReason string
}

// Resolve selects the primary action and merges constraints (Spec v1.6 §4.2).
// stage is required so the no-match fail-closed default can pick a terminal
// action that is valid for the stage per the Stage x Action Matrix (§2).
func Resolve(matched []MatchedPolicy, env model.Environment, fr model.FusedRisk, stage model.Stage) Resolution {
	if len(matched) == 0 {
		return defaultDecision(env, fr, stage)
	}

	// Sort by (priority desc, policy_id asc) for a deterministic order.
	P := make([]MatchedPolicy, len(matched))
	copy(P, matched)
	sort.SliceStable(P, func(i, j int) bool {
		if P[i].Priority != P[j].Priority {
			return P[i].Priority > P[j].Priority
		}
		return P[i].PolicyID < P[j].PolicyID
	})

	// Primary = strongest action across all matched policies (§4.1).
	primary := P[0].Action
	for _, p := range P {
		if model.ActionStrength(p.Action) > model.ActionStrength(primary) {
			primary = p.Action
		}
	}

	res := Resolution{
		Action:     primary,
		Confidence: fr.ConfidenceSummary.Representative,
	}

	// §4.2.2: union constraints from policies whose action is compatible with primary.
	var redactionTie bool
	for _, p := range P {
		if !compatible(p.Action, primary) {
			continue
		}
		res.ReasonCodes = append(res.ReasonCodes, p.ReasonCode)
		res.MatchedRuleIDs = append(res.MatchedRuleIDs, p.MatchedRuleIDs...)
		redactionTie = mergeConstraints(&res.Constraints, p.Constraints) || redactionTie
	}

	// §4.4: a redaction-profile tie at equal rank is irreconcilable -> require_review.
	if redactionTie {
		res.Action = model.ActionRequireReview
		res.EscalatedReason = "redaction_profile_tie"
	}

	// §4.2.3: gate-class constraints always co-apply when primary is a gate.
	if isGate(res.Action) {
		for _, p := range P {
			switch p.Action {
			case model.ActionRequireConfirmation:
				res.Constraints.ConfirmationRequired = true
			case model.ActionStepUpAuth:
				res.Constraints.StepUpAuthRequired = true
			}
		}
	}

	return res
}

// compatible reports whether action a's constraints co-apply with the primary.
// Terminal stops (deny/block) suppress transform/passive constraints but keep
// the audit/review trail (§4.3).
func compatible(a, primary model.Action) bool {
	if primary == model.ActionDeny || primary == model.ActionBlock {
		switch a {
		case model.ActionDeny, model.ActionBlock, model.ActionRequireReview, model.ActionAuditOnly:
			return true
		default:
			return false
		}
	}
	return true
}

func isGate(a model.Action) bool {
	return a == model.ActionRequireConfirmation || a == model.ActionStepUpAuth || a == model.ActionRequireReview
}

// mergeConstraints performs the deterministic, most-restrictive-wins union
// (§4.4). It returns true if it detected an irreconcilable redaction-profile tie.
func mergeConstraints(acc *Constraints, in Constraints) bool {
	acc.AuditRequired = acc.AuditRequired || in.AuditRequired
	acc.EvidenceRequired = acc.EvidenceRequired || in.EvidenceRequired
	acc.ConfirmationRequired = acc.ConfirmationRequired || in.ConfirmationRequired
	acc.StepUpAuthRequired = acc.StepUpAuthRequired || in.StepUpAuthRequired

	if len(in.ScopeRestriction) > 0 {
		acc.ScopeRestriction = unionSorted(acc.ScopeRestriction, in.ScopeRestriction)
	}

	tie := false
	if in.RedactionProfile != "" {
		switch {
		case in.RedactionRank > acc.RedactionRank:
			acc.RedactionProfile = in.RedactionProfile
			acc.RedactionRank = in.RedactionRank
		case in.RedactionRank == acc.RedactionRank && acc.RedactionProfile != "" && in.RedactionProfile != acc.RedactionProfile:
			tie = true // equal-rank, different profile -> escalate to review.
		}
	}

	// Review queue: the first (highest-priority) policy to set a queue wins;
	// a later policy only overrides on a STRICTLY higher severity. Using >=
	// would let an equal-severity, lower-priority policy clobber it (P2-K).
	if in.ReviewQueue != "" {
		if acc.ReviewQueue == "" || in.ReviewQueueSeverity > acc.ReviewQueueSeverity {
			acc.ReviewQueue = in.ReviewQueue
			acc.ReviewQueueSeverity = in.ReviewQueueSeverity
		}
	}

	// First policy (highest priority) that sets a template wins.
	if acc.UserMessageTemplate == "" && in.UserMessageTemplate != "" {
		acc.UserMessageTemplate = in.UserMessageTemplate
	}
	return tie
}

func unionSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// defaultDecision is the fail behavior when no policy matched (Spec v1.5 §20.2).
// The terminal action is stage-aware so it is always valid per the Stage x
// Action Matrix: output stops are `block`, every other stage stops are `deny`
// (deny is not allowed in `output`). A stage-agnostic deny here would otherwise
// fail decision validation at the output stage and break fail-closed.
func defaultDecision(env model.Environment, fr model.FusedRisk, stage model.Stage) Resolution {
	highRisk := fr.HighestSeverity >= model.SeverityHigh || fr.HasFlag(model.FlagNeedsReview)
	switch env {
	case model.EnvProd:
		if highRisk {
			return Resolution{Action: terminalAction(stage), ReasonCodes: []string{"no_match_prod_high_risk_fail_closed"},
				Constraints: Constraints{EvidenceRequired: true, AuditRequired: true}, Confidence: fr.ConfidenceSummary.Representative}
		}
		return Resolution{Action: model.ActionAuditOnly, ReasonCodes: []string{"no_match_prod_low_risk_fallback"},
			Constraints: Constraints{AuditRequired: true}, Confidence: fr.ConfidenceSummary.Representative}
	case model.EnvCanary:
		return Resolution{Action: model.ActionRequireReview, ReasonCodes: []string{"no_match_canary_review"},
			Constraints: Constraints{ReviewQueue: "default"}, Confidence: fr.ConfidenceSummary.Representative}
	default: // shadow
		return Resolution{Action: model.ActionAuditOnly, ReasonCodes: []string{"no_match_shadow_audit"},
			Constraints: Constraints{AuditRequired: true}, Confidence: fr.ConfidenceSummary.Representative}
	}
}

// terminalAction returns the strongest stop action that is valid for the stage
// per the Stage x Action Matrix (§2): `block` at output, `deny` elsewhere.
func terminalAction(stage model.Stage) model.Action {
	if stage == model.StageOutput {
		return model.ActionBlock
	}
	return model.ActionDeny
}
