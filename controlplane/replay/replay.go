// Package replay implements decision-level Replay-lite (Spec v1.5 §14, v1.6 §14).
// It deterministically re-runs fusion + policy from the pinned context and signal
// snapshots and compares the replayed action/reason against the original. It does
// NOT reproduce model generation, detector inference, RAG ranking, external tool
// responses, or human reasoning (Spec v1.5 §14.3).
package replay

import (
	"fmt"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
)

// Inputs is the snapshot captured at decision time and replayed later (§14.1).
type Inputs struct {
	OriginalDecisionID string
	Context            model.Context
	Signals            []model.Signal
	Mode               model.Environment
	OriginalAction     model.Action
	OriginalReason     string
	// EvalTime pins the instant used for signal TTL expiry at decision time so a
	// replay drops exactly the same expired signals (deterministic by §3/§14).
	// Zero means "no expiry" (TTL evaluation disabled), preserving older inputs.
	EvalTime time.Time
}

// Result is the replay outcome (§14.2).
type Result struct {
	ReplayID           string       `json:"replay_id"`
	OriginalDecisionID string       `json:"original_decision_id"`
	ReplayedAction     model.Action `json:"replayed_action"`
	ReplayedReason     string       `json:"replayed_reason_code"`
	MatchedPolicyIDs   []string     `json:"matched_policy_ids"`
	Consistency        string       `json:"consistency"` // match | mismatch | partial
	Diff               []string     `json:"diff"`
}

// Run re-evaluates the snapshot against a (possibly different) policy bundle and
// fusion config, returning the consistency verdict. Replaying with the same
// pinned versions MUST reproduce the original action (deterministic by §3/§4).
func Run(in Inputs, bundle policy.Bundle, cfg fusion.Config) Result {
	// Pin TTL expiry to the snapshot's evaluation instant so replay is
	// deterministic regardless of the caller's clock.
	if !in.EvalTime.IsZero() {
		cfg.Now = in.EvalTime
	}
	fr := fusion.Fuse(in.Signals, in.Context, cfg)
	matched := bundle.Match(in.Context, fr)
	res := policy.Resolve(matched, in.Mode, fr, in.Context.Stage)

	replayedReason := res.EscalatedReason
	if replayedReason == "" && len(res.ReasonCodes) > 0 {
		replayedReason = res.ReasonCodes[0]
	}

	out := Result{
		ReplayID:           idutil.New("replay"),
		OriginalDecisionID: in.OriginalDecisionID,
		ReplayedAction:     res.Action,
		ReplayedReason:     replayedReason,
	}
	for _, m := range matched {
		out.MatchedPolicyIDs = append(out.MatchedPolicyIDs, m.PolicyID)
	}

	actionMatch := res.Action == in.OriginalAction
	reasonMatch := replayedReason == in.OriginalReason
	switch {
	case actionMatch && reasonMatch:
		out.Consistency = "match"
	case actionMatch && !reasonMatch:
		out.Consistency = "partial"
		out.Diff = append(out.Diff, fmt.Sprintf("reason: %q -> %q", in.OriginalReason, replayedReason))
	default:
		out.Consistency = "mismatch"
		out.Diff = append(out.Diff, fmt.Sprintf("action: %q -> %q", in.OriginalAction, res.Action))
		if !reasonMatch {
			out.Diff = append(out.Diff, fmt.Sprintf("reason: %q -> %q", in.OriginalReason, replayedReason))
		}
	}
	return out
}
