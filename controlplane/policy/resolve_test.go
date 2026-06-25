package policy

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func mp(id string, prio int, a model.Action, reason string) MatchedPolicy {
	return MatchedPolicy{PolicyID: id, Priority: prio, Action: a, ReasonCode: reason}
}

func emptyFR() model.FusedRisk {
	return model.FusedRisk{Flags: map[string]bool{}, ConfidenceSummary: model.ConfidenceSummary{Representative: 0.9}}
}

// v1.5 §10.4 pairwise conflict cases must all hold under the strength order.
func TestPairwiseConflicts(t *testing.T) {
	cases := []struct {
		name string
		in   []MatchedPolicy
		want model.Action
	}{
		{"allow_vs_deny", []MatchedPolicy{mp("a", 10, model.ActionAllow, "x"), mp("b", 10, model.ActionDeny, "y")}, model.ActionDeny},
		{"allow_vs_redact", []MatchedPolicy{mp("a", 10, model.ActionAllow, "x"), mp("b", 10, model.ActionRedact, "y")}, model.ActionRedact},
		{"redact_vs_block", []MatchedPolicy{mp("a", 10, model.ActionRedact, "x"), mp("b", 10, model.ActionBlock, "y")}, model.ActionBlock},
		{"confirm_vs_deny", []MatchedPolicy{mp("a", 10, model.ActionRequireConfirmation, "x"), mp("b", 10, model.ActionDeny, "y")}, model.ActionDeny},
		{"audit_vs_redact", []MatchedPolicy{mp("a", 10, model.ActionAuditOnly, "x"), mp("b", 10, model.ActionRedact, "y")}, model.ActionRedact},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Resolve(c.in, model.EnvProd, emptyFR(), model.StageOutput)
			if got.Action != c.want {
				t.Fatalf("%s: want %s, got %s", c.name, c.want, got.Action)
			}
		})
	}
}

// require_confirmation + step_up_auth -> both constraints co-apply (§4.2.3 "combine").
func TestCombineConfirmationAndStepUp(t *testing.T) {
	in := []MatchedPolicy{
		mp("a", 10, model.ActionRequireConfirmation, "confirm"),
		mp("b", 10, model.ActionStepUpAuth, "stepup"),
	}
	got := Resolve(in, model.EnvProd, emptyFR(), model.StageToolPreExecution)
	// step_up_auth (90) > require_confirmation (80) -> primary step_up_auth.
	if got.Action != model.ActionStepUpAuth {
		t.Fatalf("want step_up_auth primary, got %s", got.Action)
	}
	if !got.Constraints.ConfirmationRequired || !got.Constraints.StepUpAuthRequired {
		t.Fatalf("want both confirmation+stepup constraints, got %+v", got.Constraints)
	}
}

// Terminal block suppresses transform constraints but keeps the reason trail (§4.3).
func TestBlockSuppressesTransformConstraints(t *testing.T) {
	in := []MatchedPolicy{
		{PolicyID: "redactor", Priority: 10, Action: model.ActionRedact, ReasonCode: "redact_pii",
			Constraints: Constraints{RedactionProfile: "pii_v1", RedactionRank: 1, EvidenceRequired: true}},
		{PolicyID: "blocker", Priority: 10, Action: model.ActionBlock, ReasonCode: "block_critical",
			Constraints: Constraints{EvidenceRequired: true}},
	}
	got := Resolve(in, model.EnvProd, emptyFR(), model.StageOutput)
	if got.Action != model.ActionBlock {
		t.Fatalf("want block, got %s", got.Action)
	}
	if got.Constraints.RedactionProfile != "" {
		t.Fatalf("block must suppress redaction profile, got %q", got.Constraints.RedactionProfile)
	}
	// Reason trail from the incompatible redact policy is NOT applied (incompatible),
	// but the block reason must be present.
	if !contains(got.ReasonCodes, "block_critical") {
		t.Fatalf("want block reason in trail, got %v", got.ReasonCodes)
	}
}

// Multi-policy constraint union under a non-terminal primary (require_review).
func TestMultiPolicyConstraintUnion(t *testing.T) {
	in := []MatchedPolicy{
		{PolicyID: "redactor", Priority: 20, Action: model.ActionRedact, ReasonCode: "redact",
			Constraints: Constraints{RedactionProfile: "conf_v1", RedactionRank: 2, EvidenceRequired: true, AuditRequired: true}},
		{PolicyID: "reviewer", Priority: 30, Action: model.ActionRequireReview, ReasonCode: "review",
			Constraints: Constraints{ReviewQueue: "privacy", ReviewQueueSeverity: model.SeverityHigh, EvidenceRequired: true}},
	}
	got := Resolve(in, model.EnvProd, emptyFR(), model.StageOutput)
	if got.Action != model.ActionRequireReview {
		t.Fatalf("want require_review (strength 100 > 60), got %s", got.Action)
	}
	// require_review is not terminal, so redaction constraint co-applies.
	if got.Constraints.RedactionProfile != "conf_v1" {
		t.Fatalf("want redaction profile merged, got %q", got.Constraints.RedactionProfile)
	}
	if got.Constraints.ReviewQueue != "privacy" {
		t.Fatalf("want review queue privacy, got %q", got.Constraints.ReviewQueue)
	}
	if !got.Constraints.AuditRequired || !got.Constraints.EvidenceRequired {
		t.Fatalf("want audit+evidence required, got %+v", got.Constraints)
	}
}

// Equal-rank, different redaction profile -> escalate to require_review (§4.4).
func TestRedactionProfileTieEscalates(t *testing.T) {
	in := []MatchedPolicy{
		{PolicyID: "a", Priority: 10, Action: model.ActionRedact, ReasonCode: "ra",
			Constraints: Constraints{RedactionProfile: "p1", RedactionRank: 1}},
		{PolicyID: "b", Priority: 10, Action: model.ActionRedact, ReasonCode: "rb",
			Constraints: Constraints{RedactionProfile: "p2", RedactionRank: 1}},
	}
	got := Resolve(in, model.EnvProd, emptyFR(), model.StageOutput)
	if got.Action != model.ActionRequireReview {
		t.Fatalf("want escalation to require_review on tie, got %s", got.Action)
	}
	if got.EscalatedReason != "redaction_profile_tie" {
		t.Fatalf("want redaction_profile_tie reason, got %q", got.EscalatedReason)
	}
}

// No matched policy -> environment-specific fail behavior (§20.2). The terminal
// fail-closed action must be valid for the stage per the Stage x Action Matrix:
// deny for input/retrieval/tool_pre_execution, block for output.
func TestDefaultDecisionFailClosed(t *testing.T) {
	fr := emptyFR()
	fr.HighestSeverity = model.SeverityHigh

	for _, stage := range []model.Stage{model.StageInput, model.StageRetrieval, model.StageToolPreExecution} {
		got := Resolve(nil, model.EnvProd, fr, stage)
		if got.Action != model.ActionDeny {
			t.Fatalf("prod high-risk no-match at %s must fail closed (deny), got %s", stage, got.Action)
		}
	}

	// Output stage must fail closed with `block` (deny is not allowed in output).
	gotOutput := Resolve(nil, model.EnvProd, fr, model.StageOutput)
	if gotOutput.Action != model.ActionBlock {
		t.Fatalf("prod high-risk no-match at output must fail closed (block), got %s", gotOutput.Action)
	}

	gotShadow := Resolve(nil, model.EnvShadow, fr, model.StageOutput)
	if gotShadow.Action != model.ActionAuditOnly {
		t.Fatalf("shadow no-match must be audit_only, got %s", gotShadow.Action)
	}
}

// Resolve is deterministic regardless of matched-policy input order.
func TestResolveOrderIndependence(t *testing.T) {
	a := []MatchedPolicy{
		{PolicyID: "x", Priority: 20, Action: model.ActionRedact, ReasonCode: "r", Constraints: Constraints{RedactionProfile: "p", RedactionRank: 1}},
		{PolicyID: "y", Priority: 30, Action: model.ActionRequireReview, ReasonCode: "v", Constraints: Constraints{ReviewQueue: "q", ReviewQueueSeverity: model.SeverityHigh}},
		{PolicyID: "z", Priority: 10, Action: model.ActionAuditOnly, ReasonCode: "a", Constraints: Constraints{AuditRequired: true}},
	}
	b := []MatchedPolicy{a[2], a[0], a[1]}

	r1 := Resolve(a, model.EnvProd, emptyFR(), model.StageOutput)
	r2 := Resolve(b, model.EnvProd, emptyFR(), model.StageOutput)
	if r1.Action != r2.Action || r1.Constraints.ReviewQueue != r2.Constraints.ReviewQueue {
		t.Fatalf("resolve not order-independent: %+v vs %+v", r1, r2)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
