package evidence

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func baseContract(stage model.Stage) decision.Contract {
	c := decision.Contract{
		TraceID: "t1", DecisionID: "d1", ContextID: "ctx1", Stage: stage,
	}
	c.Decision.ReasonCode = "some_reason"
	c.Policy.MatchedPolicies = []decision.MatchedPolicy{{PolicyID: "p1"}}
	return c
}

func TestCompleteness_OutputMinimalVsEnriched(t *testing.T) {
	c := baseContract(model.StageOutput)

	// Synchronous minimal: content_span + enforcement_result not yet captured.
	min := BuildFromContract(c, Enrichment{}).Completeness()
	// required = 6 (context, content_span, signal_summary, policy_match, decision, enforcement_result)
	// present = 4 (context, signal_summary, policy_match, decision)
	if min <= 0 || min >= 1 {
		t.Fatalf("minimal completeness should be partial, got %.3f", min)
	}
	if got, want := min, 4.0/6.0; got != want {
		t.Fatalf("minimal completeness = %.3f want %.3f", got, want)
	}

	// Async enrichment completes the package (§13.4).
	full := BuildFromContract(c, Enrichment{ContentSpanCaptured: true, EnforcementResultCommitted: true}).Completeness()
	if full != 1.0 {
		t.Fatalf("enriched completeness = %.3f want 1.0 (missing=%v)", full,
			BuildFromContract(c, Enrichment{ContentSpanCaptured: true, EnforcementResultCommitted: true}).MissingFields())
	}
}

func TestCompleteness_ToolStage(t *testing.T) {
	c := baseContract(model.StageToolPreExecution)
	c.Object.ToolID = "send_email"
	c.ApprovalBinding = decision.ApprovalBinding{Required: true, ApprovalID: "appr-1", BindingHash: "h"}

	// tool required = 7: context, tool_metadata, parameters_hash, approval_record, signal_summary, policy_match, decision
	got := BuildFromContract(c, Enrichment{}).Completeness()
	if got != 1.0 {
		t.Fatalf("tool completeness = %.3f want 1.0 (missing=%v)", got,
			BuildFromContract(c, Enrichment{}).MissingFields())
	}
}

func TestCompleteness_MissingPolicyMatchLowers(t *testing.T) {
	c := baseContract(model.StageInput)
	c.Policy.MatchedPolicies = nil // default fallback, no explicit match
	pkg := BuildFromContract(c, Enrichment{ContentSpanCaptured: true})
	if pkg.Completeness() == 1.0 {
		t.Fatalf("missing policy_match must lower completeness, got 1.0")
	}
	miss := pkg.MissingFields()
	if len(miss) != 1 || miss[0] != FieldPolicyMatch {
		t.Fatalf("want only policy_match missing, got %v", miss)
	}
}
