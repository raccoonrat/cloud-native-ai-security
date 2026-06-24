package policy

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func cloneBundle(b Bundle) Bundle {
	ps := make([]Policy, len(b.Policies))
	copy(ps, b.Policies)
	return Bundle{Version: b.Version, Policies: ps}
}

func findIdx(b Bundle, id string) int {
	for i, p := range b.Policies {
		if p.PolicyID == id {
			return i
		}
	}
	return -1
}

func TestDiff_NoChange(t *testing.T) {
	cur := DefaultBundle()
	cand := cloneBundle(cur)
	d := Diff(cur, cand)
	if d.RiskLevel != "low" {
		t.Fatalf("identical bundles must be low risk, got %s", d.RiskLevel)
	}
	if len(d.Added)+len(d.Removed)+len(d.Modified) != 0 {
		t.Fatalf("identical bundles must have no changes, got %+v", d)
	}
}

func TestDiff_WeakenControlIsCritical(t *testing.T) {
	cur := DefaultBundle()
	cand := cloneBundle(cur)
	cand.Version = "bundle-candidate"
	i := findIdx(cand, "enterprise_external_disclosure_policy")
	cand.Policies[i].Version = "1.1.0"
	cand.Policies[i].Decision.Action = model.ActionAllow // redact -> allow weakens a control

	d := Diff(cur, cand)
	if d.RiskLevel != "critical" {
		t.Fatalf("weakening a control must be critical, got %s", d.RiskLevel)
	}
	if len(d.Modified) != 1 || !d.Modified[0].Weakened {
		t.Fatalf("expected one weakened modification, got %+v", d.Modified)
	}
	if !containsStage(d.AffectedStages, model.StageOutput) {
		t.Fatalf("blast radius must include output stage, got %v", d.AffectedStages)
	}
}

func TestDiff_RemoveControlIsCritical(t *testing.T) {
	cur := DefaultBundle()
	cand := cloneBundle(cur)
	i := findIdx(cand, "tool_revocation_policy")
	cand.Policies = append(cand.Policies[:i], cand.Policies[i+1:]...)

	d := Diff(cur, cand)
	if d.RiskLevel != "critical" {
		t.Fatalf("removing a deny control must be critical, got %s", d.RiskLevel)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "tool_revocation_policy" {
		t.Fatalf("expected removed tool_revocation_policy, got %v", d.Removed)
	}
}

func TestDiff_AddPolicyIsMedium(t *testing.T) {
	cur := DefaultBundle()
	cand := cloneBundle(cur)
	cand.Policies = append(cand.Policies, Policy{
		PolicyID: "new_audit_policy", Version: "1.0.0", Status: "prod", Priority: 10,
		Scope:    Scope{Stages: []model.Stage{model.StageInput}},
		Decision: PolicyDecision{Action: model.ActionAuditOnly, ReasonCode: "new_audit"},
	})
	d := Diff(cur, cand)
	if d.RiskLevel != "medium" {
		t.Fatalf("adding a policy must be medium risk, got %s", d.RiskLevel)
	}
}

func TestDiff_ConstraintOnlyChangeIsMedium(t *testing.T) {
	cur := DefaultBundle()
	cand := cloneBundle(cur)
	i := findIdx(cand, "enterprise_external_disclosure_policy")
	c := cand.Policies[i].Decision.Constraints
	c.RedactionProfile = "enterprise_confidential_v2"
	cand.Policies[i].Decision.Constraints = c

	d := Diff(cur, cand)
	if d.RiskLevel != "medium" {
		t.Fatalf("constraint-only change must be medium, got %s", d.RiskLevel)
	}
	if len(d.Modified) != 1 || !d.Modified[0].ConstraintChanged || d.Modified[0].ActionChanged {
		t.Fatalf("expected constraint-only modification, got %+v", d.Modified)
	}
}
