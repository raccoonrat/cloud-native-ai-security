package policy

import "github.com/raccoonrat/cloud-native-ai-security/controlplane/model"

// DefaultBundle returns the Sprint-2 MVP policy bundle covering the three golden
// scenarios (Spec v1.5 §19) plus a revoked-tool deny. Real deployments load a
// versioned, gate-released bundle; this constant bundle exists so the vertical
// slice is testable end to end.
func DefaultBundle() Bundle {
	allEnv := []model.Environment{model.EnvShadow, model.EnvCanary, model.EnvProd}
	return Bundle{
		Version: "bundle-mvp-2026-06-24",
		Policies: []Policy{
			{
				PolicyID: "tool_revocation_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 200,
				Scope:    Scope{Stages: []model.Stage{model.StageToolPreExecution}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{{Field: "fused_risk", Op: "has_flag", Value: []string{model.FlagToolRevoked}}},
				},
				RuleIDs: []string{"rule-revoked-deny"},
				Decision: PolicyDecision{
					Action:     model.ActionDeny,
					ReasonCode: "revoked_tool_denied",
					Constraints: Constraints{EvidenceRequired: true, AuditRequired: true},
				},
			},
			{
				// Golden Scenario 1: Enterprise Data Leakage Output Control.
				PolicyID: "enterprise_external_disclosure_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 100,
				Scope:    Scope{Stages: []model.Stage{model.StageOutput}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{
						{Field: "data.sensitivity", Op: "in", Value: []string{"confidential", "restricted", "regulated"}},
						{Field: "destination.boundary", Op: "in", Value: []string{"external", "cross_tenant"}},
					},
				},
				RuleIDs: []string{"rule-001"},
				Decision: PolicyDecision{
					Action:     model.ActionRedact,
					ReasonCode: "confidential_enterprise_data_external_boundary",
					Constraints: Constraints{
						RedactionProfile: "enterprise_confidential_v1", RedactionRank: 1,
						EvidenceRequired: true, AuditRequired: true,
						UserMessageTemplate: "enterprise_data_redacted_external_boundary",
					},
				},
			},
			{
				// Golden Scenario 2: Prompt Injection Input / Retrieval Control.
				PolicyID: "untrusted_retrieval_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 90,
				Scope:    Scope{Stages: []model.Stage{model.StageRetrieval}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{{Field: "fused_risk.highest_severity", Op: "gte", Value: []string{"high"}}},
				},
				RuleIDs: []string{"rule-retrieval-001"},
				Decision: PolicyDecision{
					Action:     model.ActionRestrictScope,
					ReasonCode: "untrusted_retrieval_prompt_injection",
					Constraints: Constraints{
						ScopeRestriction: []string{"drop_untrusted_source"},
						EvidenceRequired: true, AuditRequired: true,
					},
				},
			},
			{
				// Golden Scenario 3: Tool Pre-Execution Confirmation (no valid approval yet).
				PolicyID: "external_tool_sensitive_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 100,
				Scope:    Scope{Stages: []model.Stage{model.StageToolPreExecution}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{
						{Field: "tool.permission_class", Op: "eq", Value: []string{"external_send"}},
						{Field: "data.sensitivity", Op: "in", Value: []string{"confidential", "restricted", "regulated"}},
						{Field: "tool.approval_valid", Op: "eq", Value: []string{"false"}},
					},
				},
				RuleIDs: []string{"rule-tool-001"},
				Decision: PolicyDecision{
					Action:     model.ActionRequireConfirmation,
					ReasonCode: "external_tool_action_with_sensitive_data",
					Constraints: Constraints{
						ConfirmationRequired: true,
						EvidenceRequired:     true, AuditRequired: true,
					},
				},
			},
			{
				// Tool pre-execution with a VALID confirmation binding -> allow.
				PolicyID: "external_tool_approved_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 100,
				Scope:    Scope{Stages: []model.Stage{model.StageToolPreExecution}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{
						{Field: "tool.permission_class", Op: "eq", Value: []string{"external_send"}},
						{Field: "data.sensitivity", Op: "in", Value: []string{"confidential", "restricted", "regulated"}},
						{Field: "tool.approval_valid", Op: "eq", Value: []string{"true"}},
					},
				},
				RuleIDs: []string{"rule-tool-approved"},
				Decision: PolicyDecision{
					Action:     model.ActionAllow,
					ReasonCode: "external_tool_action_approved",
					Constraints: Constraints{EvidenceRequired: true, AuditRequired: true},
				},
			},
			{
				// Unknown tool with an elevated permission class -> deny (Spec v1.5 §20.4).
				PolicyID: "unknown_tool_elevated_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 150,
				Scope:    Scope{Stages: []model.Stage{model.StageToolPreExecution}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{
						{Field: "tool.trust_state", Op: "eq", Value: []string{"unknown"}},
						{Field: "tool.permission_class", Op: "in", Value: []string{"write", "external_send", "privileged"}},
					},
				},
				RuleIDs: []string{"rule-unknown-elevated"},
				Decision: PolicyDecision{
					Action:     model.ActionDeny,
					ReasonCode: "unknown_tool_elevated_denied",
					Constraints: Constraints{EvidenceRequired: true, AuditRequired: true},
				},
			},
			{
				// Unknown tool with a read permission class -> require_review (Spec v1.5 §20.4).
				PolicyID: "unknown_tool_read_policy",
				Version:  "1.0.0",
				Status:   "prod",
				Priority: 140,
				Scope:    Scope{Stages: []model.Stage{model.StageToolPreExecution}, Environments: allEnv, AppIDs: []string{"*"}, TenantIDs: []string{"*"}},
				Condition: Condition{
					All: []Predicate{
						{Field: "tool.trust_state", Op: "eq", Value: []string{"unknown"}},
						{Field: "tool.permission_class", Op: "eq", Value: []string{"read"}},
					},
				},
				RuleIDs: []string{"rule-unknown-read"},
				Decision: PolicyDecision{
					Action:     model.ActionRequireReview,
					ReasonCode: "unknown_tool_read_review",
					Constraints: Constraints{ReviewQueue: "tool_security", EvidenceRequired: true, AuditRequired: true},
				},
			},
		},
	}
}
