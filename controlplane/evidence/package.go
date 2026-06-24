package evidence

import (
	"sort"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// Evidence field tokens (Spec v1.5 §13.1 / §13.5).
const (
	FieldContext          = "context"
	FieldContentSpan      = "content_span"
	FieldRetrievalSource  = "retrieval_source"
	FieldSignalSummary    = "signal_summary"
	FieldPolicyMatch      = "policy_match"
	FieldDecision         = "decision"
	FieldToolMetadata     = "tool_metadata"
	FieldParametersHash   = "parameters_hash"
	FieldApprovalRecord   = "approval_record"
	FieldEnforcementResult = "enforcement_result"
)

// requiredByStage is the stage-specific required-evidence table (Spec v1.5 §13.5).
var requiredByStage = map[model.Stage][]string{
	model.StageInput: {
		FieldContext, FieldContentSpan, FieldSignalSummary, FieldPolicyMatch, FieldDecision,
	},
	model.StageRetrieval: {
		FieldContext, FieldRetrievalSource, FieldContentSpan, FieldSignalSummary, FieldPolicyMatch, FieldDecision,
	},
	model.StageToolPreExecution: {
		FieldContext, FieldToolMetadata, FieldParametersHash, FieldApprovalRecord, FieldSignalSummary, FieldPolicyMatch, FieldDecision,
	},
	model.StageOutput: {
		FieldContext, FieldContentSpan, FieldSignalSummary, FieldPolicyMatch, FieldDecision, FieldEnforcementResult,
	},
}

// RequiredFields returns the required evidence tokens for a stage.
func RequiredFields(stage model.Stage) []string { return requiredByStage[stage] }

// Enrichment marks evidence captured by asynchronous enrichment (Spec v1.5 §13.4)
// that is not derivable from the synchronous Decision Contract alone.
type Enrichment struct {
	ContentSpanCaptured     bool
	RetrievalSourceCaptured bool
	EnforcementResultCommitted bool
}

// Package is the full evidence package (Spec v1.5 §13.2). The Sprint-4 model
// tracks which required evidence fields are present so completeness is scorable.
type Package struct {
	EvidenceID string          `json:"evidence_id"`
	TraceID    string          `json:"trace_id"`
	DecisionID string          `json:"decision_id"`
	Stage      model.Stage     `json:"stage"`
	Present    map[string]bool `json:"present"`
	RiskFamily model.RiskFamily `json:"risk_family,omitempty"`
}

// BuildFromContract derives the present evidence set from a Decision Contract
// plus optional async enrichment, then is ready for completeness scoring.
func BuildFromContract(c decision.Contract, enr Enrichment) Package {
	present := map[string]bool{
		FieldContext:       c.ContextID != "",
		FieldSignalSummary: true, // the fused-risk summary is always committed
		FieldPolicyMatch:   len(c.Policy.MatchedPolicies) > 0,
		FieldDecision:      c.Decision.ReasonCode != "",
	}
	if c.Stage == model.StageToolPreExecution {
		present[FieldToolMetadata] = c.Object.ToolID != ""
		present[FieldParametersHash] = c.ApprovalBinding.BindingHash != ""
		present[FieldApprovalRecord] = c.ApprovalBinding.Required || c.ApprovalBinding.ApprovalID != ""
	}
	if enr.ContentSpanCaptured {
		present[FieldContentSpan] = true
	}
	if enr.RetrievalSourceCaptured {
		present[FieldRetrievalSource] = true
	}
	if enr.EnforcementResultCommitted {
		present[FieldEnforcementResult] = true
	}

	var fam model.RiskFamily
	if len(c.FusedRiskSummary.RiskFamilies) > 0 {
		fam = c.FusedRiskSummary.RiskFamilies[0]
	}
	return Package{
		TraceID: c.TraceID, DecisionID: c.DecisionID, Stage: c.Stage,
		Present: present, RiskFamily: fam,
	}
}

// Completeness implements Spec v1.5 §13.5:
// evidence_completeness = required_fields_present / required_fields_total.
func (p Package) Completeness() float64 {
	req := requiredByStage[p.Stage]
	if len(req) == 0 {
		return 0
	}
	got := 0
	for _, f := range req {
		if p.Present[f] {
			got++
		}
	}
	return float64(got) / float64(len(req))
}

// MissingFields returns the required-but-absent evidence tokens (sorted).
func (p Package) MissingFields() []string {
	var miss []string
	for _, f := range requiredByStage[p.Stage] {
		if !p.Present[f] {
			miss = append(miss, f)
		}
	}
	sort.Strings(miss)
	return miss
}
