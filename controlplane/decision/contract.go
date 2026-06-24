// Package decision builds, signs, and validates the Decision Contract — the only
// enforcement input (INV-3). Spec v1.6 §11 (+ §1.4 provenance, §6.2 revision).
package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

// Contract is the Decision Contract (Spec v1.6 §11.1).
type Contract struct {
	SchemaVersion    string           `json:"schema_version"`
	DecisionID       string           `json:"decision_id"`
	TraceID          string           `json:"trace_id"`
	ContextID        string           `json:"context_id"`
	Timestamp        time.Time        `json:"timestamp"`
	Stage            model.Stage      `json:"stage"`
	Subject          Subject          `json:"subject"`
	Object           Object           `json:"object"`
	Signals          []SignalRef      `json:"signals"`
	FusedRiskSummary FusedRiskSummary `json:"fused_risk_summary"`
	Policy           PolicyRef        `json:"policy"`
	Decision         Block            `json:"decision"`
	Constraints      ConstraintsBlock `json:"constraints"`
	ApprovalBinding  ApprovalBinding  `json:"approval_binding"`
	Evidence         EvidenceBlock    `json:"evidence"`
	ReplayBinding    ReplayBinding    `json:"replay_binding"`
	Integrity        Integrity        `json:"integrity"`
}

// Subject is the acting principal.
type Subject struct {
	UserID         string `json:"user_id"`
	TenantID       string `json:"tenant_id"`
	AppID          string `json:"app_id"`
	SessionID      string `json:"session_id"`
	PrivilegeLevel string `json:"privilege_level"`
}

// Object is the thing being controlled.
type Object struct {
	ObjectType          string `json:"object_type"`
	DataAssetType       string `json:"data_asset_type"`
	Sensitivity         string `json:"sensitivity"`
	ToolID              string `json:"tool_id,omitempty"`
	ServerID            string `json:"server_id,omitempty"`
	DestinationBoundary string `json:"destination_boundary"`
}

// SignalRef is a compact signal reference carried on the decision.
type SignalRef struct {
	SignalID   string         `json:"signal_id"`
	SignalType string         `json:"signal_type"`
	RiskFamily model.RiskFamily `json:"risk_family"`
	Severity   model.Severity `json:"severity"`
	Confidence float64        `json:"confidence"`
}

// FusedRiskSummary mirrors the relevant fused facts.
type FusedRiskSummary struct {
	HighestSeverity model.Severity     `json:"highest_severity"`
	RiskFamilies    []model.RiskFamily `json:"risk_families"`
	RiskReasons     []string           `json:"risk_reasons"`
	Flags           []string           `json:"flags"`
	Uncertainty     model.Uncertainty  `json:"uncertainty"`
}

// PolicyRef binds the decision to the policy bundle and matched rules.
type PolicyRef struct {
	PolicyBundleVersion string          `json:"policy_bundle_version"`
	MatchedPolicies     []MatchedPolicy `json:"matched_policies"`
}

// MatchedPolicy is a compact record of a matched policy.
type MatchedPolicy struct {
	PolicyID      string   `json:"policy_id"`
	MatchedRuleIDs []string `json:"matched_rule_ids"`
}

// Block is the decision itself.
type Block struct {
	Action              model.Action `json:"action"`
	ReasonCode          string       `json:"reason_code"`
	Confidence          float64      `json:"confidence"`
	DecisionMode        string       `json:"decision_mode"`
	EnforcementRequired bool         `json:"enforcement_required"`
	Stability           string       `json:"stability"`
	DecisionRevision    int          `json:"decision_revision"`
	SupersedesID        string       `json:"supersedes_decision_id,omitempty"`
}

// ConstraintsBlock is the merged constraint set.
type ConstraintsBlock struct {
	RedactionProfile     string   `json:"redaction_profile,omitempty"`
	ScopeRestriction     []string `json:"scope_restriction,omitempty"`
	ConfirmationRequired bool     `json:"confirmation_required"`
	StepUpAuthRequired   bool     `json:"step_up_auth_required"`
	ReviewQueue          string   `json:"review_queue,omitempty"`
	AuditRequired        bool     `json:"audit_required"`
	UserMessageTemplate  string   `json:"user_message_template,omitempty"`
}

// ApprovalBinding records confirmation binding requirements (Spec v1.5 §15.3).
type ApprovalBinding struct {
	Required    bool     `json:"required"`
	BindingHash string   `json:"binding_hash,omitempty"`
	Fields      []string `json:"binding_fields,omitempty"`
}

// EvidenceBlock records evidence requirements and refs.
type EvidenceBlock struct {
	EvidenceRequired        bool     `json:"evidence_required"`
	EvidenceRefs            []string `json:"evidence_refs"`
	MinimalEvidenceCommitted bool    `json:"minimal_evidence_committed"`
}

// ReplayBinding pins every version needed for deterministic replay (Spec v1.6 §1.4, §14).
type ReplayBinding struct {
	ContextSnapshotRef     string                `json:"context_snapshot_ref"`
	SignalSnapshotRefs     []string              `json:"signal_snapshot_refs"`
	PolicyBundleVersion    string                `json:"policy_bundle_version"`
	FusionConfigVersion    string                `json:"fusion_config_version"`
	ThresholdConfigVersion string                `json:"threshold_config_version"`
	MatrixVersion          string                `json:"matrix_version"`
	ProvenanceMode         model.ProvenanceMode  `json:"provenance_mode"`
	DroppedSignals         []model.DroppedSignal `json:"dropped_signals,omitempty"`
}

// Integrity carries the decision hash and signature (Spec v1.6 §5.4).
type Integrity struct {
	DecisionHash string `json:"decision_hash"`
	SignedBy     string `json:"signed_by,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// Inputs bundles everything needed to build a Decision Contract.
type Inputs struct {
	Context        model.Context
	Signals        []model.Signal
	FusedRisk      model.FusedRisk
	Resolution     policy.Resolution
	BundleVersion  string
	ThresholdVer   string
	MatrixVersion  string
	ProvenanceMode model.ProvenanceMode
	Mode           model.Environment
}

// Build assembles, hashes, and signs a Decision Contract.
func Build(in Inputs, signer sign.Signer) Contract {
	ctx := in.Context
	res := in.Resolution

	c := Contract{
		SchemaVersion: "1.6",
		DecisionID:    idutil.New("dec"),
		TraceID:       ctx.TraceID,
		ContextID:     ctx.ContextID,
		Timestamp:     time.Now().UTC(),
		Stage:         ctx.Stage,
		Subject: Subject{
			UserID: ctx.Actor.UserID, TenantID: ctx.Actor.TenantID,
			AppID: ctx.Application.AppID, PrivilegeLevel: ctx.Actor.PrivilegeLevel,
		},
		Object: Object{
			ObjectType:          objectType(ctx.Stage),
			DataAssetType:       ctx.Data.DataAssetType,
			Sensitivity:         ctx.Data.Sensitivity,
			ToolID:              ctx.Tool.ToolID,
			ServerID:            ctx.Tool.ServerID,
			DestinationBoundary: string(ctx.Destination.Boundary),
		},
		FusedRiskSummary: FusedRiskSummary{
			HighestSeverity: in.FusedRisk.HighestSeverity,
			RiskFamilies:    in.FusedRisk.RiskFamilies,
			RiskReasons:     in.FusedRisk.RiskReasons,
			Flags:           in.FusedRisk.SortedFlags(),
			Uncertainty:     in.FusedRisk.Uncertainty,
		},
		Policy: PolicyRef{PolicyBundleVersion: in.BundleVersion},
		Decision: Block{
			Action:              res.Action,
			ReasonCode:          reasonCode(res),
			Confidence:          res.Confidence,
			DecisionMode:        string(in.Mode),
			EnforcementRequired: res.Action != model.ActionAllow && res.Action != model.ActionAuditOnly,
			Stability:           "final",
			DecisionRevision:    0,
		},
		Constraints: ConstraintsBlock{
			RedactionProfile:     res.Constraints.RedactionProfile,
			ScopeRestriction:     res.Constraints.ScopeRestriction,
			ConfirmationRequired: res.Constraints.ConfirmationRequired,
			StepUpAuthRequired:   res.Constraints.StepUpAuthRequired,
			ReviewQueue:          res.Constraints.ReviewQueue,
			AuditRequired:        res.Constraints.AuditRequired,
			UserMessageTemplate:  res.Constraints.UserMessageTemplate,
		},
		ApprovalBinding: ApprovalBinding{Required: res.Action == model.ActionRequireConfirmation || res.Constraints.ConfirmationRequired},
		Evidence:        EvidenceBlock{EvidenceRequired: res.Constraints.EvidenceRequired},
		ReplayBinding: ReplayBinding{
			ContextSnapshotRef:     ctx.ContextID,
			SignalSnapshotRefs:     signalIDs(in.Signals),
			PolicyBundleVersion:    in.BundleVersion,
			FusionConfigVersion:    in.FusedRisk.FusionConfigVersion,
			ThresholdConfigVersion: in.ThresholdVer,
			MatrixVersion:          in.MatrixVersion,
			ProvenanceMode:         in.ProvenanceMode,
			DroppedSignals:         in.FusedRisk.DroppedSignals,
		},
	}

	for _, s := range in.Signals {
		c.Signals = append(c.Signals, SignalRef{
			SignalID: s.SignalID, SignalType: s.SignalType, RiskFamily: s.RiskFamily,
			Severity: s.Severity, Confidence: s.Confidence,
		})
	}
	c.Policy.MatchedPolicies = matchedPolicies(res)

	// Integrity: hash the canonical core, then sign (§5.4).
	c.Integrity.DecisionHash = hashCore(c)
	if signer != nil {
		sig, by := signer.Sign(c.Integrity.DecisionHash)
		c.Integrity.Signature, c.Integrity.SignedBy = sig, by
	}
	return c
}

// Validate checks the v1.6 §11.2 correctness criteria.
func Validate(c Contract, m *matrix.Matrix) error {
	if err := c.Stage.Validate(); err != nil {
		return err
	}
	if err := m.Validate(c.Stage, c.Decision.Action); err != nil {
		return err
	}
	if c.Decision.ReasonCode == "" {
		return fmt.Errorf("decision: empty reason_code")
	}
	if c.ReplayBinding.ContextSnapshotRef == "" ||
		c.ReplayBinding.PolicyBundleVersion == "" ||
		c.ReplayBinding.FusionConfigVersion == "" ||
		c.ReplayBinding.MatrixVersion == "" {
		return fmt.Errorf("decision: incomplete replay_binding")
	}
	if c.Decision.Action == model.ActionRequireConfirmation && !c.ApprovalBinding.Required {
		return fmt.Errorf("decision: require_confirmation must set approval_binding")
	}
	if c.Integrity.DecisionHash == "" {
		return fmt.Errorf("decision: missing decision_hash")
	}
	return nil
}

// VerifySignature checks the decision signature (used by enforcement, INV-3).
func VerifySignature(c Contract, v sign.Verifier) bool {
	if c.Integrity.Signature == "" {
		return false
	}
	return v.Verify(c.Integrity.DecisionHash, c.Integrity.Signature)
}

func hashCore(c Contract) string {
	core := struct {
		TraceID    string       `json:"trace_id"`
		ContextID  string       `json:"context_id"`
		Stage      model.Stage  `json:"stage"`
		Action     model.Action `json:"action"`
		ReasonCode string       `json:"reason_code"`
		Bundle     string       `json:"policy_bundle_version"`
		Fusion     string       `json:"fusion_config_version"`
		Matrix     string       `json:"matrix_version"`
		Signals    []string     `json:"signal_snapshot_refs"`
	}{
		TraceID: c.TraceID, ContextID: c.ContextID, Stage: c.Stage,
		Action: c.Decision.Action, ReasonCode: c.Decision.ReasonCode,
		Bundle: c.ReplayBinding.PolicyBundleVersion, Fusion: c.ReplayBinding.FusionConfigVersion,
		Matrix: c.ReplayBinding.MatrixVersion, Signals: c.ReplayBinding.SignalSnapshotRefs,
	}
	b, _ := json.Marshal(core)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func objectType(s model.Stage) string {
	switch s {
	case model.StageInput:
		return "input"
	case model.StageRetrieval:
		return "retrieved_content"
	case model.StageToolPreExecution:
		return "tool_action"
	case model.StageOutput:
		return "model_output"
	default:
		return "unknown"
	}
}

func reasonCode(res policy.Resolution) string {
	if res.EscalatedReason != "" {
		return res.EscalatedReason
	}
	if len(res.ReasonCodes) > 0 {
		return res.ReasonCodes[0]
	}
	return "no_reason"
}

func signalIDs(s []model.Signal) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		out = append(out, x.SignalID)
	}
	return out
}

func matchedPolicies(res policy.Resolution) []MatchedPolicy {
	// res carries reason codes + rule ids; for the compact contract we surface
	// the rule ids grouped under a synthetic record when policy ids are absent.
	if len(res.MatchedRuleIDs) == 0 {
		return nil
	}
	return []MatchedPolicy{{PolicyID: "resolved", MatchedRuleIDs: dedupe(res.MatchedRuleIDs)}}
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
