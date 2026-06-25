package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// Context is the normalized runtime context snapshot (Spec v1.6 §7). Only the
// fields consumed by the Sprint-1 vertical slice (fusion + policy) are modeled
// concretely; the full schema is carried as the embedded JSON Schema.
type Context struct {
	SchemaVersion string      `json:"schema_version"`
	ContextID     string      `json:"context_id"`
	TraceID       string      `json:"trace_id"`
	RequestID     string      `json:"request_id"`
	Stage         Stage       `json:"stage"`
	Timestamp     time.Time   `json:"timestamp,omitempty"`
	Actor         Actor       `json:"actor"`
	Application   Application `json:"application"`
	Data          DataCtx     `json:"data"`
	Destination   Destination `json:"destination"`
	Tool          ToolCtx     `json:"tool"`
	Runtime       Runtime     `json:"runtime"`
}

// Actor holds identity/privilege facts.
type Actor struct {
	UserID         string `json:"user_id"`
	TenantID       string `json:"tenant_id"`
	Role           string `json:"role"`
	PrivilegeLevel string `json:"privilege_level"`
	AuthStrength   string `json:"auth_strength"`
}

// Application holds the calling application/runtime facts.
type Application struct {
	AppID            string      `json:"app_id"`
	RuntimeID        string      `json:"runtime_id"`
	Environment      Environment `json:"environment"`
	IntegrationPoint string      `json:"integration_point"`
}

// DataCtx holds data classification facts.
type DataCtx struct {
	DataAssetType        string `json:"data_asset_type"`
	Sensitivity          string `json:"sensitivity"`
	Owner                string `json:"owner"`
	Provenance           string `json:"provenance"`
	ClassificationSource string `json:"classification_source"`
}

// Destination holds boundary/channel facts.
type Destination struct {
	Boundary      Boundary `json:"boundary"`
	Channel       string   `json:"channel"`
	RecipientType string   `json:"recipient_type"`
}

// ToolCtx holds the registry-backed tool facts relevant to fusion (FR-003/007/008).
type ToolCtx struct {
	ToolID          string          `json:"tool_id"`
	ServerID        string          `json:"server_id"`
	ToolVersion     string          `json:"tool_version"`
	SchemaHash      string          `json:"schema_hash"`
	ManifestHash    string          `json:"manifest_hash"`
	PermissionClass PermissionClass `json:"permission_class"`
	TrustState      TrustState      `json:"trust_state"`
	HasPriorApproval bool           `json:"has_prior_approval"`
	ApprovalValid    bool           `json:"approval_valid"`
}

// Runtime carries the version pins required for replay determinism.
type Runtime struct {
	Region                 string `json:"region"`
	DeploymentID           string `json:"deployment_id"`
	PolicyBundleVersion    string `json:"policy_bundle_version"`
	FusionConfigVersion    string `json:"fusion_config_version"`
	ThresholdConfigVersion string `json:"threshold_config_version"`
	MatrixVersion          string `json:"matrix_version"`
}

// Signal is a structured security signal (Spec v1.6 §8). Signal is NOT a
// decision (INV-1); provenance must be verifiable (INV-7).
type Signal struct {
	SchemaVersion string          `json:"schema_version"`
	SignalID      string          `json:"signal_id"`
	TraceID       string          `json:"trace_id"`
	ContextID     string          `json:"context_id"`
	Stage         Stage           `json:"stage"`
	SignalType    string          `json:"signal_type"`
	RiskFamily    RiskFamily      `json:"risk_family"`
	Severity      Severity        `json:"severity"`
	Confidence    float64         `json:"confidence"`
	CreatedAt     time.Time       `json:"created_at,omitempty"`
	TTLMs         int64           `json:"ttl_ms"`
	Source        SignalSource    `json:"source"`
	Attributes    SignalAttrs     `json:"attributes"`
	Integrity     SignalIntegrity `json:"integrity"`
	EvidenceRef   string          `json:"evidence_ref,omitempty"`
}

// SignalSource is the signal origin used for provenance checks (INV-7).
type SignalSource struct {
	SourceID      string     `json:"source_id"`
	SourceType    SourceType `json:"source_type"`
	SourceVersion string     `json:"source_version"`
}

// SignalAttrs carries optional, type-specific attributes.
type SignalAttrs struct {
	ToolID       string `json:"tool_id,omitempty"`
	ServerID     string `json:"server_id,omitempty"`
	ReasonSummary string `json:"reason_summary,omitempty"`
	AdvisoryOnly bool   `json:"advisory_only,omitempty"`
}

// SignalIntegrity carries the MODE-B signature material (INV-7).
type SignalIntegrity struct {
	Signature        string `json:"signature,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	SignedPayloadHash string `json:"signed_payload_hash,omitempty"`
}

// CanonicalSignalHash is the content hash a MODE-B signer MUST sign (INV-7).
// It covers every security-relevant field EXCEPT the Integrity block itself, so
// the signature binds the signal payload: a valid (hash, signature) pair cannot
// be replayed onto a signal with a different severity/type/source/etc.
func CanonicalSignalHash(s Signal) string {
	core := struct {
		SchemaVersion string       `json:"schema_version"`
		SignalID      string       `json:"signal_id"`
		TraceID       string       `json:"trace_id"`
		ContextID     string       `json:"context_id"`
		Stage         Stage        `json:"stage"`
		SignalType    string       `json:"signal_type"`
		RiskFamily    RiskFamily   `json:"risk_family"`
		Severity      Severity     `json:"severity"`
		Confidence    float64      `json:"confidence"`
		CreatedAt     time.Time    `json:"created_at"`
		TTLMs         int64        `json:"ttl_ms"`
		Source        SignalSource `json:"source"`
		Attributes    SignalAttrs  `json:"attributes"`
		EvidenceRef   string       `json:"evidence_ref"`
	}{
		SchemaVersion: s.SchemaVersion, SignalID: s.SignalID, TraceID: s.TraceID,
		ContextID: s.ContextID, Stage: s.Stage, SignalType: s.SignalType,
		RiskFamily: s.RiskFamily, Severity: s.Severity, Confidence: s.Confidence,
		CreatedAt: s.CreatedAt.UTC(), TTLMs: s.TTLMs, Source: s.Source,
		Attributes: s.Attributes, EvidenceRef: s.EvidenceRef,
	}
	b, _ := json.Marshal(core)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// IsExpired reports whether the signal TTL has elapsed relative to now.
// A non-positive TTL means "no expiry".
func (s Signal) IsExpired(now time.Time) bool {
	if s.TTLMs <= 0 || s.CreatedAt.IsZero() || now.IsZero() {
		return false
	}
	return now.After(s.CreatedAt.Add(time.Duration(s.TTLMs) * time.Millisecond))
}

// Conflict records a detector disagreement (Spec v1.5 §9.2, FR-004).
type Conflict struct {
	ConflictType string   `json:"conflict_type"`
	SignalIDs    []string `json:"signal_ids"`
	Resolution   string   `json:"resolution"`
}

// ConfidenceSummary is the deterministic_v1 aggregation (Spec v1.6 §3.5).
type ConfidenceSummary struct {
	Min            float64 `json:"min"`
	Max            float64 `json:"max"`
	Representative float64 `json:"representative"`
	Aggregation    string  `json:"aggregation"`
	HasValues      bool    `json:"-"`
}

// DroppedSignal records a signal removed during normalization (INV-7, §1.3).
type DroppedSignal struct {
	SourceID string `json:"source_id"`
	SignalID string `json:"signal_id"`
	Reason   string `json:"reason"`
}

// FusedRisk is the output of deterministic fusion (Spec v1.6 §3.6). Fusion
// emits facts, never an action (INV-2): Flags such as needs_review and
// approval_invalidated are inputs to Policy.
type FusedRisk struct {
	SchemaVersion         string            `json:"schema_version"`
	HighestSeverity       Severity          `json:"highest_severity"`
	RiskFamilies          []RiskFamily      `json:"risk_families"`
	Flags                 map[string]bool   `json:"flags"`
	RiskReasons           []string          `json:"risk_reasons"`
	Conflicts             []Conflict        `json:"conflicts"`
	Uncertainty           Uncertainty       `json:"uncertainty"`
	ConfidenceSummary     ConfidenceSummary `json:"confidence_summary"`
	RecommendedPolicyPath string            `json:"recommended_policy_path"`
	FusionConfigVersion   string            `json:"fusion_config_version"`
	DroppedSignals        []DroppedSignal   `json:"dropped_signals,omitempty"`
}

// HasFlag reports whether a fusion fact flag is set.
func (f FusedRisk) HasFlag(name string) bool { return f.Flags[name] }

// SortedFlags returns flag names in deterministic order (for serialization).
func (f FusedRisk) SortedFlags() []string {
	out := make([]string, 0, len(f.Flags))
	for k, v := range f.Flags {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Fusion fact flag names (Spec v1.6 §3.4).
const (
	FlagToolRevoked          = "tool_revoked"
	FlagApprovalInvalidated  = "approval_invalidated"
	FlagNeedsReview          = "needs_review"
)
