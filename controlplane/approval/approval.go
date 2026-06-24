// Package approval is the Approval Binding Service (Spec v1.5 §15.3/§15.4,
// v1.6 §15). A human confirmation binds a concrete action (not a vague intent),
// expires, and is invalidated on schema/manifest/parameter/target/destination
// drift. Validation is re-run at execution time to close the TOCTOU window
// between approval and execution (v1.6 review P1-4).
package approval

import (
	"sync"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

// State is the lifecycle state of a binding.
type State string

const (
	StateApproved    State = "approved"
	StateInvalidated State = "invalidated"
	StateExpired     State = "expired"
)

// Binding records an approved, action-bound confirmation.
type Binding struct {
	ApprovalID          string                `json:"approval_id"`
	Fingerprint         string                `json:"action_fingerprint"`
	BindingHash         string                `json:"binding_hash"`
	ToolID              string                `json:"tool_id"`
	ServerID            string                `json:"server_id"`
	ManifestHash        string                `json:"manifest_hash"`
	SchemaHash          string                `json:"schema_hash"`
	ParametersHash      string                `json:"parameters_hash"`
	TargetResourceID    string                `json:"target_resource_id"`
	DestinationBoundary model.Boundary        `json:"destination_boundary"`
	ApproverID          string                `json:"approver_id"`
	TimeWindow          string                `json:"approval_time_window"`
	ApprovedAt          time.Time             `json:"approved_at"`
	ExpiresAt           time.Time             `json:"expires_at"`
	State               State                 `json:"state"`
}

// Result is the outcome of validating an approval against a current action.
type Result struct {
	Valid  bool
	Reason string // "" when valid; otherwise an invalidation reason code (§15.4)
}

// Service binds and validates confirmations.
type Service interface {
	Approve(ac tool.ActionContext, approverID string, ttl time.Duration) Binding
	Get(approvalID string) (Binding, bool)
	Validate(b Binding, ac tool.ActionContext, now time.Time) Result
}

// MemService is an in-memory Approval Binding Service for the MVP / tests.
type MemService struct {
	mu sync.RWMutex
	m  map[string]Binding
}

// NewMemService builds an empty binding service.
func NewMemService() *MemService { return &MemService{m: map[string]Binding{}} }

// Approve binds the concrete action and returns an approved Binding.
func (s *MemService) Approve(ac tool.ActionContext, approverID string, ttl time.Duration) Binding {
	now := time.Now().UTC()
	window := now.Format("2006-01-02T15:04Z") // minute-bucket time window
	fp := tool.ActionFingerprint(ac)
	b := Binding{
		ApprovalID:          idutil.New("appr"),
		Fingerprint:         fp,
		BindingHash:         tool.BindingHash(fp, approverID, window),
		ToolID:              ac.ToolID,
		ServerID:            ac.ServerID,
		ManifestHash:        ac.ManifestHash,
		SchemaHash:          ac.SchemaHash,
		ParametersHash:      ac.ParametersHash,
		TargetResourceID:    ac.TargetResourceID,
		DestinationBoundary: ac.DestinationBoundary,
		ApproverID:          approverID,
		TimeWindow:          window,
		ApprovedAt:          now,
		ExpiresAt:           now.Add(ttl),
		State:               StateApproved,
	}
	s.mu.Lock()
	s.m[b.ApprovalID] = b
	s.mu.Unlock()
	return b
}

// Get returns a stored binding.
func (s *MemService) Get(approvalID string) (Binding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.m[approvalID]
	return b, ok
}

// Validate re-checks an approval against the CURRENT action (TOCTOU re-validate).
// It implements the field-level invalidation rules of Spec v1.5 §15.4.
func (s *MemService) Validate(b Binding, ac tool.ActionContext, now time.Time) Result {
	if b.State == StateInvalidated {
		return Result{Valid: false, Reason: "approval_invalidated"}
	}
	if now.After(b.ExpiresAt) {
		return Result{Valid: false, Reason: "approval_expired"}
	}
	switch {
	case b.SchemaHash != ac.SchemaHash:
		return Result{Valid: false, Reason: "schema_hash_changed"}
	case b.ManifestHash != ac.ManifestHash:
		return Result{Valid: false, Reason: "manifest_hash_changed"}
	case b.ParametersHash != ac.ParametersHash:
		return Result{Valid: false, Reason: "parameters_hash_changed"}
	case b.TargetResourceID != ac.TargetResourceID:
		return Result{Valid: false, Reason: "target_resource_changed"}
	case b.DestinationBoundary != ac.DestinationBoundary:
		return Result{Valid: false, Reason: "destination_boundary_changed"}
	}
	// Defense-in-depth: the fingerprint must also match (covers any field above).
	if tool.ActionFingerprint(ac) != b.Fingerprint {
		return Result{Valid: false, Reason: "action_fingerprint_mismatch"}
	}
	return Result{Valid: true}
}
