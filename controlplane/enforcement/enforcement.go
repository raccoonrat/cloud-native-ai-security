// Package enforcement is the Enforcement Adapter (Spec v1.5 §12). It executes
// ONLY the action in the Decision Contract (INV-3) and never inspects detector
// or policy internals. It first verifies the decision signature (INV-3 extended,
// Spec v1.6 §5.4) and the stage/action against the matrix.
package enforcement

import (
	"fmt"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

// Result is the enforcement outcome (Spec v1.5 §12.2).
type Result struct {
	EnforcementID  string       `json:"enforcement_id"`
	DecisionID     string       `json:"decision_id"`
	Status         string       `json:"status"` // success | partial | failed | skipped
	ActionExecuted model.Action `json:"action_executed"`
	OutputRef      string       `json:"output_ref,omitempty"`
	ErrorCode      string       `json:"error_code,omitempty"`
	ErrorMessage   string       `json:"error_message,omitempty"`
	Timestamp      time.Time    `json:"timestamp"`
}

// MockAdapter is a deterministic Enforcement Adapter for the MVP / tests.
type MockAdapter struct {
	matrix   *matrix.Matrix
	verifier sign.Verifier
	// requireSignature mirrors §5.4: signature MUST be verified in canary/prod.
	requireSignature bool
}

// NewMockAdapter builds a mock adapter. If verifier is non-nil and
// requireSignature is true, the decision signature is verified before acting.
func NewMockAdapter(m *matrix.Matrix, v sign.Verifier, requireSignature bool) *MockAdapter {
	return &MockAdapter{matrix: m, verifier: v, requireSignature: requireSignature}
}

// Execute runs the decision action. It returns failed/skipped Results rather than
// errors for control-flow outcomes; it returns an error only for contract violations.
func (a *MockAdapter) Execute(c decision.Contract) (Result, error) {
	r := Result{
		EnforcementID: idutil.New("enf"),
		DecisionID:    c.DecisionID,
		Timestamp:     time.Now().UTC(),
	}

	// INV-3 extended: verify signature before acting (§5.4).
	if a.requireSignature {
		if a.verifier == nil || !decision.VerifySignature(c, a.verifier) {
			r.Status = "failed"
			r.ErrorCode = "signature_invalid"
			r.ErrorMessage = "decision signature verification failed"
			return r, fmt.Errorf("enforcement: %s", r.ErrorMessage)
		}
	}

	// Enforcement validates the action against the SAME matrix (single source).
	if err := a.matrix.Validate(c.Stage, c.Decision.Action); err != nil {
		r.Status = "failed"
		r.ErrorCode = "invalid_action_for_stage"
		r.ErrorMessage = err.Error()
		return r, err
	}

	r.ActionExecuted = c.Decision.Action
	switch c.Decision.Action {
	case model.ActionAllow, model.ActionAuditOnly, model.ActionAnnotateRisk:
		r.Status = "success" // no mutation; record-only / pass-through.
	case model.ActionRedact, model.ActionMask, model.ActionSanitize:
		r.Status = "success"
		r.OutputRef = idutil.New("content-transformed")
	case model.ActionRestrictScope:
		r.Status = "success"
		r.OutputRef = idutil.New("content-scoped")
	case model.ActionRequireConfirmation, model.ActionStepUpAuth, model.ActionRequireReview:
		// Gates do not complete here; the data plane must wait for the human/auth loop.
		r.Status = "skipped"
	case model.ActionDeny, model.ActionBlock:
		r.Status = "success" // the stop itself is the successful enforcement.
	default:
		r.Status = "failed"
		r.ErrorCode = "unknown_action"
	}
	return r, nil
}
