// Package model defines the language-neutral control-plane contracts as Go
// types: enums, the severity/uncertainty lattices, and the Context / Signal /
// FusedRisk / Decision structures shared by fusion, policy, matrix, and
// enforcement. Determinism guarantees (Spec v1.6 §3, §4) start here, in the
// ordered ranks defined for each enum.
package model

import (
	"encoding/json"
	"fmt"
)

// Stage is one of the four MVP runtime stages (Spec v1.6 §2.1).
type Stage string

const (
	StageInput            Stage = "input"
	StageRetrieval        Stage = "retrieval"
	StageToolPreExecution Stage = "tool_pre_execution"
	StageOutput           Stage = "output"
)

// Severity is a total-ordered lattice; merge via Join (max). Spec v1.6 §3.2.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityName = map[Severity]string{
	SeverityNone: "none", SeverityLow: "low", SeverityMedium: "medium",
	SeverityHigh: "high", SeverityCritical: "critical",
}

func (s Severity) String() string { return severityName[s] }

// Join returns the lattice join (max). Fusion only ever escalates severity.
func (s Severity) Join(o Severity) Severity {
	if o > s {
		return o
	}
	return s
}

// MarshalJSON renders severity as its canonical string (matches the JSON Schema enum).
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON accepts the canonical severity string form.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = ParseSeverity(v)
	return nil
}

// ParseSeverity parses a severity string; "" and unknown map to SeverityNone.
func ParseSeverity(v string) Severity {
	switch v {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityNone
	}
}

// Uncertainty is a total-ordered lattice; merge via Join (max). Spec v1.6 §3.2.
type Uncertainty int

const (
	UncertaintyLow Uncertainty = iota
	UncertaintyMedium
	UncertaintyHigh
)

var uncertaintyName = map[Uncertainty]string{
	UncertaintyLow: "low", UncertaintyMedium: "medium", UncertaintyHigh: "high",
}

func (u Uncertainty) String() string { return uncertaintyName[u] }

// MarshalJSON renders uncertainty as its canonical string.
func (u Uncertainty) MarshalJSON() ([]byte, error) { return json.Marshal(u.String()) }

// UnmarshalJSON accepts the canonical uncertainty string form.
func (u *Uncertainty) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v {
	case "medium":
		*u = UncertaintyMedium
	case "high":
		*u = UncertaintyHigh
	default:
		*u = UncertaintyLow
	}
	return nil
}

// Join returns the lattice join (max).
func (u Uncertainty) Join(o Uncertainty) Uncertainty {
	if o > u {
		return o
	}
	return u
}

// RiskFamily and its fixed canonical order (Spec v1.6 §3.3: SEC<SAF<PRIV<REL<COMP).
type RiskFamily string

const (
	RiskSEC  RiskFamily = "SEC"
	RiskSAF  RiskFamily = "SAF"
	RiskPRIV RiskFamily = "PRIV"
	RiskREL  RiskFamily = "REL"
	RiskCOMP RiskFamily = "COMP"
)

var riskFamilyOrder = map[RiskFamily]int{
	RiskSEC: 0, RiskSAF: 1, RiskPRIV: 2, RiskREL: 3, RiskCOMP: 4,
}

// RiskFamilyOrder returns the canonical sort rank for a risk family.
func RiskFamilyOrder(r RiskFamily) int {
	if v, ok := riskFamilyOrder[r]; ok {
		return v
	}
	return 99
}

// SourceType is the engineering origin of a signal (Spec v1.5 §8.1).
type SourceType string

const (
	SourceRule     SourceType = "rule"
	SourceModel    SourceType = "model"
	SourceJudge    SourceType = "judge"
	SourceTrust    SourceType = "trust"
	SourceSchema   SourceType = "schema"
	SourceRegistry SourceType = "registry"
	SourceHuman    SourceType = "human"
	SourceSystem   SourceType = "system"
)

var sourceTypeOrder = map[SourceType]int{
	SourceRule: 0, SourceSchema: 1, SourceRegistry: 2, SourceTrust: 3,
	SourceModel: 4, SourceJudge: 5, SourceHuman: 6, SourceSystem: 7,
}

// SourceTypeOrder returns the canonical sort rank for a source type.
func SourceTypeOrder(t SourceType) int {
	if v, ok := sourceTypeOrder[t]; ok {
		return v
	}
	return 99
}

// Action is one of the 12 control actions (Spec v1.6 §2).
type Action string

const (
	ActionAllow               Action = "allow"
	ActionAuditOnly           Action = "audit_only"
	ActionAnnotateRisk        Action = "annotate_risk"
	ActionMask                Action = "mask"
	ActionSanitize            Action = "sanitize"
	ActionRedact              Action = "redact"
	ActionRestrictScope       Action = "restrict_scope"
	ActionRequireConfirmation Action = "require_confirmation"
	ActionStepUpAuth          Action = "step_up_auth"
	ActionRequireReview       Action = "require_review"
	ActionBlock               Action = "block"
	ActionDeny                Action = "deny"
)

// actionStrength is the total order for primary-action selection
// (strongest wins). Spec v1.6 §4.1.
var actionStrength = map[Action]int{
	ActionDeny:                120,
	ActionBlock:               110,
	ActionRequireReview:       100,
	ActionStepUpAuth:          90,
	ActionRequireConfirmation: 80,
	ActionRestrictScope:       70,
	ActionRedact:              60,
	ActionSanitize:            50,
	ActionMask:                40,
	ActionAnnotateRisk:        30,
	ActionAuditOnly:           20,
	ActionAllow:               10,
}

// ActionStrength returns the strength rank used to pick the primary action.
func ActionStrength(a Action) int {
	if v, ok := actionStrength[a]; ok {
		return v
	}
	return 0
}

// TrustState is the registry-backed tool trust state (Spec v1.5 §15.5).
type TrustState string

const (
	TrustApproved TrustState = "approved"
	TrustPinned   TrustState = "pinned"
	TrustDrifted  TrustState = "drifted"
	TrustRevoked  TrustState = "revoked"
	TrustUnknown  TrustState = "unknown"
)

// PermissionClass is the tool permission class (Spec v1.5 §6.3).
type PermissionClass string

const (
	PermRead         PermissionClass = "read"
	PermWrite        PermissionClass = "write"
	PermExternalSend PermissionClass = "external_send"
	PermPrivileged   PermissionClass = "privileged"
	PermUnknown      PermissionClass = "unknown"
)

// IsElevated reports write/external_send/privileged classes (FR-007, §1.3).
func (p PermissionClass) IsElevated() bool {
	return p == PermWrite || p == PermExternalSend || p == PermPrivileged
}

// Boundary is the destination boundary (Spec v1.5 §7).
type Boundary string

const (
	BoundarySameUser    Boundary = "same_user"
	BoundarySameTenant  Boundary = "same_tenant"
	BoundaryCrossTenant Boundary = "cross_tenant"
	BoundaryExternal    Boundary = "external"
	BoundaryUnknown     Boundary = "unknown"
)

// IsCrossing reports whether the boundary leaves the tenant (FR-002).
func (b Boundary) IsCrossing() bool {
	return b == BoundaryExternal || b == BoundaryCrossTenant
}

// Environment is the deployment environment (Spec v1.5 §7).
type Environment string

const (
	EnvShadow Environment = "shadow"
	EnvCanary Environment = "canary"
	EnvProd   Environment = "prod"
)

// ProvenanceMode is the INV-7 signal provenance mode (Spec v1.6 §1.1).
type ProvenanceMode string

const (
	ModeA ProvenanceMode = "MODE_A"
	ModeB ProvenanceMode = "MODE_B"
)

// Validate is a tiny helper used by tests and validators.
func (s Stage) Validate() error {
	switch s {
	case StageInput, StageRetrieval, StageToolPreExecution, StageOutput:
		return nil
	default:
		return fmt.Errorf("invalid stage: %q", s)
	}
}
