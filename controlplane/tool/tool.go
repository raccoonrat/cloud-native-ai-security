// Package tool implements the Tool / MCP pre-execution security layer
// (Spec v1.5 §15, v1.6 §15). Tool calls are an independent execution boundary
// (INV-5): every tool call is normalized into an ActionContext, compared against
// a registry-backed immutable MetadataSnapshot for drift, assigned a trust
// state, and bound by an action fingerprint used for confirmation binding.
package tool

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// ActionContext is the normalized tool/MCP call (Spec v1.5 §15.1).
type ActionContext struct {
	ToolActionID        string                `json:"tool_action_id"`
	ToolID              string                `json:"tool_id"`
	ServerID            string                `json:"server_id"`
	ToolVersion         string                `json:"tool_version"`
	ManifestHash        string                `json:"manifest_hash"`
	SchemaHash          string                `json:"schema_hash"`
	DescriptionHash     string                `json:"description_hash"`
	PermissionClass     model.PermissionClass `json:"permission_class"`
	Operation           string                `json:"operation"`
	ParametersHash      string                `json:"parameters_hash"`
	TargetResourceID    string                `json:"target_resource_id"`
	DestinationBoundary model.Boundary        `json:"destination_boundary"`
	DataSensitivity     string                `json:"data_sensitivity"`
	DataAssetType       string                `json:"data_asset_type"`
	// ApprovalID, when present, references a prior confirmation binding.
	ApprovalID string `json:"approval_id,omitempty"`
}

// MetadataSnapshot is the registry-backed immutable baseline (Spec v1.5 §15.2).
type MetadataSnapshot struct {
	ToolID          string                `json:"tool_id"`
	ServerID        string                `json:"server_id"`
	ToolVersion     string                `json:"tool_version"`
	ManifestHash    string                `json:"manifest_hash"`
	SchemaHash      string                `json:"schema_hash"`
	DescriptionHash string                `json:"description_hash"`
	PermissionClass model.PermissionClass `json:"permission_class"`
	TrustState      model.TrustState      `json:"trust_state"`
	Owner           string                `json:"owner"`
	LastReviewedAt  time.Time             `json:"last_reviewed_at"`
}

// Registry resolves tool metadata snapshots (Spec v1.6 §26 Q#13: platform MCP
// registry is authoritative; the control plane snapshots it).
type Registry interface {
	Lookup(toolID, serverID string) (MetadataSnapshot, bool)
}

// MemRegistry is an in-memory Registry for the MVP / tests.
type MemRegistry struct {
	snaps map[string]MetadataSnapshot
}

// NewMemRegistry builds an empty tool registry.
func NewMemRegistry() *MemRegistry { return &MemRegistry{snaps: map[string]MetadataSnapshot{}} }

// Register adds or replaces a tool metadata snapshot.
func (r *MemRegistry) Register(s MetadataSnapshot) { r.snaps[key(s.ToolID, s.ServerID)] = s }

// Lookup returns the snapshot for a (tool_id, server_id).
func (r *MemRegistry) Lookup(toolID, serverID string) (MetadataSnapshot, bool) {
	s, ok := r.snaps[key(toolID, serverID)]
	return s, ok
}

func key(toolID, serverID string) string { return toolID + "@" + serverID }

// Drift records which immutable baselines diverged (Spec v1.5 §15.4).
type Drift struct {
	SchemaDrift      bool
	ManifestDrift    bool
	DescriptionDrift bool
}

// Any reports whether any drift was detected.
func (d Drift) Any() bool { return d.SchemaDrift || d.ManifestDrift || d.DescriptionDrift }

// DetectDrift compares the current action against the registered snapshot. A
// drift is only flagged when the baseline hash is present and differs.
func DetectDrift(ac ActionContext, snap MetadataSnapshot) Drift {
	return Drift{
		SchemaDrift:      snap.SchemaHash != "" && ac.SchemaHash != snap.SchemaHash,
		ManifestDrift:    snap.ManifestHash != "" && ac.ManifestHash != snap.ManifestHash,
		DescriptionDrift: snap.DescriptionHash != "" && ac.DescriptionHash != snap.DescriptionHash,
	}
}

// ResolveTrust applies the Tool Trust State rules (Spec v1.5 §15.5).
func ResolveTrust(snap MetadataSnapshot, drift Drift) model.TrustState {
	switch snap.TrustState {
	case model.TrustRevoked:
		return model.TrustRevoked
	case model.TrustPinned:
		if drift.Any() {
			return model.TrustDrifted // pinned requires exact hash match
		}
		return model.TrustPinned
	case model.TrustApproved:
		if drift.Any() {
			return model.TrustDrifted
		}
		return model.TrustApproved
	case model.TrustUnknown, "":
		return model.TrustUnknown
	default:
		return snap.TrustState
	}
}

// Adapt normalizes a tool action into enriched tool context plus the tool
// signals (drift / registry miss) that feed deterministic fusion. The bool
// reports whether the tool was found in the registry.
func Adapt(ctx model.Context, ac ActionContext, reg Registry) (model.ToolCtx, []model.Signal, bool) {
	tc := model.ToolCtx{
		ToolID: ac.ToolID, ServerID: ac.ServerID, ToolVersion: ac.ToolVersion,
		SchemaHash: ac.SchemaHash, ManifestHash: ac.ManifestHash,
		PermissionClass: ac.PermissionClass,
	}

	snap, ok := reg.Lookup(ac.ToolID, ac.ServerID)
	if !ok {
		tc.TrustState = model.TrustUnknown
		return tc, []model.Signal{toolSignal(ctx, "registry_miss", model.SourceRegistry, model.SeverityMedium)}, false
	}

	drift := DetectDrift(ac, snap)
	tc.TrustState = ResolveTrust(snap, drift)
	if snap.PermissionClass != "" {
		tc.PermissionClass = snap.PermissionClass // registry is authoritative
	}

	var sigs []model.Signal
	if drift.SchemaDrift {
		sigs = append(sigs, toolSignal(ctx, "tool_schema_drift", model.SourceSchema, model.SeverityHigh))
	}
	if drift.ManifestDrift {
		sigs = append(sigs, toolSignal(ctx, "tool_manifest_drift", model.SourceSchema, model.SeverityHigh))
	}
	if snap.TrustState == model.TrustRevoked {
		sigs = append(sigs, toolSignal(ctx, "unauthorized_action", model.SourceRegistry, model.SeverityCritical))
	}
	return tc, sigs, true
}

func toolSignal(ctx model.Context, typ string, src model.SourceType, sev model.Severity) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6", SignalID: idutil.New("sig-tool"), TraceID: ctx.TraceID,
		ContextID: ctx.ContextID, Stage: ctx.Stage, SignalType: typ,
		RiskFamily: model.RiskSEC, Severity: sev, Confidence: 1.0,
		Source: model.SignalSource{SourceID: "tool-security", SourceType: src, SourceVersion: "1.6"},
	}
}

// BindingFieldNames lists the fields bound by a confirmation (Spec v1.5 §15.3).
var BindingFieldNames = []string{
	"tool_id", "server_id", "manifest_hash", "schema_hash",
	"parameters_hash", "target_resource_id", "destination_boundary",
}

// ActionFingerprint hashes the immutable action identity. Two actions with the
// same fingerprint are the same controllable operation; a changed fingerprint
// after approval invalidates the approval (Spec v1.5 §15.4, v1.6 P1-4).
func ActionFingerprint(ac ActionContext) string {
	parts := []string{
		ac.ToolID, ac.ServerID, ac.ManifestHash, ac.SchemaHash,
		ac.ParametersHash, ac.TargetResourceID, string(ac.DestinationBoundary),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BindingHash is the full confirmation binding hash (Spec v1.5 §15.3):
// hash(fingerprint, approver_id, approval_time_window).
func BindingHash(fingerprint, approverID, timeWindow string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{fingerprint, approverID, timeWindow}, "\x1f")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
