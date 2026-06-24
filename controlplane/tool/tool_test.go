package tool

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func baseSnap() MetadataSnapshot {
	return MetadataSnapshot{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s1", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
	}
}

func baseAC() ActionContext {
	return ActionContext{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s1", ManifestHash: "sha256:m1",
		PermissionClass: model.PermExternalSend, ParametersHash: "sha256:p1",
		TargetResourceID: "rcpt-1", DestinationBoundary: model.BoundaryExternal,
	}
}

func TestDetectDriftAndTrust(t *testing.T) {
	ac := baseAC()
	ac.SchemaHash = "sha256:s2" // schema drift
	d := DetectDrift(ac, baseSnap())
	if !d.SchemaDrift || d.ManifestDrift {
		t.Fatalf("want schema drift only, got %+v", d)
	}
	if ts := ResolveTrust(baseSnap(), d); ts != model.TrustDrifted {
		t.Fatalf("approved+drift must become drifted, got %s", ts)
	}
}

func TestResolveTrustRevokedAndPinned(t *testing.T) {
	rev := baseSnap()
	rev.TrustState = model.TrustRevoked
	if ResolveTrust(rev, Drift{}) != model.TrustRevoked {
		t.Fatalf("revoked must stay revoked")
	}
	pin := baseSnap()
	pin.TrustState = model.TrustPinned
	if ResolveTrust(pin, Drift{SchemaDrift: true}) != model.TrustDrifted {
		t.Fatalf("pinned+drift must become drifted")
	}
	if ResolveTrust(pin, Drift{}) != model.TrustPinned {
		t.Fatalf("pinned+no-drift stays pinned")
	}
}

func TestAdaptUnknownTool(t *testing.T) {
	reg := NewMemRegistry()
	ctx := model.Context{Stage: model.StageToolPreExecution, TraceID: "t"}
	tc, sigs, found := Adapt(ctx, baseAC(), reg)
	if found {
		t.Fatalf("expected not found")
	}
	if tc.TrustState != model.TrustUnknown {
		t.Fatalf("unknown tool must have unknown trust, got %s", tc.TrustState)
	}
	if len(sigs) != 1 || sigs[0].SignalType != "registry_miss" {
		t.Fatalf("want registry_miss signal, got %+v", sigs)
	}
}

func TestAdaptEmitsSchemaDriftSignal(t *testing.T) {
	reg := NewMemRegistry()
	reg.Register(baseSnap())
	ac := baseAC()
	ac.SchemaHash = "sha256:CHANGED"
	ctx := model.Context{Stage: model.StageToolPreExecution, TraceID: "t"}
	_, sigs, found := Adapt(ctx, ac, reg)
	if !found {
		t.Fatalf("expected found")
	}
	if len(sigs) != 1 || sigs[0].SignalType != "tool_schema_drift" {
		t.Fatalf("want tool_schema_drift signal, got %+v", sigs)
	}
}

func TestFingerprintStabilityAndSensitivity(t *testing.T) {
	a := baseAC()
	if ActionFingerprint(a) != ActionFingerprint(baseAC()) {
		t.Fatalf("fingerprint must be stable for identical actions")
	}
	b := baseAC()
	b.ParametersHash = "sha256:p2"
	if ActionFingerprint(a) == ActionFingerprint(b) {
		t.Fatalf("fingerprint must change when parameters change")
	}
}
