package decision

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

// buildRedact builds a signed, valid output-stage redact decision for tampering.
func buildRedact(t *testing.T) (Contract, *matrix.Matrix, sign.Verifier) {
	t.Helper()
	m := matrix.MustLoad()
	signer := sign.NewHMAC([]byte("cp-key"), "cp")

	ctx := model.Context{SchemaVersion: "1.6", ContextID: "ctx-1", TraceID: "trace-1", Stage: model.StageOutput}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "confidential"
	ctx.Destination.Boundary = model.BoundaryExternal

	res := policy.Resolution{
		Action:      model.ActionRedact,
		ReasonCodes: []string{"enterprise_external_disclosure"},
		Constraints: policy.Constraints{
			RedactionProfile: "pii_full", RedactionRank: 3,
			EvidenceRequired: true, AuditRequired: true,
			ScopeRestriction: []string{"a", "b"},
		},
	}
	c := Build(Inputs{
		Context:       ctx,
		FusedRisk:     model.FusedRisk{FusionConfigVersion: "deterministic_v1", HighestSeverity: model.SeverityHigh},
		Resolution:    res,
		BundleVersion: "bundle-v1",
		ThresholdVer:  "threshold_v1",
		MatrixVersion: m.MatrixVersion,
		Mode:          model.EnvProd,
	}, signer)

	if err := Validate(c, m); err != nil {
		t.Fatalf("freshly built decision must validate: %v", err)
	}
	if !VerifyIntegrity(c) {
		t.Fatalf("freshly built decision must pass VerifyIntegrity")
	}
	if !VerifySignature(c, signer) {
		t.Fatalf("freshly built decision must pass VerifySignature")
	}
	return c, m, signer
}

// TestHashCoversConstraintTamper proves a redaction downgrade with the original
// (hash, signature) left intact is now detected. Previously the constraints were
// outside the hash, so this mutation verified successfully.
func TestHashCoversConstraintTamper(t *testing.T) {
	c, m, v := buildRedact(t)
	c.Constraints.RedactionProfile = "none" // downgrade pii_full -> none
	if VerifyIntegrity(c) {
		t.Fatalf("a redaction-profile downgrade must break VerifyIntegrity")
	}
	if VerifySignature(c, v) {
		t.Fatalf("a redaction-profile downgrade must break VerifySignature")
	}
	if err := Validate(c, m); err == nil {
		t.Fatalf("Validate must reject a hash that does not cover the contract")
	}
}

// TestHashCoversModeTamper proves a shadow<->prod environment swap is detected,
// so a shadow (audit_only) decision cannot be replayed as a prod decision.
func TestHashCoversModeTamper(t *testing.T) {
	c, _, v := buildRedact(t)
	c.Decision.DecisionMode = string(model.EnvShadow)
	if VerifyIntegrity(c) || VerifySignature(c, v) {
		t.Fatalf("a decision_mode swap must break integrity/signature")
	}
}

// TestHashCoversScopeAndRevisionTamper proves scope restriction and async
// revision lineage are bound by the hash.
func TestHashCoversScopeAndRevisionTamper(t *testing.T) {
	c, _, v := buildRedact(t)
	c.Constraints.ScopeRestriction = nil // widen scope
	if VerifyIntegrity(c) || VerifySignature(c, v) {
		t.Fatalf("widening scope_restriction must break integrity/signature")
	}

	c2, _, v2 := buildRedact(t)
	c2.Decision.SupersedesID = "dec-old" // forge supersedes lineage
	c2.Decision.DecisionRevision = 5
	if VerifyIntegrity(c2) || VerifySignature(c2, v2) {
		t.Fatalf("forging revision lineage must break integrity/signature")
	}
}

// TestHashIsDeterministic guarantees the recomputed hash is a pure function of
// the contract, so an untampered contract always re-verifies (replay safety).
func TestHashIsDeterministic(t *testing.T) {
	c, _, _ := buildRedact(t)
	if hashCore(c) != hashCore(c) {
		t.Fatalf("hashCore must be deterministic")
	}
	if hashCore(c) != c.Integrity.DecisionHash {
		t.Fatalf("recomputed hash must equal the embedded hash for an untampered contract")
	}
}
