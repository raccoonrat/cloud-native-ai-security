package approval

import (
	"testing"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

func ac() tool.ActionContext {
	return tool.ActionContext{
		ToolID: "send_email", ServerID: "srv", SchemaHash: "sha256:s1", ManifestHash: "sha256:m1",
		ParametersHash: "sha256:p1", TargetResourceID: "rcpt-1", DestinationBoundary: model.BoundaryExternal,
	}
}

func TestApproveThenValidate(t *testing.T) {
	s := NewMemService()
	b := s.Approve(ac(), "alice", time.Hour)
	if b.State != StateApproved || b.BindingHash == "" {
		t.Fatalf("approve must produce an approved binding with a binding hash")
	}
	res := s.Validate(b, ac(), time.Now().UTC())
	if !res.Valid {
		t.Fatalf("unchanged action must validate, got %q", res.Reason)
	}
}

func TestSchemaDriftInvalidatesApproval(t *testing.T) {
	s := NewMemService()
	b := s.Approve(ac(), "alice", time.Hour)
	drifted := ac()
	drifted.SchemaHash = "sha256:CHANGED"
	res := s.Validate(b, drifted, time.Now().UTC())
	if res.Valid || res.Reason != "schema_hash_changed" {
		t.Fatalf("schema drift must invalidate, got valid=%v reason=%q", res.Valid, res.Reason)
	}
}

func TestParameterAndTargetDriftInvalidate(t *testing.T) {
	s := NewMemService()
	b := s.Approve(ac(), "alice", time.Hour)

	p := ac()
	p.ParametersHash = "sha256:p2"
	if r := s.Validate(b, p, time.Now().UTC()); r.Valid || r.Reason != "parameters_hash_changed" {
		t.Fatalf("param drift must invalidate, got %+v", r)
	}
	tgt := ac()
	tgt.TargetResourceID = "rcpt-2"
	if r := s.Validate(b, tgt, time.Now().UTC()); r.Valid || r.Reason != "target_resource_changed" {
		t.Fatalf("target drift must invalidate, got %+v", r)
	}
}

func TestApprovalExpiry(t *testing.T) {
	s := NewMemService()
	b := s.Approve(ac(), "alice", time.Minute)
	future := time.Now().UTC().Add(2 * time.Minute)
	if r := s.Validate(b, ac(), future); r.Valid || r.Reason != "approval_expired" {
		t.Fatalf("expired approval must invalidate, got %+v", r)
	}
}
