package matrix

import (
	"testing"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

func TestLoadMatrix(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.MatrixVersion != "stage_action_matrix_v1" {
		t.Fatalf("unexpected matrix_version %q", m.MatrixVersion)
	}
}

func TestStageActionRules(t *testing.T) {
	m := MustLoad()
	cases := []struct {
		stage  model.Stage
		action model.Action
		want   bool
	}{
		{model.StageInput, model.ActionSanitize, true},
		{model.StageInput, model.ActionRedact, false},          // disallowed: no spans to redact yet
		{model.StageInput, model.ActionRequireConfirmation, false}, // premature
		{model.StageInput, model.ActionBlock, false},           // block reserved for output
		{model.StageRetrieval, model.ActionRestrictScope, true},
		{model.StageRetrieval, model.ActionDeny, true},
		{model.StageToolPreExecution, model.ActionRequireConfirmation, true},
		{model.StageToolPreExecution, model.ActionStepUpAuth, true},
		{model.StageOutput, model.ActionRedact, true},
		{model.StageOutput, model.ActionBlock, true},
		{model.StageOutput, model.ActionDeny, false}, // cannot deny an already-produced artifact
		{model.StageOutput, model.ActionRestrictScope, false},
	}
	for _, c := range cases {
		if got := m.Allowed(c.stage, c.action); got != c.want {
			t.Errorf("Allowed(%s,%s)=%v want %v", c.stage, c.action, got, c.want)
		}
	}
}

func TestValidateError(t *testing.T) {
	m := MustLoad()
	if err := m.Validate(model.StageInput, model.ActionRedact); err == nil {
		t.Fatalf("expected error for redact@input")
	}
	if err := m.Validate(model.StageOutput, model.ActionRedact); err != nil {
		t.Fatalf("unexpected error for redact@output: %v", err)
	}
}

func TestRequiresApprovalBinding(t *testing.T) {
	m := MustLoad()
	req := m.Requires(model.ActionRequireConfirmation)
	if len(req) != 1 || req[0] != "approval_binding" {
		t.Fatalf("require_confirmation must require approval_binding, got %v", req)
	}
}
