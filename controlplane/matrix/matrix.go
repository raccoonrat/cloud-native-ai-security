// Package matrix loads the Stage x Action Matrix (Spec v1.6 §2) from the
// embedded YAML artifact and exposes the single validator used by policy lint
// (PL-002), decision output validation, and enforcement input validation.
package matrix

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/contracts"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

type rawMatrix struct {
	SchemaVersion string      `json:"schema_version"`
	MatrixVersion string      `json:"matrix_version"`
	Stages        []string    `json:"stages"`
	Actions       []rawAction `json:"actions"`
}

type rawAction struct {
	Action    string   `json:"action"`
	AllowedIn []string `json:"allowed_in"`
	Requires  []string `json:"requires"`
	Evidence  string   `json:"evidence"`
}

// Entry is the resolved rule for one action.
type Entry struct {
	Action    model.Action
	AllowedIn map[model.Stage]bool
	Requires  []string
	Evidence  string
}

// Matrix is the loaded, queryable Stage x Action Matrix.
type Matrix struct {
	SchemaVersion string
	MatrixVersion string
	stages        map[model.Stage]bool
	entries       map[model.Action]Entry
}

// Load parses the embedded matrix YAML. It is the canonical constructor.
func Load() (*Matrix, error) {
	var rm rawMatrix
	if err := json.Unmarshal(contracts.StageActionMatrixJSON, &rm); err != nil {
		return nil, fmt.Errorf("matrix: unmarshal: %w", err)
	}
	if rm.MatrixVersion == "" {
		return nil, fmt.Errorf("matrix: missing matrix_version")
	}
	m := &Matrix{
		SchemaVersion: rm.SchemaVersion,
		MatrixVersion: rm.MatrixVersion,
		stages:        map[model.Stage]bool{},
		entries:       map[model.Action]Entry{},
	}
	for _, s := range rm.Stages {
		m.stages[model.Stage(s)] = true
	}
	for _, a := range rm.Actions {
		allowed := map[model.Stage]bool{}
		for _, s := range a.AllowedIn {
			st := model.Stage(s)
			if !m.stages[st] {
				return nil, fmt.Errorf("matrix: action %q allowed_in unknown stage %q", a.Action, s)
			}
			allowed[st] = true
		}
		m.entries[model.Action(a.Action)] = Entry{
			Action:    model.Action(a.Action),
			AllowedIn: allowed,
			Requires:  a.Requires,
			Evidence:  a.Evidence,
		}
	}
	return m, nil
}

// MustLoad panics on error; convenient for package-level init in services.
func MustLoad() *Matrix {
	m, err := Load()
	if err != nil {
		panic(err)
	}
	return m
}

// Allowed reports whether an action is permitted in a stage. This is the SAME
// function backing lint, decision validation, and enforcement validation.
func (m *Matrix) Allowed(stage model.Stage, action model.Action) bool {
	e, ok := m.entries[action]
	if !ok {
		return false
	}
	return e.AllowedIn[stage]
}

// Validate returns a descriptive error when an action is invalid for a stage.
func (m *Matrix) Validate(stage model.Stage, action model.Action) error {
	if _, ok := m.entries[action]; !ok {
		return fmt.Errorf("matrix: unknown action %q", action)
	}
	if !m.stages[stage] {
		return fmt.Errorf("matrix: unknown stage %q", stage)
	}
	if !m.Allowed(stage, action) {
		return fmt.Errorf("matrix: action %q is not allowed in stage %q", action, stage)
	}
	return nil
}

// Requires returns the required constraint keys for an action.
func (m *Matrix) Requires(action model.Action) []string {
	return m.entries[action].Requires
}

// AllowedActions returns the deterministically sorted list of actions valid in a stage.
func (m *Matrix) AllowedActions(stage model.Stage) []model.Action {
	var out []model.Action
	for a, e := range m.entries {
		if e.AllowedIn[stage] {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
