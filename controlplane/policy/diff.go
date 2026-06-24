package policy

import (
	"reflect"
	"sort"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// DiffReport is the policy diff + blast radius backing the Release Gate
// (Spec v1.5 §16.5 policy_diff_report, §18 blast_radius / policy_diff_risk).
type DiffReport struct {
	FromVersion     string         `json:"from_version"`
	ToVersion       string         `json:"to_version"`
	Added           []string       `json:"added"`
	Removed         []string       `json:"removed"`
	Modified        []PolicyChange `json:"modified"`
	AffectedStages  []model.Stage  `json:"affected_stages"`
	AffectedActions []model.Action `json:"affected_actions"`
	AffectedApps    []string       `json:"affected_apps"`
	RiskLevel       string         `json:"policy_diff_risk"` // low | medium | high | critical
}

// PolicyChange records a single modified policy.
type PolicyChange struct {
	PolicyID          string       `json:"policy_id"`
	FromAction        model.Action `json:"from_action"`
	ToAction          model.Action `json:"to_action"`
	FromVersion       string       `json:"from_version"`
	ToVersion         string       `json:"to_version"`
	ActionChanged     bool         `json:"action_changed"`
	ConstraintChanged bool         `json:"constraint_changed"`
	Weakened          bool         `json:"weakened"`
}

// controlFloor: actions at/above redact strength are active enterprise controls;
// removing or weakening one is the highest-risk class of change.
var controlFloor = model.ActionStrength(model.ActionRedact)

func isControl(a model.Action) bool { return model.ActionStrength(a) >= controlFloor }

// Diff computes the change set between a current and candidate bundle and
// classifies the release risk. It is deterministic (sorted output).
func Diff(current, candidate Bundle) DiffReport {
	cur := indexByID(current.Policies)
	cand := indexByID(candidate.Policies)

	rep := DiffReport{FromVersion: current.Version, ToVersion: candidate.Version}
	stages := map[model.Stage]bool{}
	actions := map[model.Action]bool{}
	apps := map[string]bool{}

	markAffected := func(p Policy) {
		for _, s := range expandStages(p.Scope.Stages) {
			stages[s] = true
		}
		actions[p.Decision.Action] = true
		for _, a := range expandApps(p.Scope.AppIDs) {
			apps[a] = true
		}
	}

	critical, high, medium := false, false, false

	for id, p := range cur {
		if _, ok := cand[id]; !ok {
			rep.Removed = append(rep.Removed, id)
			markAffected(p)
			if isControl(p.Decision.Action) {
				critical = true // removing an active control can open a hole
			} else {
				high = true
			}
		}
	}
	for id, p := range cand {
		if _, ok := cur[id]; !ok {
			rep.Added = append(rep.Added, id)
			markAffected(p)
			medium = true
		}
	}
	for id, a := range cur {
		b, ok := cand[id]
		if !ok {
			continue
		}
		ch := PolicyChange{
			PolicyID: id, FromAction: a.Decision.Action, ToAction: b.Decision.Action,
			FromVersion: a.Version, ToVersion: b.Version,
		}
		ch.ActionChanged = a.Decision.Action != b.Decision.Action
		ch.ConstraintChanged = !reflect.DeepEqual(a.Decision.Constraints, b.Decision.Constraints)
		ch.Weakened = model.ActionStrength(b.Decision.Action) < model.ActionStrength(a.Decision.Action)
		if !ch.ActionChanged && !ch.ConstraintChanged &&
			reflect.DeepEqual(a.Scope, b.Scope) && reflect.DeepEqual(a.Condition, b.Condition) {
			continue // metadata-only (e.g. version/status) — no behavioral delta
		}
		rep.Modified = append(rep.Modified, ch)
		markAffected(a)
		markAffected(b)
		switch {
		case ch.Weakened && isControl(a.Decision.Action):
			critical = true // weakening an active control
		case ch.ActionChanged:
			high = true
		default:
			medium = true // constraint / scope / condition change only
		}
	}

	rep.AffectedStages = sortedStages(stages)
	rep.AffectedActions = sortedActions(actions)
	rep.AffectedApps = sortedStrings(apps)
	sort.Strings(rep.Added)
	sort.Strings(rep.Removed)
	sort.Slice(rep.Modified, func(i, j int) bool { return rep.Modified[i].PolicyID < rep.Modified[j].PolicyID })

	switch {
	case critical:
		rep.RiskLevel = "critical"
	case high:
		rep.RiskLevel = "high"
	case medium:
		rep.RiskLevel = "medium"
	default:
		rep.RiskLevel = "low"
	}
	return rep
}

func indexByID(ps []Policy) map[string]Policy {
	m := make(map[string]Policy, len(ps))
	for _, p := range ps {
		m[p.PolicyID] = p
	}
	return m
}

func expandStages(ss []model.Stage) []model.Stage {
	if len(ss) == 0 {
		return []model.Stage{model.StageInput, model.StageRetrieval, model.StageToolPreExecution, model.StageOutput}
	}
	return ss
}

func expandApps(as []string) []string {
	if len(as) == 0 {
		return []string{"*"}
	}
	return as
}

func sortedStages(m map[model.Stage]bool) []model.Stage {
	out := make([]model.Stage, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedActions(m map[model.Action]bool) []model.Action {
	out := make([]model.Action, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return model.ActionStrength(out[i]) > model.ActionStrength(out[j]) })
	return out
}

func sortedStrings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
