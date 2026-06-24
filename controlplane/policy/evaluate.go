package policy

import (
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// Policy is a declarative, typed policy (Spec v1.5 §10.2 / v1.6 §4). The Sprint-2
// evaluator (v0) supports scope filtering and a small condition language; it does
// not implement a DSL (v1.5 explicitly advises against one for v1).
type Policy struct {
	PolicyID  string              `json:"policy_id"`
	Version   string              `json:"version"`
	Status    string              `json:"status"`
	Priority  int                 `json:"priority"`
	Scope     Scope               `json:"scope"`
	Condition Condition           `json:"conditions"`
	Decision  PolicyDecision      `json:"decision"`
	RuleIDs   []string            `json:"rule_ids"`
}

// Scope filters which contexts a policy applies to.
type Scope struct {
	Stages       []model.Stage       `json:"stages"`
	AppIDs       []string            `json:"app_ids"`
	TenantIDs    []string            `json:"tenant_ids"`
	Environments []model.Environment `json:"environments"`
}

// Condition is an all/any tree of predicates.
type Condition struct {
	All []Predicate `json:"all"`
	Any []Predicate `json:"any"`
}

// Predicate is a single field test. Supported ops: in, eq, gte, has_flag.
type Predicate struct {
	Field string   `json:"field"`
	Op    string   `json:"op"`
	Value []string `json:"value"`
}

// PolicyDecision is the action a matched policy proposes.
type PolicyDecision struct {
	Action      model.Action `json:"action"`
	ReasonCode  string       `json:"reason_code"`
	Constraints Constraints  `json:"constraints"`
}

// Bundle is a versioned set of policies (Spec v1.5 §10: immutable after release).
type Bundle struct {
	Version  string   `json:"policy_bundle_version"`
	Policies []Policy `json:"policies"`
}

// Match returns the matched policies for a context + fused risk, ready for Resolve.
func (b Bundle) Match(ctx model.Context, fr model.FusedRisk) []MatchedPolicy {
	var out []MatchedPolicy
	for _, p := range b.Policies {
		if !p.Scope.matches(ctx) {
			continue
		}
		if !p.Condition.eval(ctx, fr) {
			continue
		}
		out = append(out, MatchedPolicy{
			PolicyID:       p.PolicyID,
			Priority:       p.Priority,
			Action:         p.Decision.Action,
			ReasonCode:     p.Decision.ReasonCode,
			Constraints:    p.Decision.Constraints,
			MatchedRuleIDs: p.RuleIDs,
		})
	}
	return out
}

func (s Scope) matches(ctx model.Context) bool {
	if len(s.Stages) > 0 && !containsStage(s.Stages, ctx.Stage) {
		return false
	}
	if len(s.Environments) > 0 && !containsEnv(s.Environments, ctx.Application.Environment) {
		return false
	}
	if !wildcardMatch(s.AppIDs, ctx.Application.AppID) {
		return false
	}
	if !wildcardMatch(s.TenantIDs, ctx.Actor.TenantID) {
		return false
	}
	return true
}

func (c Condition) eval(ctx model.Context, fr model.FusedRisk) bool {
	for _, p := range c.All {
		if !p.eval(ctx, fr) {
			return false
		}
	}
	if len(c.Any) > 0 {
		ok := false
		for _, p := range c.Any {
			if p.eval(ctx, fr) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (p Predicate) eval(ctx model.Context, fr model.FusedRisk) bool {
	switch p.Op {
	case "has_flag":
		return len(p.Value) > 0 && fr.HasFlag(p.Value[0])
	case "gte":
		// Only severity comparison is supported in v0.
		if p.Field == "fused_risk.highest_severity" && len(p.Value) > 0 {
			return fr.HighestSeverity >= model.ParseSeverity(p.Value[0])
		}
		return false
	case "eq":
		v, ok := resolveField(ctx, fr, p.Field)
		return ok && len(p.Value) > 0 && v == p.Value[0]
	case "in":
		v, ok := resolveField(ctx, fr, p.Field)
		if !ok {
			return false
		}
		for _, want := range p.Value {
			if v == want {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// resolveField maps a dotted field path to a string value from Context/FusedRisk.
func resolveField(ctx model.Context, fr model.FusedRisk, field string) (string, bool) {
	switch field {
	case "stage":
		return string(ctx.Stage), true
	case "data.sensitivity":
		return ctx.Data.Sensitivity, true
	case "data.data_asset_type":
		return ctx.Data.DataAssetType, true
	case "destination.boundary":
		return string(ctx.Destination.Boundary), true
	case "destination.channel":
		return ctx.Destination.Channel, true
	case "tool.permission_class":
		return string(ctx.Tool.PermissionClass), true
	case "tool.trust_state":
		return string(ctx.Tool.TrustState), true
	case "tool.approval_valid":
		if ctx.Tool.ApprovalValid {
			return "true", true
		}
		return "false", true
	case "actor.privilege_level":
		return ctx.Actor.PrivilegeLevel, true
	case "application.environment":
		return string(ctx.Application.Environment), true
	case "fused_risk.highest_severity":
		return fr.HighestSeverity.String(), true
	default:
		return "", false
	}
}

func containsStage(xs []model.Stage, v model.Stage) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsEnv(xs []model.Environment, v model.Environment) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// wildcardMatch returns true if the list is empty, contains "*", or contains v.
func wildcardMatch(xs []string, v string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if x == "*" || x == v {
			return true
		}
	}
	return false
}
