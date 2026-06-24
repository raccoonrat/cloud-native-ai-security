// Package gate implements the Release Gate (INV-6, Spec v1.5 §16.5, §18). A
// detector / policy / threshold / tool-metadata / approval-workflow change is
// release-gated: each evaluation produces a GateEvaluationRecord that binds the
// candidate to its offline-eval, replay-regression, policy-diff, and latency
// artifacts and yields a deterministic release decision.
package gate

import (
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/replay"
)

// Decision is the gate outcome (Spec v1.5 §18.2).
type Decision string

const (
	DecisionPass             Decision = "pass"
	DecisionPassWithWarning  Decision = "pass_with_warning"
	DecisionBlock            Decision = "block"
	DecisionShadowOnly       Decision = "shadow_only"
	DecisionCanaryOnly       Decision = "canary_only"
	DecisionRollbackRequired Decision = "rollback_required"
)

// Target identifies the release-gated change (Spec v1.5 §18.1).
type Target struct {
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
}

// ArtifactRefs binds the gate to its evidence/evaluation artifacts (§16.5).
type ArtifactRefs struct {
	OfflineEvalReportRef      string `json:"offline_eval_report_ref"`
	ReplayRegressionReportRef string `json:"replay_regression_report_ref"`
	PolicyDiffReportRef       string `json:"policy_diff_report_ref"`
	EvidenceSamplingReportRef string `json:"evidence_sampling_report_ref"`
	LatencyReportRef          string `json:"latency_report_ref"`
}

// Metrics are the gate decision inputs (Spec v1.5 §17.2, §18.2).
type Metrics struct {
	ActionCorrectness    float64 `json:"action_correctness"`
	ReasonCorrectness    float64 `json:"reason_correctness"`
	EvidenceCompleteness float64 `json:"evidence_completeness"`
	ReplayConsistency    float64 `json:"replay_consistency"`
	FalsePositiveRate    float64 `json:"false_positive_rate"`
	FalseNegativeRate    float64 `json:"false_negative_rate"`
	P95LatencyMs         int64   `json:"p95_decision_latency_ms"`
	BehaviorDrift        float64 `json:"policy_behavior_drift"`
}

// BlastRadius summarizes what the change can affect (§18.2).
type BlastRadius struct {
	AffectedStages  []model.Stage  `json:"affected_stages"`
	AffectedActions []model.Action `json:"affected_actions"`
	AffectedApps    []string       `json:"affected_apps"`
}

// GateEvaluationRecord is the gate output (Spec v1.5 §18.2). INV-6: every
// release-gated change MUST produce one.
type GateEvaluationRecord struct {
	GateEvaluationID  string            `json:"gate_evaluation_id"`
	GateID            string            `json:"gate_id"`
	Target            Target            `json:"target"`
	Metrics           Metrics           `json:"metrics"`
	PolicyDiffRisk    string            `json:"policy_diff_risk"`
	BlastRadius       BlastRadius       `json:"blast_radius"`
	Decision          Decision          `json:"decision"`
	RequiredFollowups []string          `json:"required_followups"`
	Artifacts         ArtifactRefs      `json:"artifacts"`
	Diff              policy.DiffReport `json:"policy_diff"`
	Timestamp         time.Time         `json:"timestamp"`
}

// Thresholds are the release acceptance criteria (Spec §24 non-functional reqs).
type Thresholds struct {
	MinActionCorrectness    float64
	MinEvidenceCompleteness float64
	MinReplayConsistency    float64
	MaxFalsePositiveRate    float64
	MaxP95LatencyMs         int64
	CanaryDrift             float64 // behavior drift at/above this -> canary_only
	RollbackDrift           float64 // behavior drift at/above this -> rollback_required
}

// DefaultThresholds returns conservative MVP gate criteria.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MinActionCorrectness:    0.95,
		MinEvidenceCompleteness: 0.90,
		MinReplayConsistency:    0.99,
		MaxFalsePositiveRate:    0.10,
		MaxP95LatencyMs:         300,
		CanaryDrift:             0.20,
		RollbackDrift:           0.50,
	}
}

// Sample is one corpus item: a pinned decision input plus its expected control.
type Sample struct {
	Inputs               replay.Inputs
	ExpectedAction       model.Action
	ExpectedReason       string
	ShouldIntervene      bool
	RiskFamily           model.RiskFamily
	EvidenceCompleteness float64 // optional per-sample completeness for the dry-run
}

// Request bundles everything the gate needs (Spec §16.5 + the candidate bundle
// and the dry-run/regression corpus the runtime supplies).
type Request struct {
	GateID          string
	Target          Target
	CurrentBundle   policy.Bundle
	CandidateBundle policy.Bundle
	Corpus          []Sample
	FusionConfig    fusion.Config
	Thresholds      Thresholds
	Artifacts       ArtifactRefs

	// Observed measurements taken outside the deterministic core. When > 0 they
	// override the corpus-derived values (latency cannot be derived from a dry run).
	ObservedEvidenceCompleteness float64
	ObservedP95LatencyMs         int64
}

// Evaluate runs the policy diff, the candidate dry-run, and the replay
// regression over the corpus, then renders a deterministic GateEvaluationRecord.
func Evaluate(req Request) GateEvaluationRecord {
	if (req.Thresholds == Thresholds{}) {
		req.Thresholds = DefaultThresholds()
	}
	diff := policy.Diff(req.CurrentBundle, req.CandidateBundle)

	var (
		total                                  = len(req.Corpus)
		actionCorrect, reasonCorrect, reasonN  int
		changed                                int // candidate differs from current bundle
		fp, fn, posTotal, negTotal             int
		completenessSum                        float64
	)
	for _, s := range req.Corpus {
		candAction, candReason := evalBundle(s.Inputs, req.CandidateBundle, req.FusionConfig)
		curAction, _ := evalBundle(s.Inputs, req.CurrentBundle, req.FusionConfig)

		if s.ExpectedAction != "" && candAction == s.ExpectedAction {
			actionCorrect++
		}
		if s.ExpectedReason != "" {
			reasonN++
			if candReason == s.ExpectedReason {
				reasonCorrect++
			}
		}
		if candAction != curAction {
			changed++
		}
		intervened := isActiveControl(candAction)
		if s.ShouldIntervene {
			posTotal++
			if !intervened {
				fn++
			}
		} else {
			negTotal++
			if intervened {
				fp++
			}
		}
		completenessSum += s.EvidenceCompleteness
	}

	m := Metrics{}
	if total > 0 {
		m.ActionCorrectness = ratio(actionCorrect, total)
		m.BehaviorDrift = ratio(changed, total)
		m.ReplayConsistency = 1 - m.BehaviorDrift
		m.EvidenceCompleteness = completenessSum / float64(total)
	} else {
		// No regression corpus: no evidence of behavioral change, stay neutral and
		// let policy_diff_risk drive the decision.
		m.ActionCorrectness = 1
		m.ReplayConsistency = 1
		m.EvidenceCompleteness = 1
	}
	if reasonN > 0 {
		m.ReasonCorrectness = ratio(reasonCorrect, reasonN)
	}
	if negTotal > 0 {
		m.FalsePositiveRate = ratio(fp, negTotal)
	}
	if posTotal > 0 {
		m.FalseNegativeRate = ratio(fn, posTotal)
	}
	if req.ObservedEvidenceCompleteness > 0 {
		m.EvidenceCompleteness = req.ObservedEvidenceCompleteness
	}
	m.P95LatencyMs = req.ObservedP95LatencyMs

	dec, followups := Decide(m, diff.RiskLevel, req.Thresholds)

	return GateEvaluationRecord{
		GateEvaluationID:  idutil.New("gate-eval"),
		GateID:            req.GateID,
		Target:            req.Target,
		Metrics:           m,
		PolicyDiffRisk:    diff.RiskLevel,
		BlastRadius:       BlastRadius{AffectedStages: diff.AffectedStages, AffectedActions: diff.AffectedActions, AffectedApps: diff.AffectedApps},
		Decision:          dec,
		RequiredFollowups: followups,
		Artifacts:         req.Artifacts,
		Diff:              diff,
		Timestamp:         time.Now().UTC(),
	}
}

// Decide maps metrics + diff risk to a deterministic release decision (§18.2).
// Severity order: block > rollback_required > shadow_only > canary_only >
// pass_with_warning > pass.
func Decide(m Metrics, diffRisk string, t Thresholds) (Decision, []string) {
	var fail []string
	if m.ActionCorrectness < t.MinActionCorrectness {
		fail = append(fail, "action_correctness below floor")
	}
	if m.EvidenceCompleteness < t.MinEvidenceCompleteness {
		fail = append(fail, "evidence_completeness below floor")
	}
	if m.FalsePositiveRate > t.MaxFalsePositiveRate {
		fail = append(fail, "false_positive_rate above ceiling")
	}
	if t.MaxP95LatencyMs > 0 && m.P95LatencyMs > t.MaxP95LatencyMs {
		fail = append(fail, "p95_decision_latency_ms above ceiling")
	}
	if len(fail) > 0 {
		// Failing AND massively disruptive -> rollback_required (stronger than a
		// contained block: if already deployed it must be rolled back).
		if m.BehaviorDrift >= t.RollbackDrift {
			return DecisionRollbackRequired, append(fail, "severe behavior drift; roll back if deployed")
		}
		return DecisionBlock, fail
	}

	if diffRisk == "critical" {
		return DecisionShadowOnly, []string{"critical policy diff risk; observe in shadow before any traffic"}
	}
	if diffRisk == "high" || m.BehaviorDrift >= t.CanaryDrift {
		return DecisionCanaryOnly, []string{"elevated behavior change; limit to canary and monitor false_positive_rate"}
	}
	if diffRisk == "medium" || m.BehaviorDrift > 0 ||
		m.FalsePositiveRate > t.MaxFalsePositiveRate/2 ||
		(t.MaxP95LatencyMs > 0 && float64(m.P95LatencyMs) > 0.8*float64(t.MaxP95LatencyMs)) {
		return DecisionPassWithWarning, []string{"monitor metrics post-release"}
	}
	return DecisionPass, nil
}

func evalBundle(in replay.Inputs, b policy.Bundle, cfg fusion.Config) (model.Action, string) {
	r := replay.Run(in, b, cfg)
	return r.ReplayedAction, r.ReplayedReason
}

func isActiveControl(a model.Action) bool {
	switch a {
	case model.ActionAllow, model.ActionAuditOnly, model.ActionAnnotateRisk:
		return false
	default:
		return true
	}
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
