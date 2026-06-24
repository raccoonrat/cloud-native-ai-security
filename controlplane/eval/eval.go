// Package eval is the Evaluation Harness (Spec v1.5 §17, v1.6 §17). It assesses
// CONTROL effectiveness, not detector accuracy: did the system take the right
// action, cite the right reason, produce sufficient evidence, and replay
// consistently. It produces per-stage and per-risk-family metric cards.
package eval

import (
	"fmt"
	"sort"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/replay"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/service"
)

// Case is one labeled evaluation scenario.
type Case struct {
	Name            string
	Req             service.EvaluateRequest
	ExpectedAction  model.Action
	ExpectedReason  string // optional; "" skips reason scoring
	ShouldIntervene bool   // ground truth: an active control is expected
	RiskFamily      model.RiskFamily
	// Enrichment models async evidence captured outside the sync decision (§13.4).
	Enrichment evidence.Enrichment
}

// Card is the per-case evaluation record (Spec v1.6 §17 "evaluation card").
type Card struct {
	Name                 string
	Stage                model.Stage
	RiskFamily           model.RiskFamily
	ExpectedAction       model.Action
	ActualAction         model.Action
	ActionCorrect        bool
	ReasonCorrect        bool
	EvidenceCompleteness float64
	ReplayConsistency    string
	LatencyMs            int64
	Err                  string
}

// Bucket aggregates metrics for a stage or risk family.
type Bucket struct {
	Total                   int
	ActionCorrect           int
	EvidenceCompletenessSum float64
}

// ActionCorrectness returns the action-correctness rate for the bucket.
func (b Bucket) ActionCorrectness() float64 {
	if b.Total == 0 {
		return 0
	}
	return float64(b.ActionCorrect) / float64(b.Total)
}

// EvidenceCompletenessAvg returns the average evidence completeness for the bucket.
func (b Bucket) EvidenceCompletenessAvg() float64 {
	if b.Total == 0 {
		return 0
	}
	return b.EvidenceCompletenessSum / float64(b.Total)
}

// Report is the aggregated evaluation result.
type Report struct {
	Total                   int
	ActionCorrect           int
	ReasonCorrect           int
	ReasonScored            int
	EvidenceCompletenessAvg float64
	ReplayConsistencyRate   float64
	FalsePositiveRate       float64
	FalseNegativeRate       float64
	P95LatencyMs            int64
	PerStage                map[model.Stage]*Bucket
	PerRiskFamily           map[model.RiskFamily]*Bucket
	Cards                   []Card
}

// ActionCorrectness returns the overall action-correctness rate.
func (r Report) ActionCorrectness() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.ActionCorrect) / float64(r.Total)
}

// Decider is the subset of the service used by the harness.
type Decider interface {
	Evaluate(req service.EvaluateRequest) (service.EvaluateResponse, error)
	EvaluateToolAction(req service.EvaluateRequest) (service.EvaluateResponse, error)
	ReplayDecision(decisionID string) (replay.Result, error)
}

// Run executes all cases and returns the aggregated report with metric cards.
func Run(d Decider, cases []Case) Report {
	rep := Report{
		PerStage:      map[model.Stage]*Bucket{},
		PerRiskFamily: map[model.RiskFamily]*Bucket{},
	}
	var (
		latencies        []int64
		completenessSum  float64
		replayMatch      int
		fp, fn           int
		interveneActual  int
	)

	for _, c := range cases {
		stage := c.Req.Context.Stage
		card := Card{Name: c.Name, Stage: stage, RiskFamily: c.RiskFamily, ExpectedAction: c.ExpectedAction}

		var resp service.EvaluateResponse
		var err error
		if c.Req.ToolAction != nil {
			resp, err = d.EvaluateToolAction(c.Req)
		} else {
			resp, err = d.Evaluate(c.Req)
		}
		if err != nil {
			card.Err = err.Error()
			rep.Cards = append(rep.Cards, card)
			rep.Total++
			bucket(rep.PerStage, stage).Total++
			bucket(rep.PerRiskFamily, c.RiskFamily).Total++
			continue
		}

		dec := resp.Decision
		card.ActualAction = dec.Decision.Action
		card.ActionCorrect = dec.Decision.Action == c.ExpectedAction
		card.LatencyMs = resp.LatencyMs

		// Evidence completeness with async enrichment (§13.4/§13.5).
		comp := evidence.BuildFromContract(dec, c.Enrichment).Completeness()
		card.EvidenceCompleteness = comp

		// Replay consistency (§14).
		if rr, rerr := d.ReplayDecision(dec.DecisionID); rerr == nil {
			card.ReplayConsistency = rr.Consistency
			if rr.Consistency == "match" {
				replayMatch++
			}
		} else {
			card.ReplayConsistency = "unavailable"
		}

		if c.ExpectedReason != "" {
			rep.ReasonScored++
			card.ReasonCorrect = dec.Decision.ReasonCode == c.ExpectedReason
			if card.ReasonCorrect {
				rep.ReasonCorrect++
			}
		}

		// False positive / negative on intervention.
		intervened := isActiveControl(dec.Decision.Action)
		if intervened {
			interveneActual++
		}
		if intervened && !c.ShouldIntervene {
			fp++
		}
		if !intervened && c.ShouldIntervene {
			fn++
		}

		rep.Total++
		if card.ActionCorrect {
			rep.ActionCorrect++
		}
		completenessSum += comp
		latencies = append(latencies, resp.LatencyMs)

		bs := bucket(rep.PerStage, stage)
		bs.Total++
		bs.EvidenceCompletenessSum += comp
		if card.ActionCorrect {
			bs.ActionCorrect++
		}
		bf := bucket(rep.PerRiskFamily, c.RiskFamily)
		bf.Total++
		bf.EvidenceCompletenessSum += comp
		if card.ActionCorrect {
			bf.ActionCorrect++
		}

		rep.Cards = append(rep.Cards, card)
	}

	if rep.Total > 0 {
		rep.EvidenceCompletenessAvg = completenessSum / float64(rep.Total)
		rep.ReplayConsistencyRate = float64(replayMatch) / float64(rep.Total)
	}
	// FP rate over non-intervene-expected; FN rate over intervene-expected.
	negTotal, posTotal := 0, 0
	for _, c := range cases {
		if c.ShouldIntervene {
			posTotal++
		} else {
			negTotal++
		}
	}
	if negTotal > 0 {
		rep.FalsePositiveRate = float64(fp) / float64(negTotal)
	}
	if posTotal > 0 {
		rep.FalseNegativeRate = float64(fn) / float64(posTotal)
	}
	rep.P95LatencyMs = p95(latencies)
	return rep
}

// Render produces a compact human-readable evaluation card summary.
func (r Report) Render() string {
	s := fmt.Sprintf("Evaluation Report\n=================\ncases=%d action_correctness=%.2f reason_correctness=%.2f\nevidence_completeness_avg=%.2f replay_consistency=%.2f fpr=%.2f fnr=%.2f p95_latency_ms=%d\n",
		r.Total, r.ActionCorrectness(), reasonRate(r), r.EvidenceCompletenessAvg, r.ReplayConsistencyRate, r.FalsePositiveRate, r.FalseNegativeRate, r.P95LatencyMs)
	s += "\nPer stage:\n"
	for _, st := range sortedStages(r.PerStage) {
		b := r.PerStage[st]
		s += fmt.Sprintf("  %-20s action_correctness=%.2f evidence=%.2f (n=%d)\n", st, b.ActionCorrectness(), b.EvidenceCompletenessAvg(), b.Total)
	}
	s += "\nPer risk family:\n"
	for _, fam := range sortedFamilies(r.PerRiskFamily) {
		b := r.PerRiskFamily[fam]
		s += fmt.Sprintf("  %-6s action_correctness=%.2f evidence=%.2f (n=%d)\n", fam, b.ActionCorrectness(), b.EvidenceCompletenessAvg(), b.Total)
	}
	return s
}

func reasonRate(r Report) float64 {
	if r.ReasonScored == 0 {
		return 0
	}
	return float64(r.ReasonCorrect) / float64(r.ReasonScored)
}

func isActiveControl(a model.Action) bool {
	switch a {
	case model.ActionAllow, model.ActionAuditOnly, model.ActionAnnotateRisk:
		return false
	default:
		return true
	}
}

func bucket[K comparable](m map[K]*Bucket, k K) *Bucket {
	b, ok := m[k]
	if !ok {
		b = &Bucket{}
		m[k] = b
	}
	return b
}

func p95(xs []int64) int64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]int64(nil), xs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (len(cp)*95 + 99) / 100 // ceil(0.95*n)
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func sortedStages(m map[model.Stage]*Bucket) []model.Stage {
	out := make([]model.Stage, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedFamilies(m map[model.RiskFamily]*Bucket) []model.RiskFamily {
	out := make([]model.RiskFamily, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return model.RiskFamilyOrder(out[i]) < model.RiskFamilyOrder(out[j]) })
	return out
}
