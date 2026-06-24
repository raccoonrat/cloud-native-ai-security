// Package service wires the Sprint-2 runtime decision MVP: provenance check
// (INV-7) -> deterministic fusion -> policy match/resolve -> Decision Contract
// (signed) -> minimal evidence commit, behind a first-write-wins idempotent
// POST /v1/decisions:evaluate (Spec v1.6 §5.3, §6).
package service

import (
	"fmt"
	"sync"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

// EvaluateRequest is the POST /v1/decisions:evaluate body (Spec v1.5 §16.1).
type EvaluateRequest struct {
	Context model.Context  `json:"context"`
	Signals []model.Signal `json:"signals"`
	Mode    model.Environment `json:"mode"`
	Options Options        `json:"options"`
}

// Options controls evaluation behavior.
type Options struct {
	RequireEvidenceCommit bool `json:"require_evidence_commit"`
	TimeoutMs             int  `json:"timeout_ms"`
}

// EvaluateResponse is the decision response (Spec v1.5 §16.1).
type EvaluateResponse struct {
	Decision             decision.Contract `json:"decision"`
	EvidenceCommitStatus string            `json:"evidence_commit_status"`
	IdempotentReplay     bool              `json:"idempotent_replay"`
	LatencyMs            int64             `json:"latency_ms"`
}

// Config configures a Service.
type Config struct {
	ThresholdConfigVersion string
	ProvenanceMode         model.ProvenanceMode
}

// Service is the runtime decision MVP.
type Service struct {
	matrix    *matrix.Matrix
	bundle    policy.Bundle
	registry  DetectorRegistry
	evidence  evidence.Store
	signer    sign.Signer
	fusionCfg fusion.Config
	cfg       Config

	mu    sync.Mutex
	store map[string]decision.Contract // idempotency: trace|request|stage -> decision
}

// New builds a Service with sensible MVP defaults for any nil dependency.
func New(m *matrix.Matrix, bundle policy.Bundle, reg DetectorRegistry, ev evidence.Store, signer sign.Signer, cfg Config) *Service {
	if cfg.ProvenanceMode == "" {
		cfg.ProvenanceMode = model.ModeA
	}
	if cfg.ThresholdConfigVersion == "" {
		cfg.ThresholdConfigVersion = "threshold_v1"
	}
	return &Service{
		matrix:    m,
		bundle:    bundle,
		registry:  reg,
		evidence:  ev,
		signer:    signer,
		fusionCfg: fusion.DefaultConfig(),
		cfg:       cfg,
		store:     map[string]decision.Contract{},
	}
}

// Evaluate runs the full decision chain for one request.
func (s *Service) Evaluate(req EvaluateRequest) (EvaluateResponse, error) {
	start := time.Now()
	ctx := req.Context

	if err := ctx.Stage.Validate(); err != nil {
		return EvaluateResponse{}, err
	}
	if ctx.TraceID == "" || ctx.RequestID == "" {
		return EvaluateResponse{}, fmt.Errorf("service: trace_id and request_id are required")
	}
	mode := req.Mode
	if mode == "" {
		mode = ctx.Application.Environment
	}
	if mode == "" {
		mode = model.EnvShadow
	}

	// §5.3 idempotency: first-write-wins. Replay returns the stored decision.
	key := ctx.TraceID + "|" + ctx.RequestID + "|" + string(ctx.Stage)
	if existing, ok := s.get(key); ok {
		return EvaluateResponse{
			Decision: existing, EvidenceCommitStatus: "committed",
			IdempotentReplay: true, LatencyMs: time.Since(start).Milliseconds(),
		}, nil
	}

	// INV-7 provenance verification (§1.2/§1.3).
	kept, synthetic, dropped := s.verifyProvenance(ctx, req.Signals)
	fuseInput := append(kept, synthetic...)

	// Deterministic fusion (§3).
	fr := fusion.Fuse(fuseInput, ctx, s.fusionCfg)
	fr.DroppedSignals = append(dropped, fr.DroppedSignals...)

	// Policy match + deterministic resolution (§4).
	matched := s.bundle.Match(ctx, fr)
	res := policy.Resolve(matched, mode, fr)

	// Build + sign the Decision Contract (§5.4).
	c := decision.Build(decision.Inputs{
		Context:        ctx,
		Signals:        kept,
		FusedRisk:      fr,
		Resolution:     res,
		BundleVersion:  s.bundle.Version,
		ThresholdVer:   s.cfg.ThresholdConfigVersion,
		MatrixVersion:  s.matrix.MatrixVersion,
		ProvenanceMode: s.cfg.ProvenanceMode,
		Mode:           mode,
	}, s.signer)

	if err := decision.Validate(c, s.matrix); err != nil {
		return EvaluateResponse{}, fmt.Errorf("service: invalid decision: %w", err)
	}

	// Minimal synchronous evidence commit (§13.3, INV-4).
	commitStatus := "pending"
	if req.Options.RequireEvidenceCommit || c.Evidence.EvidenceRequired {
		evID, err := s.evidence.CommitMinimal(evidence.Minimal{
			TraceID: c.TraceID, DecisionID: c.DecisionID, ContextRef: c.ContextID,
			SignalRefs: c.ReplayBinding.SignalSnapshotRefs, PolicyRef: c.ReplayBinding.PolicyBundleVersion,
			Action: c.Decision.Action, ReasonCode: c.Decision.ReasonCode, Stage: c.Stage,
		})
		if err != nil {
			commitStatus = "failed"
		} else {
			commitStatus = "committed"
			c.Evidence.EvidenceRefs = []string{evID}
			c.Evidence.MinimalEvidenceCommitted = true
		}
	}

	// Persist for idempotency (first-write-wins under lock).
	winner, stored := s.storeIfAbsent(key, c)
	return EvaluateResponse{
		Decision: winner, EvidenceCommitStatus: commitStatus,
		IdempotentReplay: !stored, LatencyMs: time.Since(start).Milliseconds(),
	}, nil
}

// verifyProvenance enforces INV-7: only registered (and in MODE-B, signed)
// signals reach fusion. Unregistered sources are dropped and surfaced as a
// system registry_miss signal so "absence" is auditable (§1.3).
func (s *Service) verifyProvenance(ctx model.Context, sigs []model.Signal) (kept, synthetic []model.Signal, dropped []model.DroppedSignal) {
	for _, sig := range sigs {
		entry, ok := s.registry.Lookup(sig.Source.SourceID)
		if !ok {
			dropped = append(dropped, model.DroppedSignal{SourceID: sig.Source.SourceID, SignalID: sig.SignalID, Reason: "registry_miss"})
			synthetic = append(synthetic, s.systemSignal(ctx, "registry_miss", model.SeverityMedium))
			continue
		}
		if len(entry.Versions) > 0 && sig.Source.SourceVersion != "" && !entry.Versions[sig.Source.SourceVersion] {
			dropped = append(dropped, model.DroppedSignal{SourceID: sig.Source.SourceID, SignalID: sig.SignalID, Reason: "registry_miss"})
			synthetic = append(synthetic, s.systemSignal(ctx, "registry_miss", model.SeverityMedium))
			continue
		}
		if s.cfg.ProvenanceMode == model.ModeB {
			if entry.Verifier == nil || !entry.Verifier.Verify(sig.Integrity.SignedPayloadHash, sig.Integrity.Signature) {
				dropped = append(dropped, model.DroppedSignal{SourceID: sig.Source.SourceID, SignalID: sig.SignalID, Reason: "signature_invalid"})
				synthetic = append(synthetic, s.systemSignal(ctx, "signal_integrity_violation", model.SeverityHigh))
				continue
			}
		}
		kept = append(kept, sig)
	}
	return kept, synthetic, dropped
}

func (s *Service) systemSignal(ctx model.Context, typ string, sev model.Severity) model.Signal {
	return model.Signal{
		SchemaVersion: "1.6",
		SignalID:      idutil.New("sig-sys"),
		TraceID:       ctx.TraceID,
		ContextID:     ctx.ContextID,
		Stage:         ctx.Stage,
		SignalType:    typ,
		RiskFamily:    model.RiskSEC,
		Severity:      sev,
		Confidence:    1.0,
		Source:        model.SignalSource{SourceID: "control-plane", SourceType: model.SourceSystem, SourceVersion: "1.6"},
	}
}

func (s *Service) get(key string) (decision.Contract, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.store[key]
	return c, ok
}

func (s *Service) storeIfAbsent(key string, c decision.Contract) (decision.Contract, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.store[key]; ok {
		return existing, false
	}
	s.store[key] = c
	return c, true
}
