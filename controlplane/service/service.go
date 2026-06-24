// Package service wires the Sprint-2 runtime decision MVP: provenance check
// (INV-7) -> deterministic fusion -> policy match/resolve -> Decision Contract
// (signed) -> minimal evidence commit, behind a first-write-wins idempotent
// POST /v1/decisions:evaluate (Spec v1.6 §5.3, §6).
package service

import (
	"fmt"
	"sync"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/approval"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/decision"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/fusion"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/replay"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

// EvaluateRequest is the POST /v1/decisions:evaluate body (Spec v1.5 §16.1).
type EvaluateRequest struct {
	Context model.Context       `json:"context"`
	Signals []model.Signal      `json:"signals"`
	Mode    model.Environment   `json:"mode"`
	Options Options             `json:"options"`
	// ToolAction is set for stage=tool_pre_execution (Spec v1.5 §15.1).
	ToolAction *tool.ActionContext `json:"tool_action,omitempty"`
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
	toolReg   tool.Registry
	approvals approval.Service
	evidence  evidence.Store
	signer    sign.Signer
	fusionCfg fusion.Config
	cfg       Config

	mu        sync.Mutex
	store     map[string]decision.Contract // idempotency: trace|request|stage -> decision
	snapshots map[string]replay.Inputs     // decision_id -> replay snapshot (§14)
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
		snapshots: map[string]replay.Inputs{},
	}
}

// WithTooling wires the Tool Registry and Approval Binding Service (Sprint 3).
func (s *Service) WithTooling(reg tool.Registry, appr approval.Service) *Service {
	s.toolReg = reg
	s.approvals = appr
	return s
}

// extras carries optional tool-confirmation binding inputs into decide.
type extras struct {
	approvalID   string
	bindingHash  string
	bindingField []string
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

	// INV-7 provenance verification (§1.2/§1.3).
	kept, synthetic, dropped := s.verifyProvenance(ctx, req.Signals)
	fuseInput := append(kept, synthetic...)
	return s.decide(ctx, mode, req.Options, fuseInput, dropped, extras{}, start)
}

// EvaluateToolAction is the tool_pre_execution path (Spec v1.5 §15, Sprint 3).
// It normalizes the ToolActionContext, runs drift detection and trust
// resolution, re-validates any prior approval (TOCTOU), and then runs the same
// deterministic decision core.
func (s *Service) EvaluateToolAction(req EvaluateRequest) (EvaluateResponse, error) {
	start := time.Now()
	ctx := req.Context
	if req.ToolAction == nil {
		return EvaluateResponse{}, fmt.Errorf("service: tool_action is required")
	}
	if ctx.Stage != model.StageToolPreExecution {
		return EvaluateResponse{}, fmt.Errorf("service: tool_action requires stage=tool_pre_execution")
	}
	if s.toolReg == nil || s.approvals == nil {
		return EvaluateResponse{}, fmt.Errorf("service: tooling not configured (call WithTooling)")
	}
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
	ac := *req.ToolAction

	// Normalize the tool action -> enriched tool context + tool signals (§15).
	toolCtx, toolSignals, _ := tool.Adapt(ctx, ac, s.toolReg)
	if ctx.Data.Sensitivity == "" {
		ctx.Data.Sensitivity = ac.DataSensitivity
	}
	if ctx.Data.DataAssetType == "" {
		ctx.Data.DataAssetType = ac.DataAssetType
	}
	if ctx.Destination.Boundary == "" {
		ctx.Destination.Boundary = ac.DestinationBoundary
	}

	// Re-validate any prior approval against the CURRENT action (§15.4, TOCTOU).
	approvalValid, approvalSignals := s.resolveApproval(ctx, ac, &toolCtx)
	toolCtx.ApprovalValid = approvalValid
	ctx.Tool = toolCtx

	// External detector signals still pass provenance; tool/approval signals are
	// control-plane-internal and bypass the registry check.
	kept, synthetic, dropped := s.verifyProvenance(ctx, req.Signals)
	fuseInput := append(kept, synthetic...)
	fuseInput = append(fuseInput, toolSignals...)
	fuseInput = append(fuseInput, approvalSignals...)

	ex := extras{
		approvalID:   ac.ApprovalID,
		bindingHash:  tool.ActionFingerprint(ac),
		bindingField: tool.BindingFieldNames,
	}
	return s.decide(ctx, mode, req.Options, fuseInput, dropped, ex, start)
}

// ApproveToolAction simulates a human confirmation binding a concrete action
// (Spec v1.5 §15.3). It returns the approval id to be replayed by the agent.
func (s *Service) ApproveToolAction(ac tool.ActionContext, approverID string, ttl time.Duration) (approval.Binding, error) {
	if s.approvals == nil {
		return approval.Binding{}, fmt.Errorf("service: tooling not configured")
	}
	return s.approvals.Approve(ac, approverID, ttl), nil
}

// resolveApproval re-validates a prior approval. On drift it surfaces the
// corresponding tool drift signal and marks HasPriorApproval so FR-003 flags
// approval_invalidated during fusion.
func (s *Service) resolveApproval(ctx model.Context, ac tool.ActionContext, toolCtx *model.ToolCtx) (bool, []model.Signal) {
	if ac.ApprovalID == "" {
		return false, nil
	}
	b, ok := s.approvals.Get(ac.ApprovalID)
	if !ok {
		return false, nil
	}
	res := s.approvals.Validate(b, ac, time.Now().UTC())
	if res.Valid {
		return true, nil
	}
	toolCtx.HasPriorApproval = true
	var sigs []model.Signal
	switch res.Reason {
	case "schema_hash_changed":
		sigs = append(sigs, s.systemSignalTyped(ctx, "tool_schema_drift", model.SourceSchema, model.SeverityHigh))
	case "manifest_hash_changed":
		sigs = append(sigs, s.systemSignalTyped(ctx, "tool_manifest_drift", model.SourceSchema, model.SeverityHigh))
	case "parameters_hash_changed", "target_resource_changed", "destination_boundary_changed":
		sigs = append(sigs, s.systemSignalTyped(ctx, "approval_stale", model.SourceSystem, model.SeverityHigh))
	}
	return false, sigs
}

// decide is the shared deterministic core: fusion -> policy -> signed decision
// -> minimal evidence commit, behind first-write-wins idempotency (§5.3).
func (s *Service) decide(ctx model.Context, mode model.Environment, opts Options, fuseInput []model.Signal, dropped []model.DroppedSignal, ex extras, start time.Time) (EvaluateResponse, error) {
	key := ctx.TraceID + "|" + ctx.RequestID + "|" + string(ctx.Stage)
	if existing, ok := s.get(key); ok {
		return EvaluateResponse{
			Decision: existing, EvidenceCommitStatus: "committed",
			IdempotentReplay: true, LatencyMs: time.Since(start).Milliseconds(),
		}, nil
	}

	fr := fusion.Fuse(fuseInput, ctx, s.fusionCfg)
	fr.DroppedSignals = append(dropped, fr.DroppedSignals...)

	matched := s.bundle.Match(ctx, fr)
	res := policy.Resolve(matched, mode, fr)

	c := decision.Build(decision.Inputs{
		Context:             ctx,
		Signals:             fuseInput,
		FusedRisk:           fr,
		Resolution:          res,
		BundleVersion:       s.bundle.Version,
		ThresholdVer:        s.cfg.ThresholdConfigVersion,
		MatrixVersion:       s.matrix.MatrixVersion,
		ProvenanceMode:      s.cfg.ProvenanceMode,
		Mode:                mode,
		ApprovalID:          ex.approvalID,
		ApprovalBindingHash: ex.bindingHash,
		ApprovalFields:      ex.bindingField,
	}, s.signer)

	if err := decision.Validate(c, s.matrix); err != nil {
		return EvaluateResponse{}, fmt.Errorf("service: invalid decision: %w", err)
	}

	// Minimal synchronous evidence completeness (§13.3/§13.5).
	c.Evidence.EvidenceCompleteness = evidence.BuildFromContract(c, evidence.Enrichment{}).Completeness()

	commitStatus := "pending"
	if opts.RequireEvidenceCommit || c.Evidence.EvidenceRequired {
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

	winner, stored := s.storeIfAbsent(key, c)
	if stored {
		// Capture the replay snapshot (§14.1) for decision-level replay.
		s.putSnapshot(winner.DecisionID, replay.Inputs{
			OriginalDecisionID: winner.DecisionID,
			Context:            ctx,
			Signals:            fuseInput,
			Mode:               mode,
			OriginalAction:     winner.Decision.Action,
			OriginalReason:     winner.Decision.ReasonCode,
		})
	}
	return EvaluateResponse{
		Decision: winner, EvidenceCommitStatus: commitStatus,
		IdempotentReplay: !stored, LatencyMs: time.Since(start).Milliseconds(),
	}, nil
}

// ReplayDecision re-runs a stored decision's snapshot through the deterministic
// core and returns the consistency verdict (Spec v1.5 §14).
func (s *Service) ReplayDecision(decisionID string) (replay.Result, error) {
	snap, ok := s.getSnapshot(decisionID)
	if !ok {
		return replay.Result{}, fmt.Errorf("service: no replay snapshot for decision %q", decisionID)
	}
	return replay.Run(snap, s.bundle, s.fusionCfg), nil
}

func (s *Service) putSnapshot(id string, in replay.Inputs) {
	s.mu.Lock()
	s.snapshots[id] = in
	s.mu.Unlock()
}

func (s *Service) getSnapshot(id string) (replay.Inputs, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.snapshots[id]
	return in, ok
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
	return s.systemSignalTyped(ctx, typ, model.SourceSystem, sev)
}

func (s *Service) systemSignalTyped(ctx model.Context, typ string, src model.SourceType, sev model.Severity) model.Signal {
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
		Source:        model.SignalSource{SourceID: "control-plane", SourceType: src, SourceVersion: "1.6"},
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
