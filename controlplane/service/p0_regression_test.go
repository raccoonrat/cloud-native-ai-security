package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/gate"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

// P0-1: at the output stage, a prod high-risk no-match must fail closed with a
// `block` (deny is not valid in output). Before the fix this produced an invalid
// `deny`, failing decision validation and erroring the whole evaluation.
func TestP0_OutputFailClosedIsBlockNotError(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-fc", TraceID: "trace-fc", RequestID: "req-fc", Stage: model.StageOutput,
	}
	ctx.Application.Environment = model.EnvProd
	// internal data to a same-tenant boundary: the enterprise disclosure policy
	// (confidential + external) does NOT match, so we hit the fail-closed default.
	ctx.Data.Sensitivity = "internal"
	ctx.Destination.Boundary = model.BoundarySameTenant

	resp, err := svc.Evaluate(EvaluateRequest{
		Context: ctx,
		Mode:    model.EnvProd,
		Signals: []model.Signal{det("s1", "det-prompt-injection", "unsafe_output", model.RiskSEC, model.SeverityHigh, 0.95, model.StageOutput)},
	})
	if err != nil {
		t.Fatalf("output-stage fail-closed must not error, got %v", err)
	}
	if resp.Decision.Decision.Action != model.ActionBlock {
		t.Fatalf("output prod high-risk no-match must block, got %s", resp.Decision.Decision.Action)
	}
	// The decision must validate and be enforceable for the stage.
	assertEnforceable(t, resp.Decision)
}

// P0-2: a tool action submitted through the generic Evaluate is rejected, and
// the HTTP handler rejects stage=tool_pre_execution outright. This closes the
// endpoint-confusion bypass of the tool pre-execution controls (§15).
func TestP0_ToolStageRejectedOnGenericPath(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-t", TraceID: "trace-t", RequestID: "req-t", Stage: model.StageOutput,
	}
	if _, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd, ToolAction: &tool.ActionContext{ToolID: "send_email"}}); err == nil {
		t.Fatalf("Evaluate must reject a tool_action on the generic path")
	}

	body, _ := json.Marshal(EvaluateRequest{
		Context: model.Context{
			SchemaVersion: "1.6", ContextID: "ctx-h", TraceID: "trace-h", RequestID: "req-h",
			Stage: model.StageToolPreExecution,
		},
		Mode: model.EnvProd,
	})
	rr := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/decisions:evaluate", bytes.NewReader(body)))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("HTTP evaluate must reject tool stage with 422, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// P0-3: an expired signal is dropped on the live path (TTL was previously dead
// because the fusion clock was never set), and a replay reproduces the same
// outcome because the evaluation instant is pinned in the snapshot.
func TestP0_ExpiredSignalDroppedAndReplayable(t *testing.T) {
	svc, _ := newTestService()
	ctx := model.Context{
		SchemaVersion: "1.6", ContextID: "ctx-ttl", TraceID: "trace-ttl", RequestID: "req-ttl", Stage: model.StageOutput,
	}
	ctx.Application.Environment = model.EnvProd
	ctx.Data.Sensitivity = "internal"
	ctx.Destination.Boundary = model.BoundarySameTenant

	expired := det("s-old", "det-prompt-injection", "unsafe_output", model.RiskSEC, model.SeverityHigh, 0.95, model.StageOutput)
	expired.CreatedAt = time.Now().Add(-1 * time.Hour)
	expired.TTLMs = 1000 // 1s TTL, created an hour ago -> expired

	resp, err := svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd, Signals: []model.Signal{expired}})
	if err != nil {
		t.Fatal(err)
	}
	// With TTL enforced the only risk signal is dropped -> low risk -> audit_only.
	if resp.Decision.Decision.Action != model.ActionAuditOnly {
		t.Fatalf("expired signal must be dropped (audit_only), got %s", resp.Decision.Decision.Action)
	}
	foundExpired := false
	for _, ds := range resp.Decision.ReplayBinding.DroppedSignals {
		if ds.Reason == "expired" {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Fatalf("expired signal must be recorded as dropped, got %+v", resp.Decision.ReplayBinding.DroppedSignals)
	}
	// Replay must reproduce the same outcome using the pinned evaluation instant.
	rr, err := svc.ReplayDecision(resp.Decision.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Consistency != "match" {
		t.Fatalf("replay with pinned eval time must match, got %s diff=%v", rr.Consistency, rr.Diff)
	}
}

// P0-4: concurrent Evaluate and ActivateBundle must not race on s.bundle. Run
// under `go test -race` to detect the previously lock-free read of s.bundle.
func TestP0_ConcurrentEvaluateAndActivateNoRace(t *testing.T) {
	svc, _ := newTestService()
	rec := gate.GateEvaluationRecord{Decision: gate.DecisionPass}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := model.Context{
				SchemaVersion: "1.6", ContextID: "ctx-c", TraceID: "trace-c", RequestID: idForRace(), Stage: model.StageOutput,
			}
			ctx.Application.Environment = model.EnvProd
			_, _ = svc.Evaluate(EvaluateRequest{Context: ctx, Mode: model.EnvProd})
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.ActivateBundle(policy.DefaultBundle(), rec, model.EnvProd)
		}()
	}
	wg.Wait()
}

// idForRace returns a unique request id so concurrent calls don't collapse onto
// the same idempotency key.
var raceMu sync.Mutex
var raceCounter int

func idForRace() string {
	raceMu.Lock()
	defer raceMu.Unlock()
	raceCounter++
	return "req-c-" + time.Now().Format("150405.000000000") + "-" + itoa(raceCounter)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
