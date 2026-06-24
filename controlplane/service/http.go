package service

import (
	"encoding/json"
	"net/http"
)

// Handler returns an http.Handler exposing the runtime decision API.
//
// NOTE: Spec v1.6 §5.1 mandates mTLS + workload identity + per-tenant rate
// limiting + anti-replay in front of this handler. Those belong to the serving
// edge (gateway / interceptor) and are intentionally out of scope for the
// Sprint-2 skeleton handler.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decisions:evaluate", s.handleEvaluate)
	mux.HandleFunc("/v1/replay:decision", s.handleReplay)
	mux.HandleFunc("/v1/release-gates:evaluate", s.handleReleaseGate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (s *Service) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	res, err := s.ReplayDecision(req.DecisionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "replay_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Service) handleReleaseGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req ReleaseGateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	rec := s.EvaluateReleaseGate(req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rec)
}

func (s *Service) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	resp, err := s.Evaluate(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "evaluation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "message": msg})
}
