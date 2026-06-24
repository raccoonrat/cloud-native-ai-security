// Package evidence implements minimal synchronous evidence commit (Spec v1.6 §13.3).
// Evidence is part of correctness, not logging (INV-4). The Sprint-2 store is
// in-memory; production swaps in a platform-owned, encrypted, tenant-isolated store.
package evidence

import (
	"sync"
	"time"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/idutil"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
)

// Minimal is the minimal synchronous evidence record (Spec v1.6 §13.3).
type Minimal struct {
	EvidenceID   string       `json:"evidence_id"`
	TraceID      string       `json:"trace_id"`
	DecisionID   string       `json:"decision_id"`
	ContextRef   string       `json:"context_ref"`
	SignalRefs   []string     `json:"signal_refs"`
	PolicyRef    string       `json:"policy_ref"`
	Action       model.Action `json:"action"`
	ReasonCode   string       `json:"reason_code"`
	Stage        model.Stage  `json:"stage"`
	Timestamp    time.Time    `json:"timestamp"`
	Committed    bool         `json:"committed"`
}

// Store persists evidence. CommitMinimal must be synchronous for high-risk paths.
type Store interface {
	CommitMinimal(m Minimal) (string, error)
	Get(evidenceID string) (Minimal, bool)
}

// MemStore is an in-memory Store for the MVP / tests.
type MemStore struct {
	mu sync.RWMutex
	m  map[string]Minimal
}

// NewMemStore builds an empty in-memory evidence store.
func NewMemStore() *MemStore { return &MemStore{m: map[string]Minimal{}} }

// CommitMinimal stores the minimal evidence and returns its evidence_id.
func (s *MemStore) CommitMinimal(m Minimal) (string, error) {
	if m.EvidenceID == "" {
		m.EvidenceID = idutil.New("ev")
	}
	m.Committed = true
	if m.Timestamp.IsZero() {
		m.Timestamp = time.Now().UTC()
	}
	s.mu.Lock()
	s.m[m.EvidenceID] = m
	s.mu.Unlock()
	return m.EvidenceID, nil
}

// Get returns a stored evidence record.
func (s *MemStore) Get(id string) (Minimal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[id]
	return v, ok
}
