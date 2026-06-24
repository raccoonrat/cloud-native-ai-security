package service

import "github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"

// DetectorEntry is a registered signal source (INV-7, Spec v1.6 §1.2).
type DetectorEntry struct {
	SourceID string
	Versions map[string]bool
	// Verifier is used in MODE-B to verify the signal signature.
	Verifier sign.Verifier
}

// DetectorRegistry resolves a signal source for provenance verification.
type DetectorRegistry interface {
	Lookup(sourceID string) (DetectorEntry, bool)
}

// MemRegistry is an in-memory DetectorRegistry for the MVP / tests.
type MemRegistry struct {
	entries map[string]DetectorEntry
}

// NewMemRegistry builds an empty registry.
func NewMemRegistry() *MemRegistry { return &MemRegistry{entries: map[string]DetectorEntry{}} }

// Register adds or replaces a detector entry.
func (r *MemRegistry) Register(e DetectorEntry) { r.entries[e.SourceID] = e }

// Lookup returns the entry for a source id.
func (r *MemRegistry) Lookup(sourceID string) (DetectorEntry, bool) {
	e, ok := r.entries[sourceID]
	return e, ok
}
