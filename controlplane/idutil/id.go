// Package idutil generates prefixed random identifiers (decision_id, evidence_id,
// etc.) using crypto/rand. Stdlib only.
package idutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// New returns a prefixed 128-bit random id, e.g. New("dec") -> "dec-<32 hex>".
func New(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// Derive returns a deterministic prefixed id from the given parts. It is used
// for control-plane-synthesized signals (registry_miss, tool drift, etc.) so
// identical logical inputs yield identical signal ids, keeping the Decision
// Contract hash a pure function of the inputs (Spec v1.6 §5.4 replayability).
func Derive(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}
