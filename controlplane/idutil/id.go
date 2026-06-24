// Package idutil generates prefixed random identifiers (decision_id, evidence_id,
// etc.) using crypto/rand. Stdlib only.
package idutil

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a prefixed 128-bit random id, e.g. New("dec") -> "dec-<32 hex>".
func New(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}
