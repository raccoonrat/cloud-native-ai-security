// Package sign provides decision-integrity signing (Spec v1.6 §5.4). In
// canary/prod a decision MUST be signed and the Enforcement Adapter MUST verify
// the signature before acting (INV-3 extended). The skeleton uses HMAC-SHA256;
// production may swap in asymmetric signing behind the same interfaces.
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Signer signs a payload hash, returning the signature and the signer identity.
type Signer interface {
	Sign(payloadHash string) (signature string, signedBy string)
}

// Verifier verifies a signature against a payload hash.
type Verifier interface {
	Verify(payloadHash, signature string) bool
}

// HMAC implements Signer and Verifier with a shared secret.
type HMAC struct {
	key  []byte
	name string
}

// NewHMAC builds an HMAC signer/verifier identified by name.
func NewHMAC(key []byte, name string) *HMAC { return &HMAC{key: key, name: name} }

// Sign returns hex(HMAC-SHA256(payloadHash)) and the signer name.
func (h *HMAC) Sign(payloadHash string) (string, string) {
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(payloadHash))
	return hex.EncodeToString(mac.Sum(nil)), h.name
}

// Verify checks a signature in constant time.
func (h *HMAC) Verify(payloadHash, signature string) bool {
	want, _ := h.Sign(payloadHash)
	return hmac.Equal([]byte(want), []byte(signature))
}
