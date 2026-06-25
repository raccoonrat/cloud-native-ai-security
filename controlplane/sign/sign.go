// Package sign provides decision-integrity signing (Spec v1.6 §5.4). In
// canary/prod a decision MUST be signed and the Enforcement Adapter MUST verify
// the signature before acting (INV-3 extended). The skeleton uses HMAC-SHA256;
// production may swap in asymmetric signing behind the same interfaces.
package sign

import (
	"crypto/ed25519"
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

// Ed25519Signer signs decisions with an asymmetric private key. Unlike the
// shared-secret HMAC, the Enforcement Adapter verifies with the PUBLIC key only
// and therefore CANNOT forge a Decision Contract — this is the correct trust
// boundary between the control plane (signer) and enforcement (verifier) in
// canary/prod (Spec v1.6 §5.4, review P2-I). Stdlib only (crypto/ed25519).
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	name string
}

// NewEd25519Signer builds an asymmetric signer identified by name.
func NewEd25519Signer(priv ed25519.PrivateKey, name string) *Ed25519Signer {
	return &Ed25519Signer{priv: priv, name: name}
}

// Sign returns hex(Ed25519(payloadHash)) and the signer name.
func (s *Ed25519Signer) Sign(payloadHash string) (string, string) {
	sig := ed25519.Sign(s.priv, []byte(payloadHash))
	return hex.EncodeToString(sig), s.name
}

// Ed25519Verifier verifies decision signatures with only the public key.
type Ed25519Verifier struct {
	pub ed25519.PublicKey
}

// NewEd25519Verifier builds a verifier from a public key (no signing capability).
func NewEd25519Verifier(pub ed25519.PublicKey) *Ed25519Verifier {
	return &Ed25519Verifier{pub: pub}
}

// Verify checks an Ed25519 signature over the payload hash.
func (v *Ed25519Verifier) Verify(payloadHash, signature string) bool {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(v.pub, []byte(payloadHash), sig)
}
