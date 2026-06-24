package service

import (
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
)

// NewDefault builds a fully wired MVP Service with the embedded matrix, the
// default policy bundle, an in-memory registry/evidence store, and an HMAC
// signer. The returned registry is exposed so callers/tests can register
// detector sources (INV-7).
func NewDefault(hmacKey []byte) (*Service, *MemRegistry) {
	m := matrix.MustLoad()
	reg := NewMemRegistry()
	ev := evidence.NewMemStore()
	signer := sign.NewHMAC(hmacKey, "control-plane-runtime")
	svc := New(m, policy.DefaultBundle(), reg, ev, signer, Config{})
	return svc, reg
}
