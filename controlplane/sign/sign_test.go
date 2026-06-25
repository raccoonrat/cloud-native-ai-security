package sign

import (
	"crypto/ed25519"
	"testing"
)

// P2-I: with asymmetric signing the verifier holds only the public key, so a
// holder of the verifier (the Enforcement Adapter) cannot forge a signature.
func TestEd25519SignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewEd25519Signer(priv, "control-plane-runtime")
	verifier := NewEd25519Verifier(pub)

	hash := "sha256:abc123"
	sig, by := signer.Sign(hash)
	if by != "control-plane-runtime" {
		t.Fatalf("unexpected signer name %q", by)
	}
	if !verifier.Verify(hash, sig) {
		t.Fatalf("valid signature must verify")
	}
	if verifier.Verify("sha256:tampered", sig) {
		t.Fatalf("signature must not verify over a different payload hash")
	}
	if verifier.Verify(hash, "not-hex") {
		t.Fatalf("a malformed signature must not verify")
	}

	// A different keypair must not validate this signature (no shared secret).
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if NewEd25519Verifier(otherPub).Verify(hash, sig) {
		t.Fatalf("a foreign public key must not verify the signature")
	}
}
