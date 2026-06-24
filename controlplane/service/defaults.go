package service

import (
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/approval"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/evidence"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/matrix"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/policy"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/sign"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

// NewDefault builds a fully wired MVP Service with the embedded matrix, the
// default policy bundle, in-memory registries/stores, the Tool Registry +
// Approval Binding Service (Sprint 3), and an HMAC signer. The returned
// detector and tool registries are exposed so callers/tests can register
// sources (INV-7) and tool metadata snapshots.
func NewDefault(hmacKey []byte) (*Service, *MemRegistry, *tool.MemRegistry) {
	m := matrix.MustLoad()
	reg := NewMemRegistry()
	toolReg := tool.NewMemRegistry()
	ev := evidence.NewMemStore()
	signer := sign.NewHMAC(hmacKey, "control-plane-runtime")
	svc := New(m, policy.DefaultBundle(), reg, ev, signer, Config{}).
		WithTooling(toolReg, approval.NewMemService())
	return svc, reg, toolReg
}
