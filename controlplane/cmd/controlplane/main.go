// Command controlplane runs the Sprint-2 runtime decision MVP HTTP server.
//
// Production deployments MUST front this with mTLS, workload identity,
// per-tenant rate limiting, and request anti-replay (Spec v1.6 §5.1/§5.2).
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/model"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/service"
	"github.com/raccoonrat/cloud-native-ai-security/controlplane/tool"
)

func main() {
	addr := os.Getenv("CONTROL_PLANE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	key := []byte(os.Getenv("CONTROL_PLANE_HMAC_KEY"))
	if len(key) == 0 {
		key = []byte("dev-insecure-hmac-key-change-me")
	}

	svc, reg, toolReg := service.NewDefault(key)
	// Register the MVP P0 detectors (INV-7). In production this comes from the
	// Detector Registry service.
	for _, id := range []string{
		"det-prompt-injection", "det-enterprise-data-leakage", "det-tool-schema-drift",
		"det-source-trust",
	} {
		reg.Register(service.DetectorEntry{SourceID: id, Versions: map[string]bool{"1": true}})
	}
	// Register an example MVP tool snapshot (platform MCP registry is authoritative).
	toolReg.Register(tool.MetadataSnapshot{
		ToolID: "send_email", ServerID: "mcp-email-server-prod", ToolVersion: "1.2.0",
		SchemaHash: "sha256:schema-v1", ManifestHash: "sha256:manifest-v1",
		PermissionClass: model.PermExternalSend, TrustState: model.TrustApproved,
		Owner: "platform-mcp",
	})

	log.Printf("control plane listening on %s (provenance MODE_A)", addr)
	log.Printf("routes: POST /v1/decisions:evaluate, POST /v1/decisions:augment, POST /v1/replay:decision, POST /v1/release-gates:evaluate, GET /healthz")
	if err := http.ListenAndServe(addr, svc.Handler()); err != nil {
		log.Fatal(err)
	}
}
