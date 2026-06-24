// Command controlplane runs the Sprint-2 runtime decision MVP HTTP server.
//
// Production deployments MUST front this with mTLS, workload identity,
// per-tenant rate limiting, and request anti-replay (Spec v1.6 §5.1/§5.2).
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/raccoonrat/cloud-native-ai-security/controlplane/service"
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

	svc, reg := service.NewDefault(key)
	// Register the MVP P0 detectors (INV-7). In production this comes from the
	// Detector Registry service.
	for _, id := range []string{
		"det-prompt-injection", "det-enterprise-data-leakage", "det-tool-schema-drift",
		"det-source-trust",
	} {
		reg.Register(service.DetectorEntry{SourceID: id, Versions: map[string]bool{"1": true}})
	}

	log.Printf("control plane listening on %s (provenance MODE_A)", addr)
	if err := http.ListenAndServe(addr, svc.Handler()); err != nil {
		log.Fatal(err)
	}
}
