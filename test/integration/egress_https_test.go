//go:build integration

package integration

import (
	"testing"
	"time"
)

// TestExternalHTTPS verifies HTTPS (TLS SNI) filtering against real external
// endpoints. Skipped when the cluster cannot reach the internet.
func TestExternalHTTPS(t *testing.T) {
	ns := createNamespace(t)
	deployCurlPod(t, ns, "curl-ext", map[string]string{"app": "https-test"})
	waitPodReady(t, ns, "curl-ext")

	// Pre-check: can the pod reach the internet at all?
	status, ok := curlHTTP(ns, "curl-ext", "https://api.github.com/", 10)
	if !ok || status != "200" {
		t.Skipf("cluster cannot reach api.github.com (status=%s), skipping external HTTPS tests", status)
	}

	createEgressPolicy(t, ns, "https-policy",
		map[string]string{"app": "https-test"},
		[]string{"api.github.com"},
		"deny")
	waitPolicyEnforced(t, ns, "https-policy")

	waitBPFActive(t, ns, "curl-ext")

	t.Run("AllowedHTTPS", func(t *testing.T) {
		var lastStatus string
		for attempt := 0; attempt < 3; attempt++ {
			status, ok := curlHTTP(ns, "curl-ext", "https://api.github.com/", 10)
			if ok && status == "200" {
				return
			}
			lastStatus = status
			t.Logf("attempt %d: status=%s (retrying)", attempt+1, status)
			time.Sleep(5 * time.Second)
		}
		t.Errorf("curl to https://api.github.com/ failed after retries: status=%s", lastStatus)
	})

	t.Run("DeniedHTTPS", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-ext", "https://httpbin.org/get")
	})
}
