//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"
)

// TestMultiplePolicies verifies that two policies targeting different pod
// selectors coexist correctly in the same namespace.
func TestMultiplePolicies(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-alpha", map[string]string{"tier": "alpha"})
	deployCurlPod(t, ns, "curl-beta", map[string]string{"tier": "beta"})

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-alpha")
	waitPodReady(t, ns, "curl-beta")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")

	createEgressPolicy(t, ns, "alpha-policy",
		map[string]string{"tier": "alpha"},
		[]string{nginxFQDN},
		"deny")

	createEgressPolicy(t, ns, "beta-policy",
		map[string]string{"tier": "beta"},
		[]string{"beta-allowed.example.com"},
		"deny")

	waitPolicyEnforced(t, ns, "alpha-policy")
	waitPolicyEnforced(t, ns, "beta-policy")
	time.Sleep(3 * time.Second)

	t.Run("AlphaAllowed", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-alpha",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("AlphaDenied", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-alpha",
			"http://beta-allowed.example.com/",
			"--resolve", fmt.Sprintf("beta-allowed.example.com:80:%s", nginxIP))
	})

	t.Run("BetaAllowed", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-beta",
			"http://beta-allowed.example.com/",
			"--resolve", fmt.Sprintf("beta-allowed.example.com:80:%s", nginxIP))
	})

	t.Run("BetaDenied", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-beta",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})
}
