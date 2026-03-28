//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"
)

// TestWildcardHostname verifies that a wildcard pattern like *.example.com
// matches any subdomain while still denying non-matching hostnames.
func TestWildcardHostname(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-wc", map[string]string{"app": "wildcard-test"})

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-wc")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")
	t.Logf("nginx FQDN=%s  ClusterIP=%s", nginxFQDN, nginxIP)

	// Create policy with a wildcard hostname that covers the nginx FQDN.
	// nginx FQDN: nginx-target.<ns>.svc.cluster.local
	// Wildcard:   *.<ns>.svc.cluster.local
	wildcardPattern := fmt.Sprintf("*.%s.svc.cluster.local", ns)

	createEgressPolicy(t, ns, "wildcard-policy",
		map[string]string{"app": "wildcard-test"},
		[]string{wildcardPattern},
		"deny")
	waitPolicyEnforced(t, ns, "wildcard-policy")
	time.Sleep(3 * time.Second)

	t.Run("WildcardAllowsSubdomain", func(t *testing.T) {
		// nginx-target.<ns>.svc.cluster.local should match *.<ns>.svc.cluster.local
		assertCurlAllowed(t, ns, "curl-wc",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("WildcardDeniesNonMatch", func(t *testing.T) {
		// A hostname under a different domain should be denied.
		assertCurlDenied(t, ns, "curl-wc",
			"http://blocked.other-domain.com/",
			"--resolve", fmt.Sprintf("blocked.other-domain.com:80:%s", nginxIP))
	})

	t.Run("WildcardDeniesExactDomain", func(t *testing.T) {
		// The exact domain (without subdomain) should NOT match the wildcard.
		// e.g. "ns.svc.cluster.local" should not match "*.ns.svc.cluster.local"
		domain := fmt.Sprintf("%s.svc.cluster.local", ns)
		assertCurlDenied(t, ns, "curl-wc",
			fmt.Sprintf("http://%s/", domain),
			"--resolve", fmt.Sprintf("%s:80:%s", domain, nginxIP))
	})

	t.Run("MixedExactAndWildcard", func(t *testing.T) {
		// Update policy to include both an exact match and a wildcard.
		createEgressPolicy(t, ns, "wildcard-policy",
			map[string]string{"app": "wildcard-test"},
			[]string{wildcardPattern, "exact-host.example.com"},
			"deny")
		time.Sleep(5 * time.Second)

		// Wildcard should still work.
		assertCurlAllowed(t, ns, "curl-wc",
			fmt.Sprintf("http://%s/", nginxFQDN))

		// Exact match should also work.
		assertCurlAllowed(t, ns, "curl-wc",
			"http://exact-host.example.com/",
			"--resolve", fmt.Sprintf("exact-host.example.com:80:%s", nginxIP))
	})
}
