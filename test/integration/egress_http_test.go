//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"
)

// TestEgressFiltering exercises the core egress-filtering lifecycle:
// baseline -> create policy -> allow/deny -> update -> delete.
func TestEgressFiltering(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-labeled", map[string]string{"app": "egress-test"})
	deployCurlPod(t, ns, "curl-nolabel", nil)

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-labeled")
	waitPodReady(t, ns, "curl-nolabel")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")
	t.Logf("nginx FQDN=%s  ClusterIP=%s", nginxFQDN, nginxIP)

	t.Run("Baseline_NoPolicy", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-labeled",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	createEgressPolicy(t, ns, "test-policy",
		map[string]string{"app": "egress-test"},
		[]string{nginxFQDN},
		"deny")
	waitPolicyEnforced(t, ns, "test-policy")
	time.Sleep(3 * time.Second)

	t.Run("PolicyStatus", func(t *testing.T) {
		enforced := kubectl(t, "get", "egresspolicy", "test-policy", "-n", ns,
			"-o", "jsonpath={.status.enforced}")
		if enforced != "true" {
			t.Errorf("enforced=%s, want true", enforced)
		}
		matched := kubectl(t, "get", "egresspolicy", "test-policy", "-n", ns,
			"-o", "jsonpath={.status.matchedPods}")
		t.Logf("matchedPods=%s (informational, pod may be on either node)", matched)
	})

	t.Run("AllowedHTTP", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-labeled",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("DeniedHTTP", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-labeled",
			"http://blocked.example.com/",
			"--resolve", fmt.Sprintf("blocked.example.com:80:%s", nginxIP))
	})

	t.Run("UnlabeledPodBypass", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-nolabel",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("UnlabeledPod_NonAllowedHost", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-nolabel",
			"http://anyhost.example.com/",
			"--resolve", fmt.Sprintf("anyhost.example.com:80:%s", nginxIP))
	})

	t.Run("PolicyUpdate", func(t *testing.T) {
		createEgressPolicy(t, ns, "test-policy",
			map[string]string{"app": "egress-test"},
			[]string{nginxFQDN, "added.example.com"},
			"deny")
		time.Sleep(5 * time.Second)

		assertCurlAllowed(t, ns, "curl-labeled",
			"http://added.example.com/",
			"--resolve", fmt.Sprintf("added.example.com:80:%s", nginxIP))
	})

	t.Run("PolicyDeletion", func(t *testing.T) {
		kubectl(t, "delete", "egresspolicy", "test-policy", "-n", ns)
		time.Sleep(5 * time.Second)

		assertCurlAllowed(t, ns, "curl-labeled",
			"http://post-delete.example.com/",
			"--resolve", fmt.Sprintf("post-delete.example.com:80:%s", nginxIP))
	})
}

// TestDefaultActionAllow verifies that defaultAction=allow still denies traffic
// with an extractable but non-allowed hostname.
func TestDefaultActionAllow(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-pod", map[string]string{"app": "allow-test"})

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-pod")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")

	createEgressPolicy(t, ns, "allow-policy",
		map[string]string{"app": "allow-test"},
		[]string{nginxFQDN},
		"allow")
	waitPolicyEnforced(t, ns, "allow-policy")
	time.Sleep(3 * time.Second)

	t.Run("AllowedHost", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-pod",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("DeniedHost_ExtractableHeader", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-pod",
			"http://unknown-host.example.com/",
			"--resolve", fmt.Sprintf("unknown-host.example.com:80:%s", nginxIP))
	})
}
