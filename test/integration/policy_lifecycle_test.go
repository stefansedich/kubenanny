//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"
)

// TestPolicyRecreate verifies that deleting a policy and recreating it
// with different hostnames works correctly.
func TestPolicyRecreate(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-pod", map[string]string{"app": "recreate-test"})

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-pod")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")

	createEgressPolicy(t, ns, "recreate-policy",
		map[string]string{"app": "recreate-test"},
		[]string{nginxFQDN},
		"deny")
	waitPolicyEnforced(t, ns, "recreate-policy")
	time.Sleep(3 * time.Second)

	t.Run("OriginalPolicy_Allowed", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-pod",
			fmt.Sprintf("http://%s/", nginxFQDN))
	})

	t.Run("OriginalPolicy_Denied", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-pod",
			"http://other.example.com/",
			"--resolve", fmt.Sprintf("other.example.com:80:%s", nginxIP))
	})

	kubectl(t, "delete", "egresspolicy", "recreate-policy", "-n", ns)
	time.Sleep(5 * time.Second)

	createEgressPolicy(t, ns, "recreate-policy",
		map[string]string{"app": "recreate-test"},
		[]string{"other.example.com"},
		"deny")
	waitPolicyEnforced(t, ns, "recreate-policy")
	time.Sleep(3 * time.Second)

	t.Run("RecreatedPolicy_NewHostAllowed", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-pod",
			"http://other.example.com/",
			"--resolve", fmt.Sprintf("other.example.com:80:%s", nginxIP))
	})

	t.Run("RecreatedPolicy_OldHostDenied", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-pod",
			"http://fresh-nginx.example.com/",
			"--resolve", fmt.Sprintf("fresh-nginx.example.com:80:%s", nginxIP))
	})
}

// TestPolicyScopedToPodSelector verifies that a policy only affects pods
// matching its selector and does not interfere with other pods.
func TestPolicyScopedToPodSelector(t *testing.T) {
	ns := createNamespace(t)
	nginxFQDN := fmt.Sprintf("nginx-target.%s.svc.cluster.local", ns)

	deployNginx(t, ns)
	deployCurlPod(t, ns, "curl-targeted", map[string]string{"app": "targeted"})
	deployCurlPod(t, ns, "curl-other", map[string]string{"app": "other"})

	waitPodReady(t, ns, "nginx-target")
	waitPodReady(t, ns, "curl-targeted")
	waitPodReady(t, ns, "curl-other")

	nginxIP := serviceClusterIP(t, ns, "nginx-target")

	createEgressPolicy(t, ns, "scoped-policy",
		map[string]string{"app": "targeted"},
		[]string{nginxFQDN},
		"deny")
	waitPolicyEnforced(t, ns, "scoped-policy")
	time.Sleep(3 * time.Second)

	t.Run("TargetedPod_DeniedHost", func(t *testing.T) {
		assertCurlDenied(t, ns, "curl-targeted",
			"http://blocked.example.com/",
			"--resolve", fmt.Sprintf("blocked.example.com:80:%s", nginxIP))
	})

	t.Run("OtherPod_SameHostAllowed", func(t *testing.T) {
		assertCurlAllowed(t, ns, "curl-other",
			"http://blocked.example.com/",
			"--resolve", fmt.Sprintf("blocked.example.com:80:%s", nginxIP))
	})
}
