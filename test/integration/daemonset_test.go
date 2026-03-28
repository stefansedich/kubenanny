//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestDaemonSetReady verifies that all kubenanny DaemonSet pods are Running.
func TestDaemonSetReady(t *testing.T) {
	out := kubectl(t, "get", "pods", "-n", kubenannyNS,
		"-l", "app.kubernetes.io/name=kubenanny",
		"-o", `jsonpath={range .items[*]}{.metadata.name}={.status.phase}{"\n"}{end}`)

	pods := strings.Split(strings.TrimSpace(out), "\n")
	if len(pods) == 0 || (len(pods) == 1 && pods[0] == "") {
		t.Fatal("no kubenanny pods found in namespace " + kubenannyNS)
	}
	for _, p := range pods {
		if !strings.HasSuffix(p, "=Running") {
			t.Errorf("pod not Running: %s", p)
		}
	}
	t.Logf("%d kubenanny pod(s) running", len(pods))
}
