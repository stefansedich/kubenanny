//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	kubenannyNS  = "kubenanny-system"
	curlImage    = "curlimages/curl:latest"
	nginxImage   = "nginx:alpine"
	pollInterval = 2 * time.Second
	pollTimeout  = 120 * time.Second
)

// kubectl runs a command and fails the test on error.
func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := kubectlRun(args...)
	if err != nil {
		t.Fatalf("kubectl %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// kubectlRun runs kubectl and returns (trimmed stdout, error).
func kubectlRun(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// kubectlApply pipes a YAML manifest to kubectl apply.
func kubectlApply(t *testing.T, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v\n%s", err, out)
	}
}

// createNamespace creates a unique namespace and registers cleanup.
func createNamespace(t *testing.T) string {
	t.Helper()
	ns := fmt.Sprintf("kn-e2e-%s", fmt.Sprintf("%d", time.Now().UnixNano())[:12])
	//nolint:errcheck // best-effort cleanup of stale ns
	exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false").Run()
	time.Sleep(1 * time.Second)
	kubectl(t, "create", "namespace", ns)
	t.Cleanup(func() {
		//nolint:errcheck // cleanup
		exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false").Run()
	})
	t.Logf("created namespace %s", ns)
	return ns
}

// deployNginx deploys an nginx pod and ClusterIP service in the namespace.
func deployNginx(t *testing.T, ns string) {
	t.Helper()
	kubectlApply(t, fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: nginx-target
  namespace: %[1]s
  labels:
    role: target
spec:
  containers:
  - name: nginx
    image: %[2]s
    ports:
    - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-target
  namespace: %[1]s
spec:
  selector:
    role: target
  ports:
  - port: 80
    targetPort: 80`, ns, nginxImage))
}

// deployCurlPod creates a long-running curl pod. labels may be nil.
func deployCurlPod(t *testing.T, ns, name string, labels map[string]string) {
	t.Helper()
	labelLines := ""
	if len(labels) > 0 {
		labelLines = "  labels:\n"
		for k, v := range labels {
			labelLines += fmt.Sprintf("    %s: %q\n", k, v)
		}
	}
	kubectlApply(t, fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
%sspec:
  containers:
  - name: curl
    image: %s
    command: ["sleep", "3600"]`, name, ns, labelLines, curlImage))
}

// createEgressPolicy creates (or updates via apply) an EgressPolicy.
func createEgressPolicy(t *testing.T, ns, name string, matchLabels map[string]string, hostnames []string, defaultAction string) {
	t.Helper()
	labels := ""
	for k, v := range matchLabels {
		labels += fmt.Sprintf("        %s: %q\n", k, v)
	}
	hosts := ""
	for _, h := range hostnames {
		hosts += fmt.Sprintf("    - %q\n", h)
	}
	kubectlApply(t, fmt.Sprintf(`apiVersion: policy.kubenanny.io/v1alpha1
kind: EgressPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels:
%s  allowedHostnames:
%s  defaultAction: %s`, name, ns, labels, hosts, defaultAction))
}

// waitPodReady blocks until the named pod is Running+Ready or the timeout expires.
func waitPodReady(t *testing.T, ns, name string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		phase, _ := kubectlRun("get", "pod", name, "-n", ns,
			"-o", "jsonpath={.status.phase}")
		if phase == "Running" {
			ready, _ := kubectlRun("get", "pod", name, "-n", ns,
				"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
			if ready == "True" {
				return
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("pod %s/%s not ready within %v", ns, name, pollTimeout)
}

// waitPolicyEnforced blocks until .status.enforced == true.
func waitPolicyEnforced(t *testing.T, ns, name string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		out, err := kubectlRun("get", "egresspolicy", name, "-n", ns,
			"-o", "jsonpath={.status.enforced}")
		if err == nil && out == "true" {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("policy %s/%s not enforced within %v", ns, name, pollTimeout)
}

// serviceClusterIP returns the ClusterIP of a service.
func serviceClusterIP(t *testing.T, ns, name string) string {
	t.Helper()
	return kubectl(t, "get", "svc", name, "-n", ns, "-o", "jsonpath={.spec.clusterIP}")
}

// execInPod runs an arbitrary command inside a pod.
func execInPod(ns, pod string, args ...string) (stdout, stderr string, ok bool) {
	full := append([]string{"exec", pod, "-n", ns, "--"}, args...)
	cmd := exec.Command("kubectl", full...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err == nil
}

// curlHTTP runs curl from a pod and returns (httpStatusCode, succeeded).
func curlHTTP(ns, pod, url string, timeoutSec int, extraArgs ...string) (status string, ok bool) {
	args := []string{
		"curl", "-sS",
		"--max-time", fmt.Sprintf("%d", timeoutSec),
		"-o", "/dev/null",
		"-w", "%{http_code}",
	}
	args = append(args, extraArgs...)
	args = append(args, url)
	stdout, _, ok := execInPod(ns, pod, args...)
	return strings.TrimSpace(stdout), ok
}

// assertCurlAllowed asserts that a curl from the pod returns HTTP 200.
func assertCurlAllowed(t *testing.T, ns, pod, url string, extraArgs ...string) {
	t.Helper()
	status, ok := curlHTTP(ns, pod, url, 10, extraArgs...)
	if !ok {
		t.Errorf("curl to %s failed (want success): status=%s", url, status)
		return
	}
	if status != "200" {
		t.Errorf("curl to %s returned %s, want 200", url, status)
	}
}

// assertCurlDenied asserts that a curl from the pod does NOT return HTTP 200.
func assertCurlDenied(t *testing.T, ns, pod, url string, extraArgs ...string) {
	t.Helper()
	status, ok := curlHTTP(ns, pod, url, 5, extraArgs...)
	if ok && status == "200" {
		t.Errorf("curl to %s succeeded with 200 (want denied/timeout)", url)
	}
	t.Logf("denied check: ok=%v status=%s (non-200 is expected)", ok, status)
}

// waitBPFActive polls until the BPF egress filter is actually intercepting traffic.
func waitBPFActive(t *testing.T, ns, pod string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, ok := curlHTTP(ns, pod, "https://httpbin.org/get", 3)
		if !ok || status != "200" {
			return
		}
		t.Logf("BPF not yet active (httpbin.org returned %s), waiting...", status)
		time.Sleep(2 * time.Second)
	}
	t.Logf("warning: BPF may not be active (timed out waiting for deny)")
}
