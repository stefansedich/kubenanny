# Deployment Guide

## Requirements

- Kubernetes 1.31+ (tested with k3s v1.31.4)
- Kernel 5.3+ (for bounded BPF loops; 5.15+ recommended for TCX)
- Helm v3
- Nodes must allow privileged containers with BPF capabilities

## Helm Installation

### Quick Install

```bash
helm install kubenanny charts/kubenanny \
  --namespace kubenanny-system --create-namespace \
  --set image.repository=kubenanny \
  --set image.tag=latest
```

### From a Built Image

```bash
# Build the image
make docker/build

# Push to your registry
docker tag kubenanny:latest your-registry.com/kubenanny:v1.0.0
docker push your-registry.com/kubenanny:v1.0.0

# Install
helm install kubenanny charts/kubenanny \
  --namespace kubenanny-system --create-namespace \
  --set image.repository=your-registry.com/kubenanny \
  --set image.tag=v1.0.0
```

### Configuration

Key `values.yaml` settings:

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` | `kubenanny` | Container image repository |
| `image.tag` | `latest` | Container image tag |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `hostNetwork` | `true` | Required for TC attachment to pod veths |
| `dnsPolicy` | `ClusterFirstWithHostNet` | DNS policy for host networking |
| `metrics.enabled` | `true` | Enable Prometheus metrics |
| `metrics.port` | `9090` | Metrics/health HTTP port |
| `metrics.serviceMonitor.enabled` | `false` | Create Prometheus ServiceMonitor |
| `healthPort` | `9090` | Liveness/readiness probe port |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `256Mi` | Memory limit |

### Tolerations

By default, the DaemonSet tolerates all taints to ensure it runs on every node:

```yaml
tolerations:
  - operator: Exists
```

Override in `values.yaml` to restrict to specific nodes.

## What Gets Deployed

The Helm chart creates:

| Resource | Purpose |
|----------|---------|
| **DaemonSet** | One kubenanny pod per node |
| **ServiceAccount** | Identity for the DaemonSet pods |
| **ClusterRole** | Permission to watch pods, EgressPolicy CRDs, update status |
| **ClusterRoleBinding** | Binds the role to the service account |
| **Service** | Exposes metrics port for Prometheus scraping |
| **ServiceMonitor** (optional) | Prometheus Operator auto-discovery |
| **CRD** | `EgressPolicy` custom resource definition (installed via `crds/` directory) |

## Security Context

The DaemonSet requires elevated privileges for BPF operations:

```yaml
securityContext:
  privileged: true
  runAsUser: 0
  capabilities:
    add:
      - SYS_ADMIN   # BPF syscall, map creation
      - NET_ADMIN    # TC program attachment
      - BPF          # BPF program loading
      - PERFMON      # Performance monitoring
```

The container also mounts:
- `/sys/fs/bpf` — BPF filesystem for pinned maps
- `/sys/fs/cgroup` (read-only) — cgroup visibility

## Volume Mounts

| Mount | Host Path | Mode | Purpose |
|-------|-----------|------|---------|
| `/sys/fs/bpf` | `/sys/fs/bpf` | read-write | BPF filesystem |
| `/sys/fs/cgroup` | `/sys/fs/cgroup` | read-only | Cgroup access |

## Creating Policies

### Basic Policy

Allow only specific hostnames for pods with a given label:

```yaml
apiVersion: policy.kubenanny.io/v1alpha1
kind: EgressPolicy
metadata:
  name: allow-github
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: my-app
  allowedHostnames:
    - api.github.com
    - github.com
  defaultAction: deny
```

### Wildcard Policy

Allow all subdomains of a domain:

```yaml
apiVersion: policy.kubenanny.io/v1alpha1
kind: EgressPolicy
metadata:
  name: allow-internal
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: my-app
  allowedHostnames:
    - "*.internal.company.com"
    - monitoring.company.com
  defaultAction: deny
```

`*.internal.company.com` matches `api.internal.company.com`, `db.internal.company.com`, etc. It does **not** match `internal.company.com` itself (no subdomain prefix).

### Allow-by-Default Policy

Only inspect and block specific protocols while allowing everything else:

```yaml
apiVersion: policy.kubenanny.io/v1alpha1
kind: EgressPolicy
metadata:
  name: inspect-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: my-app
  allowedHostnames:
    - api.github.com
  defaultAction: allow
```

With `defaultAction: allow`:
- HTTP/HTTPS to `api.github.com` → allowed
- HTTP/HTTPS to any other hostname → denied
- Non-HTTP/non-TLS traffic (e.g., raw TCP, gRPC without TLS) → allowed

## Monitoring

### Prometheus Metrics

Exposed on `:9090/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kubenanny_egress_denied_total` | Counter | `src_ip`, `dst_ip`, `dst_port` | Denied connections |
| `kubenanny_egress_allowed_total` | Counter | `src_ip`, `dst_ip`, `dst_port` | Allowed connections |
| `kubenanny_policy_count` | Gauge | — | Active EgressPolicy count |
| `kubenanny_monitored_pods` | Gauge | — | Pods with active filtering |
| `kubenanny_bpf_errors_total` | Counter | — | BPF-related errors |

### Structured Logs

JSON-formatted via `slog`. Key log entries:

```json
{"level":"INFO","msg":"egress denied","src_ip":"10.42.0.5","dst_ip":"93.184.216.34","dst_port":443,"hostname_hash":12345678,"policy_id":42}
{"level":"INFO","msg":"reconciled","policy":"default/allow-github","matchedPods":3}
{"level":"INFO","msg":"TC program attached","interface":"veth1234abcd"}
```

### Health Endpoints

| Endpoint | Port | Description |
|----------|------|-------------|
| `/healthz` | 9090 | Liveness probe — process is alive |
| `/readyz` | 9090 | Readiness probe — BPF loaded, API connected |
| `/metrics` | 9090 | Prometheus metrics |
| `/healthz` | 8081 | Controller-manager liveness |
| `/readyz` | 8081 | Controller-manager readiness |

## Uninstalling

```bash
# Remove the Helm release
helm uninstall kubenanny --namespace kubenanny-system

# Remove the CRD (this deletes all EgressPolicy resources)
kubectl delete crd egresspolicies.policy.kubenanny.io

# Remove the namespace
kubectl delete namespace kubenanny-system
```

Or via Makefile:

```bash
make k3d/undeploy
```

## Troubleshooting

### Pods not being filtered

1. Check the DaemonSet is running: `kubectl -n kubenanny-system get pods`
2. Check the policy is enforced: `kubectl get egresspolicy -n <namespace> -o yaml`
3. Verify the pod labels match the policy selector.
4. Check kubenanny logs for reconciliation errors: `make k3d/logs`

### BPF program fails to load

- Ensure the kernel is 5.3+ (for bounded loops) and 5.15+ (for TCX).
- Check verifier errors in logs — kubenanny dumps the full verifier log on failure.
- Ensure the container has the required capabilities (`SYS_ADMIN`, `BPF`, `NET_ADMIN`).

### Conntrack caching stale decisions

After updating a policy, existing connections may use cached decisions for a short time. The conntrack cache is flushed on policy deletion. For policy updates, connections will be re-evaluated when the LRU evicts old entries or when new connections are established.
