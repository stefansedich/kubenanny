# KubeNanny

eBPF-based egress hostname filtering for Kubernetes pods. KubeNanny uses TC (Traffic Control) egress hooks to inspect outgoing traffic, extract hostnames from TLS SNI and HTTP Host headers, and enforce per-pod allowlists defined via a Kubernetes CRD.

## How It Works

1. **CRD-based policy** — Define `EgressPolicy` resources that select pods via label selectors and list allowed hostnames.
2. **eBPF TC egress filter** — A BPF program attached to pod veth interfaces inspects every outgoing TCP packet:
   - **Port 443**: Parses TLS ClientHello to extract the SNI hostname.
   - **Port 80**: Parses HTTP requests to extract the Host header.
   - Hostname is hashed (FNV-1a 64-bit) and matched against the policy allowlist in a BPF hash map.
3. **Allow/Deny** — Matching hostnames pass through (`TC_ACT_OK`), non-matching traffic is dropped (`TC_ACT_SHOT`) and a deny event is emitted via a ringbuf for logging and metrics.
4. **Conntrack cache** — Decisions are cached per 5-tuple in an LRU map to avoid re-parsing on every packet.

## Architecture

```
┌──────────────┐     ┌────────────────────┐     ┌──────────────┐
│ EgressPolicy │────▶│ Controller         │────▶│ BPF Maps     │
│ CRD          │     │ (Reconciler)       │     │ (pod_policy, │
└──────────────┘     └────────────────────┘     │  hostnames,  │
                              │                  │  conntrack)  │
                              ▼                  └──────┬───────┘
                     ┌────────────────────┐             │
                     │ BPF TC Egress      │◀────────────┘
                     │ (egress_filter.c)  │
                     └────────┬───────────┘
                              │ deny events
                              ▼
                     ┌────────────────────┐
                     │ Event Reader       │──▶ Prometheus Metrics
                     │ (ringbuf)          │──▶ Structured Logs
                     └────────────────────┘
```

## Prerequisites

- Go 1.25+
- Docker (for building)
- k3d and kubectl (for local development)
- Helm v3 (for deployment)

## Quick Start

### Local development with k3d

```bash
# Full cycle: create cluster, build, deploy, and run smoke tests
make dev

# View logs
make k3d-logs

# Tear down
make k3d-delete
```

### Build

```bash
# Build Docker image (includes BPF compilation)
make docker-build

# Run tests inside Docker (includes go vet)
make docker-test
```

### Deploy with Helm

```bash
# Install into an existing cluster
make helm-install

# Or manually:
helm install kubenanny charts/kubenanny \
  --namespace kubenanny-system --create-namespace \
  --set image.repository=kubenanny \
  --set image.tag=latest
```

## EgressPolicy CRD

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
    - "*.example.com"     # wildcard: matches any subdomain
  defaultAction: deny   # deny traffic when hostname can't be extracted
```

### Fields

| Field | Description |
|-------|-------------|
| `podSelector` | Standard Kubernetes label selector for target pods |
| `allowedHostnames` | Hostname allowlist. Supports exact match (`api.example.com`) and wildcard prefix (`*.example.com`) which matches any subdomain |
| `defaultAction` | `allow` or `deny` — applied when hostname cannot be determined (non-HTTP/non-TLS traffic). Default: `deny` |

## Project Structure

```
├── api/v1alpha1/          # CRD type definitions and DeepCopy methods
├── bpf/                   # eBPF C source files
│   ├── egress_filter.c    # Main TC egress classifier
│   ├── maps.h             # BPF map definitions
│   ├── sni_parser.h       # TLS ClientHello SNI extraction
│   ├── http_parser.h      # HTTP Host header extraction
│   └── vmlinux.h          # Minimal kernel type definitions
├── charts/kubenanny/      # Helm v3 chart
├── cmd/kubenanny/         # Application entrypoint
├── deploy/                # Raw Kubernetes manifests
├── internal/
│   ├── controller/        # EgressPolicy reconciler
│   ├── ebpf/              # BPF loader, map manager, event reader, hash
│   ├── metrics/           # Prometheus metrics
│   ├── netns/             # Pod IP to veth resolver
│   └── server/            # Health/readiness/metrics HTTP server
├── Dockerfile             # Multi-stage build (BPF + Go + distroless)
└── Makefile               # Build, test, k3d, and Helm targets
```

## Makefile Targets

Run `make help` to see all available targets.

## Metrics

KubeNanny exposes Prometheus metrics on port 9090 at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `kubenanny_egress_denied_total` | Counter | Denied egress connections (labels: src_ip, dst_ip, dst_port) |
| `kubenanny_egress_allowed_total` | Counter | Allowed egress connections |
| `kubenanny_policy_count` | Gauge | Active EgressPolicy resources |
| `kubenanny_monitored_pods` | Gauge | Pods with active egress filtering |
| `kubenanny_bpf_errors_total` | Counter | BPF-related errors |
