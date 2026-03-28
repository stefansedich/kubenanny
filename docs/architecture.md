# Architecture

KubeNanny is a single-binary DaemonSet that enforces hostname-based egress policies on Kubernetes pods using eBPF. One instance runs on every node, loading BPF programs into the kernel and managing policy state via shared BPF maps.

## High-Level Flow

```
                         ┌──────────────────┐
                         │  Kubernetes API   │
                         │  (EgressPolicy)   │
                         └────────┬─────────┘
                                  │ watch
                                  ▼
┌─────────────────────────────────────────────────────────┐
│  KubeNanny DaemonSet (per node)                         │
│                                                         │
│  ┌──────────────────┐    ┌────────────────────────────┐ │
│  │ Controller        │───▶│ BPF Maps                   │ │
│  │ (Reconciler)      │    │                            │ │
│  │                   │    │ pod_policy     {ip→policy}  │ │
│  │ Watches:          │    │ policy_hostnames {id,hash} │ │
│  │ • EgressPolicy    │    │ policy_default  {id→action}│ │
│  │ • Pods            │    │ conntrack      {5-tuple}   │ │
│  └──────────────────┘    └─────────┬──────────────────┘ │
│                                    │ read                │
│  ┌──────────────────┐    ┌─────────▼──────────────────┐ │
│  │ Event Reader      │◀───│ BPF TC Egress Filter       │ │
│  │ (ringbuf)         │    │ (egress_filter.c)          │ │
│  └────────┬─────────┘    │                            │ │
│           │               │ Attached to veth ifaces    │ │
│           ▼               └────────────────────────────┘ │
│  ┌──────────────────┐                                    │
│  │ Prometheus Metrics│                                    │
│  │ Structured Logs   │                                    │
│  └──────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

## Components

### BPF Datapath (`bpf/`)

The kernel-space component. A single TC (Traffic Control) classifier program attached to pod veth interfaces via TCX. It intercepts every outgoing TCP packet and:

1. Looks up the source IP in the `pod_policy` map to find the policy ID.
2. Checks the `conntrack` LRU map for a cached decision (fast-path).
3. If no cache hit, linearizes and copies the TCP payload into a per-CPU scratch buffer.
4. Parses the payload — TLS ClientHello for SNI (port 443) or HTTP request for the Host header (port 80).
5. Hashes the extracted hostname (FNV-1a 64-bit) and looks it up in `policy_hostnames`.
6. If no exact match, tries wildcard suffix matching (`*.example.com`) by decomposing the hostname at `.` boundaries.
7. Caches the decision in conntrack and returns `TC_ACT_OK` (allow) or `TC_ACT_SHOT` (deny).
8. Denied connections emit a `deny_event` to userspace via a ringbuf map.

See [BPF Datapath](bpf-datapath.md) for details.

### Go Control Plane (`internal/`)

The userspace daemon, structured as a single binary with these subsystems:

| Package | Responsibility |
|---------|----------------|
| `internal/ebpf` | BPF object loading (via `bpf2go`), TCX attachment, map CRUD, event reading, FNV-1a hashing |
| `internal/controller` | `controller-runtime` reconciler for `EgressPolicy` CRD and `Pod` events |
| `internal/netns` | Pod IP → host-side veth interface resolution via netlink |
| `internal/metrics` | Prometheus counter/gauge definitions |
| `internal/server` | HTTP server for `/healthz`, `/readyz`, and `/metrics` |

### CRD (`api/v1alpha1/`)

`EgressPolicy` is a namespace-scoped custom resource:

```yaml
apiVersion: policy.kubenanny.io/v1alpha1
kind: EgressPolicy
metadata:
  name: allow-github
spec:
  podSelector:
    matchLabels:
      app: my-app
  allowedHostnames:
    - api.github.com
    - "*.example.com"
  defaultAction: deny
```

- **podSelector** — standard label selector; only pods on the local node are processed.
- **allowedHostnames** — exact (`api.github.com`) or wildcard (`*.example.com`) patterns.
- **defaultAction** — `allow` or `deny` for traffic where no hostname can be extracted (non-HTTP/non-TLS).

### CLI (`cmd/kubenanny/`)

Uses `spf13/cobra`. Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--health-addr` | `:9090` | Health/metrics HTTP server address |
| `--probe-addr` | `:8081` | Controller-manager health probe address |
| `--log-level` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `--node-name` | `$NODE_NAME` | Kubernetes node name for pod filtering |

## BPF Maps

Six BPF maps are shared between kernel and userspace:

| Map | Type | Max Entries | Key | Value | Purpose |
|-----|------|-------------|-----|-------|---------|
| `pod_policy` | HASH | 65,536 | `pod_ip` (4B) | `policy_id` (4B) | Maps pod IPs to their policy |
| `policy_hostnames` | HASH | 65,536 | `{policy_id, hostname_hash}` (16B) | `action` (1B) | Hostname allowlist |
| `policy_default_action` | HASH | 4,096 | `policy_id` (4B) | `action` (1B) | Default action per policy |
| `conntrack` | LRU_HASH | 131,072 | `{src_ip, dst_ip, src_port, dst_port, proto}` (16B) | `action` (1B) | Per-connection decision cache |
| `events` | RINGBUF | 64 KiB | — | `deny_event` (36B) | Deny events to userspace |
| `scratch` | PERCPU_ARRAY | 1 | `0` | `512B buffer` | Payload parsing scratch space |

## Reconciliation Flow

When an `EgressPolicy` is created or updated:

1. Controller lists pods matching the selector on the local node.
2. For each pod with an IP, updates `pod_policy` map: `pod_ip → policy_id`.
3. Hashes each hostname in `allowedHostnames` and inserts into `policy_hostnames`.
4. Sets the `policy_default_action` for the policy.
5. Discovers veth interfaces via netlink and attaches TC programs (idempotent).
6. Updates CRD status (`enforced: true`, `matchedPods` count).

When a policy is deleted:

1. Removes all `policy_hostnames` entries for the policy ID.
2. Removes `pod_policy` entries pointing to the deleted policy.
3. Removes the `policy_default_action` entry.
4. Flushes all `conntrack` entries to prevent stale cached decisions.

## Hostname Hashing

Both Go and BPF use FNV-1a 64-bit, capped at 32 bytes (`MAX_HOSTNAME_LEN`). This means:

- Hostnames longer than 32 bytes are truncated before hashing.
- The Go implementation (`internal/ebpf/hash.go`) and BPF implementation (`bpf/sni_parser.h`) must produce identical output.
- The `TestFNV1aHash_KnownValues` test guards against drift.

The policy ID is a stable uint32 derived from `FNV-1a(namespace + "/" + name)`.

## Wildcard Matching

Wildcard patterns (`*.example.com`) are stored as their literal FNV-1a hash in the `policy_hostnames` map — no special expansion on the Go side.

On the BPF side, after an exact hash lookup fails, `check_wildcard()` walks the extracted hostname backward through `.` boundaries:

```
Hostname: "api.staging.example.com"
Tries:    *.staging.example.com → *.example.com → *.com
```

Each candidate hash is `FNV-1a('*' + '.suffix')`, which matches the Go-stored hash of `"*.example.com"`. Bounded to 4 domain levels (`MAX_WILDCARD_DEPTH`).

## TC Hook Choice

KubeNanny uses the TC (Traffic Control) hook via TCX — specifically **TCX ingress on the host-side veth**. This is counter-intuitive but correct: a pod sending traffic _out_ through its veth pair appears as _ingress_ on the host side of the veth.

Why TC and not other hooks:

- **Not XDP**: XDP is ingress-only at the physical NIC level — can't inspect per-pod outbound traffic.
- **Not cgroup/skb**: Requires cgroup v2 path management, varies by container runtime.
- **Not socket-level**: Too late for transparent hostname inspection.
- TC gives per-interface full packet access on the outbound path from each pod.

## Security Model

- Runs as **root** (`runAsUser: 0`) with **privileged** security context.
- Capabilities: `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_PERFMON`.
- `rlimit.RemoveMemlock()` called before BPF map creation.
- Required for: BPF syscall, map creation, TC program attachment.
- The distroless runtime image contains only the static binary.
