# Plan: KubeNanny — eBPF-based Kubernetes Egress Hostname Filter

## Current Status

### What's Done — All Phases Complete
- **Phase 1 (Scaffolding)**: Complete — Go module, Dockerfile (multi-stage with clang/llvm), Makefile, Helm chart, k3d dev targets
- **Phase 2 (eBPF Programs)**: Complete — BPF TC egress classifier loads and runs successfully. Scratch-buffer approach for payload parsing. Verifier issues resolved (see below).
- **Phase 3 (Go Userspace)**: Complete — loader, map manager, event reader, FNV-1a hash, veth resolver
- **Phase 4 (K8s Integration)**: Complete — EgressPolicy CRD, controller-runtime reconciler, DeepCopy methods, RBAC
- **Phase 5 (Observability)**: Complete — Prometheus metrics, slog JSON logging, health/readiness endpoints on `:9090`
- **Phase 6 (Deployment)**: Complete — Helm chart in `charts/kubenanny/`, CRD in `crds/` dir, DaemonSet with privileged + CAP_BPF/SYS_ADMIN

### Tests
- 40+ unit tests across all Go packages — all passing via `make docker-test`
- Packages tested: hash, events, maps (ipToU32BE, struct sizes), controller (policyHash), metrics, health (httptest), CRD types (DeepCopy), CLI (Cobra flags, version command, log level parsing)
- Integration test suite in `test/integration/` (build tag `integration`) — split into focused files:
  - **helpers_test.go**: Shared test infrastructure — kubectl wrappers, resource factories, polling/curl helpers
  - **daemonset_test.go**: `TestDaemonSetReady` — verifies all kubenanny DaemonSet pods are Running
  - **egress_http_test.go**: `TestEgressFiltering` (full lifecycle — baseline, policy create, allow/deny, update, delete), `TestDefaultActionAllow`
  - **egress_https_test.go**: `TestExternalHTTPS` — TLS SNI filtering against real external endpoints with retry logic
  - **multi_policy_test.go**: `TestMultiplePolicies` — two policies targeting different pod selectors coexist correctly
  - **policy_lifecycle_test.go**: `TestPolicyRecreate` (delete + recreate with new hostnames), `TestPolicyScopedToPodSelector` (unrelated pods unaffected)
  - **wildcard_test.go**: `TestWildcardHostname` — wildcard patterns (`*.example.com`) allow subdomains while denying non-matching and exact-domain hostnames: `go test -tags integration -v -timeout 15m ./test/integration/`
- BPF program loads successfully in k3d (kernel 6.12.72-linuxkit); both DaemonSet pods running `1/1 Ready`

### BPF Verifier Issues (Resolved)

Four verifier issues were encountered and resolved during development:

1. **Packet pointer invalidation**: BPF helper calls (`bpf_map_lookup_elem`, etc.) invalidate packet pointer ranges, causing `invalid access to packet, off=0 size=1, R4(r=0)` errors when parsers tried to read via packet pointers after helpers. **Fixed by copying TCP payload into a 512-byte per-CPU PERCPU_ARRAY scratch buffer via `bpf_skb_load_bytes()`, then parsing from the map value instead of direct packet pointers.**

2. **Instruction complexity limit (1M insns)**: The verifier unrolls every loop iteration as a separate state. With `MAX_HOSTNAME_LEN=128`, nested hash loops × parser loops exceeded 1M instructions. **Fixed by reducing `MAX_HOSTNAME_LEN` to 32, `MAX_HTTP_SCAN` to 32, SNI extension loop to 16.**

3. **Compiler-vs-verifier bounds disagreement**: `buf_byte()` had `if (off >= SCRATCH_SIZE) return 0` to bound map value accesses, but the compiler's inliner proved (from C semantics) that `off` was always in range and **eliminated the bounds check**. The BPF verifier, lacking this proof, rejected with `off=519`. **Fixed by adding `asm volatile("" : "+r"(off))` before the bounds check — this forces the compiler to forget `off`'s range, keeping the check in the emitted BPF bytecode for the verifier to see.**

4. **Non-linear SKB payload (variable-length `bpf_skb_load_bytes`)**: On bridge-port veths, TCP payload lives in non-linear/paged SKB fragments. Variable-length `bpf_skb_load_bytes` caused `R4 min value is negative` verifier errors, and large copy loops exceeded 1M instructions. **Fixed with a hybrid approach**: `bpf_skb_pull_data(skb, skb->len)` to linearize paged data, then 3-tier constant-size `bpf_skb_load_bytes` fallback (512→256→80 bytes). `payload_len` remains constant at `SCRATCH_SIZE` for all code paths, avoiding verifier state explosion from variable-length tracking.

### Fixes Applied During Development
| Issue | Fix |
|-------|-----|
| BPF stack overflow (#pragma unroll on 128-iter loops) | Removed `#pragma unroll` from large loops |
| BPF packet pointer invalidation after helpers | Scratch buffer via `bpf_skb_load_bytes()` into PERCPU_ARRAY map |
| BPF verifier 1M instruction limit | Reduced MAX_HOSTNAME_LEN=32, MAX_HTTP_SCAN=32, ext loop=16 |
| BPF bounds check eliminated by compiler | `asm volatile("" : "+r"(off))` barrier before `if (off >= SCRATCH_SIZE)` |
| DeepCopy missing | Manually wrote `zz_generated.deepcopy.go` |
| go:generate path | Fixed to `../../bpf/egress_filter.c` |
| Dockerfile golang version | `golang:1.25-bookworm` |
| CRD installation failure | Moved to `crds/` dir per Helm v3 convention |
| Memlock error on BPF load | Added `rlimit.RemoveMemlock()` + root user + distroless:latest |
| Health probe port mismatch | Changed `healthPort` from 8081 to 9090 in values.yaml |
| Struct padding mismatch (policyHostnameKey) | Added explicit `_ uint32` padding in Go struct to match C struct alignment |
| TC never attached to veths | Added `attachVeths()` call in reconcile loop discovering veth interfaces by name prefix |
| TC direction wrong (egress→ingress) | Changed `AttachTCXEgress` → `AttachTCXIngress` for host-side veths (pod→host = ingress) |
| IP byte order mismatch | Used `binary.NativeEndian` in `ipToU32BE()` for raw network-order bytes |
| controller-runtime logger not configured | Added `ctrl.SetLogger(logr.FromSlogHandler(...))` in main |
| Non-linear SKB payload on bridge-port veths | Hybrid payload loading: `bpf_skb_pull_data(skb, skb->len)` + 3-tier `bpf_skb_load_bytes` fallback (512→256→80 bytes) |
| `bpf_skb_pull_data(skb, 0)` does nothing | Changed to `bpf_skb_pull_data(skb, skb->len)` — len=0 only ensures head is writable |
| DeletePolicy left stale pod_policy entries | Added pod_policy iteration/deletion + full conntrack flush in `DeletePolicy()` |
| TLS payload size gap (ClientHello 80-512 bytes) | Added intermediate `bpf_skb_load_bytes(256)` attempt between 512 and 80-byte fallback |
| Reconcile storm from status update conflict | Only update status when `enforced` changes from false to true; properly distinguish NotFound from other errors in `r.Get` |
| `DeletePolicy` panic on unexported struct field | Changed `_ uint32` padding to exported `Pad uint32` — `encoding/binary.Decode` panics on unexported fields during map iteration |

### Refactoring Applied
| Change | Details |
|--------|---------|
| Cobra CLI framework | Replaced flat `main()` with `spf13/cobra` root command + `version` subcommand. Added `--health-addr`, `--probe-addr`, `--log-level`, `--node-name` flags. |
| Node name injection | Moved `os.Getenv("NODE_NAME")` from controller constructor to CLI flag default — configurable via `--node-name` while remaining backward compatible |
| Idiomatic error wrapping | Fixed `%+w` → `%w` in loader.go; replaced `err != http.ErrServerClosed` with `errors.Is()` |
| Dead code cleanup | Removed unused `_ = name` / `_ = data` variable suppressions in netns/resolver.go; removed unused `os.ReadFile` call |
| Write error handling | Explicitly discarded `http.ResponseWriter.Write` returns with `_, _` in health handlers |
| Build flags | Added `-ldflags="-s -w"` to Makefile and Dockerfile for smaller binaries |
| Integration test split | Replaced monolithic `integration_test.go` with 6 focused files: helpers, daemonset, egress HTTP, egress HTTPS, multi-policy, policy lifecycle |
| New integration tests | Added `TestPolicyRecreate` (delete + recreate with different hostnames) and `TestPolicyScopedToPodSelector` (pod selector isolation) |
| Wildcard hostname matching | BPF `check_wildcard()` decomposes hostnames by `.` separators and checks `*.suffix` hashes against `policy_hostnames` map (bounded to 4 domain depths). Parsers now return hostname offset+length. CRD updated to document wildcard support. Integration test (`TestWildcardHostname`) covers subdomain allow, non-match deny, exact-domain deny, and mixed exact+wildcard policies. |
| New unit tests | Added CLI tests (parseLogLevel, version cmd, flags, help), hash truncation tests, event parsing edge cases, BPF struct size validation, IP roundtrip test, health metrics endpoint test, additional policyHash tests |

## TL;DR

KubeNanny is a Go DaemonSet that uses eBPF (cilium/ebpf) to filter pod egress traffic by hostname. It extracts hostnames via TLS SNI (ClientHello) for HTTPS and HTTP Host header for plain HTTP, then enforces allow/deny policies defined via a Kubernetes CRD. Denied connections receive TCP RST / ICMP unreachable. Observability via Prometheus metrics and structured logging.

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│  Kubernetes API Server                          │
│  ┌───────────────────────────────────────────┐  │
│  │  EgressPolicy CRD                        │  │
│  │  - namespace scoped                       │  │
│  │  - pod selector (labels)                  │  │
│  │  - allowedHostnames []string (glob/exact) │  │
│  │  - defaultAction: deny | allow            │  │
│  └───────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────┘
                       │ watch/reconcile
                       ▼
┌─────────────────────────────────────────────────┐
│  KubeNanny DaemonSet (one per node)             │
│  ┌─────────────────────────────────────────┐    │
│  │  Go Controller (controller-runtime)     │    │
│  │  - Reconciles EgressPolicy CRDs         │    │
│  │  - Watches Pod events for label matches │    │
│  │  - Populates eBPF maps with policy data │    │
│  └──────────────┬──────────────────────────┘    │
│                 │ loads & configures             │
│                 ▼                                │
│  ┌─────────────────────────────────────────┐    │
│  │  eBPF Programs (TC egress hook)         │    │
│  │                                         │    │
│  │  1. SNI Parser: TC classifier on egress │    │
│  │     - Parses TCP SYN+data for TLS       │    │
│  │       ClientHello → extracts SNI        │    │
│  │     - Parses HTTP requests →            │    │
│  │       extracts Host header              │    │
│  │  2. Policy Enforcer:                    │    │
│  │     - Looks up hostname in BPF map      │    │
│  │     - TC_ACT_OK (allow) or             │    │
│  │       TC_ACT_SHOT (deny) + RST inject  │    │
│  │                                         │    │
│  │  BPF Maps:                              │    │
│  │  - pod_policy: {pod_ip → policy_id}     │    │
│  │  - policy_hostnames: {policy_id,        │    │
│  │    hostname_hash → allow/deny}          │    │
│  │  - events: ringbuf for deny events      │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
│  ┌─────────────────────────────────────────┐    │
│  │  Metrics & Logging                      │    │
│  │  - Prometheus: denied/allowed counters  │    │
│  │  - Structured logs (zerolog/slog)       │    │
│  │  - Ringbuf reader for deny events       │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

## Decisions

- **Hostname extraction**: SNI from TLS ClientHello + Host header from plain HTTP (both parsed in eBPF at TC egress hook)
- **eBPF hook point**: TC (Traffic Control) egress classifier via TCX — chosen over XDP (ingress-only), cgroup/skb (requires cgroup v2 path management), or socket-level hooks. TC egress gives full packet access on the outbound path per-interface.
- **Library**: cilium/ebpf v0.21.0 with bpf2go for compile-time BPF object embedding
- **CRD**: Namespace-scoped `EgressPolicy` with pod label selectors and hostname allowlists
- **Denied traffic**: TC_ACT_SHOT to drop the packet + ringbuf deny events to userspace
- **Non-TLS/non-HTTP traffic**: Configurable per policy (`defaultAction: deny` blocks all non-inspectable egress; `defaultAction: allow` permits it)
- **Go module**: `github.com/stefansedich/kubenanny`
- **K8s version**: 1.31+ (k3d v1.31.4-k3s1 for dev)
- **Observability**: Prometheus metrics + structured logs (slog JSON from stdlib)
- **Hostname hashing**: FNV-1a 64-bit, capped at 32 bytes (MAX_HOSTNAME_LEN). Both Go and BPF-side implementations must match exactly.
- **Payload parsing**: `bpf_skb_load_bytes()` copies TCP payload into a 512-byte per-CPU scratch buffer (PERCPU_ARRAY map), then parsers operate on the buffer — avoids packet pointer invalidation after BPF helper calls.
- **Connection caching**: LRU conntrack map (131072 entries) keyed by 5-tuple caches allow/deny decision after first packet.
- **Container runtime**: Runs as root with `privileged: true` + capabilities `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_PERFMON`. `rlimit.RemoveMemlock()` called before loading BPF objects.
- **Deployment**: Helm v3 chart with CRDs in `crds/` directory. Single binary DaemonSet per node.

## Steps

### Phase 1: Project Scaffolding

1. **Initialize Go module and project structure**
   - `go mod init github.com/stefansedich/kubenanny`
   - Create directory layout (see below)
   - Add Makefile with targets: `generate`, `build`, `docker-build`, `test`, `lint`
   - Add Dockerfile (multi-stage: clang/llvm for BPF compilation, then Go build, then distroless/static runtime)

2. **Set up BPF build toolchain**
   - Add `//go:generate go tool bpf2go ...` directives (cilium/ebpf v0.21+ style)
   - Create `bpf/` directory with BPF C source and common headers (vmlinux.h via bpftool, bpf_helpers.h)
   - Verify bpf2go generates `*_bpfel.go`, `*_bpfeb.go`, and `.o` files

### Phase 2: eBPF Programs (Core Engine)

3. **Implement TC egress classifier BPF program** — `bpf/egress_filter.c`
   - Parse Ethernet → IP → TCP headers
   - For TCP port 443: parse TLS record layer → ClientHello → extract SNI extension
   - For TCP port 80: parse HTTP request line → extract `Host:` header
   - Look up source IP in `pod_policy` map (BPF_MAP_TYPE_HASH: key=`__be32` pod IP, value=`u32` policy_id)
   - Look up hostname hash in `policy_hostnames` map (BPF_MAP_TYPE_HASH: key=`{policy_id, hostname_hash}`, value=`u8` action)
   - Return `TC_ACT_OK` or `TC_ACT_SHOT`
   - Emit deny events to `events` ringbuf map

4. **SNI parsing in BPF** — `bpf/sni_parser.h` ✅
   - Parse TLS record header (content_type=0x16, version)
   - Parse Handshake header (type=0x01 for ClientHello)
   - Skip session_id, cipher_suites, compression_methods
   - Iterate extensions to find SNI extension (type=0x0000) — bounded to 16 iterations
   - Extract server_name bytes (bounded to MAX_HOSTNAME_LEN=32 bytes)
   - Hash the hostname (FNV-1a 64-bit via `fnv1a_hash_buf`)
   - **Implementation note**: Parsing operates on a scratch buffer (not direct packet pointers) to avoid verifier issues with helper calls invalidating packet range. `buf_byte()` helper masks access via `off & (SCRATCH_SIZE - 1)`.

5. **HTTP Host header parsing in BPF** — `bpf/http_parser.h` ✅
   - Check for "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH " at buffer start via `is_http_method()`
   - Scan for `\r\nHost: ` in first MAX_HTTP_SCAN=32 bytes (8-byte marker match with `#pragma unroll`)
   - Extract hostname until `\r` or `:` (strip port), bounded to MAX_HOSTNAME_LEN=32 bytes
   - Hash and look up same as SNI path

6. **Write BPF map definitions** — shared between BPF C and Go userspace
   - `pod_policy` — HASH map, max_entries configurable (default 65536)
   - `policy_hostnames` — HASH map, max_entries configurable (default 65536)
   - `policy_default_action` — HASH map, key=policy_id, value=default action (allow/deny)
   - `events` — RINGBUF map for denied connection events to userspace

### Phase 3: Go Userspace Daemon

7. **BPF loader and lifecycle manager** — `internal/ebpf/loader.go`
   - Load compiled BPF objects via bpf2go-generated code
   - Attach TC egress classifier to specified network interfaces (veth pairs for pods)
   - Use `cilium/ebpf/link` package for TC attachment
   - Manage lifecycle: attach on pod creation, detach on pod deletion
   - Interface discovery: watch for veth interfaces corresponding to target pods (via `/sys/class/net/` or netlink)

8. **Map manager** — `internal/ebpf/maps.go`
   - CRUD operations on BPF maps from Go userspace
   - `UpdatePodPolicy(podIP, policyID)` / `DeletePodPolicy(podIP)`
   - `UpdatePolicyHostnames(policyID, hostnames []string)` / `DeletePolicy(policyID)`
   - Hostname hashing in Go (must match BPF-side hash function exactly)

9. **Event reader** — `internal/ebpf/events.go`
   - Read from ringbuf map using `cilium/ebpf/ringbuf`
   - Decode deny events (source IP, dest IP, dest port, hostname hash, timestamp)
   - Feed into metrics and logging pipeline

### Phase 4: Kubernetes Integration

10. **Define CRD** — `api/v1alpha1/egresspolicy_types.go`
    - Group: `policy.kubenanny.io`, Version: `v1alpha1`, Kind: `EgressPolicy`
    - Spec fields: `podSelector` (metav1.LabelSelector), `allowedHostnames` ([]string), `defaultAction` (enum: allow/deny)
    - Status fields: `enforced` (bool), `matchedPods` (int), `conditions`
    - Generate with controller-gen (deepcopy, CRD manifests, RBAC)

11. **Implement controller** — `internal/controller/egresspolicy_controller.go`
    - Use controller-runtime (sigs.k8s.io/controller-runtime)
    - Watch `EgressPolicy` and `Pod` resources
    - On reconcile:
      a. List pods matching selector on this node (filter by `spec.nodeName`)
      b. For each matched pod: get pod IP, update `pod_policy` BPF map
      c. Hash allowed hostnames, update `policy_hostnames` BPF map
      d. Attach TC program to pod's veth interface if not already attached
    - On policy delete: clean up BPF maps and detach TC programs
    - On pod delete: remove from `pod_policy` map

12. **Pod-to-veth resolution** — `internal/netns/resolver.go`
    - Given a pod IP or container ID, find the corresponding host-side veth interface
    - Options: parse `/sys/class/net/*/ifindex` + netlink, or use CNI-specific approaches
    - Alternatively: attach TC to the node's primary interface and filter by source IP (simpler but less granular)
    - **Recommended for MVP**: Attach to all veth interfaces, use source IP matching in BPF (avoids complex per-pod attachment logic)

### Phase 5: Observability & Operations

13. **Prometheus metrics** — `internal/metrics/metrics.go`
    - `kubenanny_egress_allowed_total{namespace, pod, hostname}` counter
    - `kubenanny_egress_denied_total{namespace, pod, hostname}` counter
    - `kubenanny_policy_count` gauge
    - `kubenanny_monitored_pods` gauge
    - `kubenanny_bpf_errors_total` counter
    - Expose on `:9090/metrics`

14. **Structured logging** — use `log/slog` (stdlib)
    - Log policy reconciliation events
    - Log denied connections (from ringbuf events)
    - Log BPF program attach/detach events

15. **Health endpoints** — `internal/server/health.go`
    - `/healthz` — liveness (process alive)
    - `/readyz` — readiness (BPF programs loaded, connected to API server)

### Phase 6: Deployment Manifests

16. **Helm chart or Kustomize manifests** — `deploy/`
    - DaemonSet with `hostNetwork: true`, `privileged` security context (required for eBPF)
    - ServiceAccount + ClusterRole + ClusterRoleBinding (watch pods, egresspolicies)
    - CRD manifest (generated by controller-gen)
    - Prometheus ServiceMonitor (optional)
    - Example `EgressPolicy` resource

## Project Directory Structure (Actual)

```
kubenanny/
├── PLAN.md
├── README.md
├── AGENTS.md
├── Makefile
├── Dockerfile
├── go.mod
├── go.sum
├── cmd/
│   └── kubenanny/
│       ├── main.go                    # Cobra CLI: root cmd + version, flags
│       └── main_test.go              # CLI flag/command tests
├── api/
│   └── v1alpha1/
│       ├── egresspolicy_types.go      # CRD type definitions
│       ├── groupversion_info.go       # GVK registration
│       ├── types_test.go              # DeepCopy tests
│       └── zz_generated.deepcopy.go   # Manually written
├── bpf/
│   ├── vmlinux.h                      # Minimal kernel types (CO-RE)
│   ├── egress_filter.c                # Main TC egress BPF program
│   ├── sni_parser.h                   # TLS ClientHello SNI extraction (scratch-buffer)
│   ├── http_parser.h                  # HTTP Host header extraction (scratch-buffer)
│   └── maps.h                         # Shared map defs + per-CPU scratch buffer
├── internal/
│   ├── ebpf/
│   │   ├── loader.go                  # BPF load/attach + VerifierError logging
│   │   ├── maps.go                    # BPF map CRUD operations
│   │   ├── maps_test.go              # ipToU32BE tests
│   │   ├── events.go                  # Ringbuf event reader
│   │   ├── events_test.go            # parseDenyEvent tests
│   │   ├── hash.go                    # FNV-1a hash (maxHostnameLen=32)
│   │   └── hash_test.go              # Hash consistency tests
│   ├── controller/
│   │   ├── egresspolicy_controller.go # Reconciler for EgressPolicy + Pod
│   │   └── egresspolicy_controller_test.go # policyHash tests
│   ├── netns/
│   │   └── resolver.go               # Pod IP → veth interface resolution
│   ├── metrics/
│   │   ├── metrics.go                 # Prometheus metrics definitions
│   │   └── metrics_test.go           # Metric registration/increment tests
│   └── server/
│       ├── health.go                  # Health/readiness on :9090
│       └── health_test.go            # httptest-based tests
├── charts/
│   └── kubenanny/
│       ├── Chart.yaml
│       ├── README.md
│       ├── values.yaml                # healthPort=9090, privileged, root
│       ├── crds/
│       │   └── egresspolicies.policy.kubenanny.io.yaml
│       └── templates/
│           ├── _helpers.tpl
│           ├── daemonset.yaml
│           ├── rbac.yaml
│           ├── serviceaccount.yaml
│           ├── service-metrics.yaml
│           └── servicemonitor.yaml
├── deploy/
│   ├── crds/
│   │   └── policy.kubenanny.io_egresspolicies.yaml
│   ├── daemonset.yaml
│   ├── rbac.yaml
│   ├── example-policy.yaml
│   └── test-pod.yaml
├── test/
│   └── integration/
│       ├── helpers_test.go            # Shared kubectl/resource/curl helpers
│       ├── daemonset_test.go          # DaemonSet readiness check
│       ├── egress_http_test.go        # HTTP egress filtering + default action tests
│       ├── egress_https_test.go       # HTTPS/TLS SNI filtering tests
│       ├── multi_policy_test.go       # Multiple co-existing policies test
│       ├── policy_lifecycle_test.go   # Policy recreate + pod selector scoping tests
│       └── wildcard_test.go           # Wildcard hostname pattern matching tests
└── hack/
    └── update-codegen.sh
```

## Relevant Files & Patterns to Reuse

- `cilium/ebpf/examples/tcx/` — Reference for TC program structure, bpf2go usage, `//go:generate` directives
- `cilium/ebpf/examples/cgroup_skb/` — Reference for packet counting BPF program
- `cilium/ebpf/examples/ringbuffer/` — Reference for ringbuf event reading pattern
- `cilium/ebpf/link` package — For TC attach/detach APIs
- `sigs.k8s.io/controller-runtime` — Controller framework (Manager, Reconciler, Client patterns)
- `sigs.k8s.io/controller-runtime/pkg/builder` — Simple controller setup with `For()`, `Watches()`

## Verification

1. **Unit tests**: BPF map operations, hostname hashing consistency (Go hash == BPF hash), controller reconciliation logic (envtest)
2. **Integration tests**: Load BPF programs in a test network namespace, send TLS ClientHello packets, verify SNI extraction and filtering via TC
3. **Manual testing in Kind/minikube**:
   - Deploy kubenanny DaemonSet
   - Create an EgressPolicy allowing `api.github.com`
   - From a matched pod: `curl https://api.github.com` should succeed
   - From a matched pod: `curl https://evil.example.com` should be rejected (connection reset)
   - From a matched pod: `curl http://httpbin.org/get` should be rejected if not in allowlist
   - Verify Prometheus metrics show denied/allowed counters
4. **BPF verifier**: Ensure all BPF programs pass the kernel verifier (test in CI with a real kernel, e.g., via GitHub Actions with a VM runner or `vimto`)
5. **Lint**: `golangci-lint run`, `clang-format` for BPF C code

## Further Considerations

1. ~~**Wildcard hostname matching**~~: **Implemented.** `*.example.com` patterns are supported natively in BPF. On the Go side, wildcard patterns are stored as `FNV1aHash("*.example.com")` — no special handling needed. On the BPF side, after an exact hash lookup fails, `check_wildcard()` iterates through the hostname's `.` separators, computing `FNV1a("*" + ".suffix")` at each level (bounded to 4 domain depths), and checks the same `policy_hostnames` map. No userspace fallback or extra maps required.

2. ~~**Connection tracking for non-first-packet decisions**~~: **Implemented.** LRU conntrack map (131072 entries) keyed by 5-tuple caches allow/deny after first packet. Flushed on policy deletion.

3. ~~**Performance impact**~~: **Implemented.** Conntrack fast-path returns cached decisions before any payload linearization or parsing. Only first packets of new connections go through the full parser chain.
