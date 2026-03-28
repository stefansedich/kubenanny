# Project Guidelines

## Code Style

- Go code follows standard `gofmt` formatting
- BPF C code uses `-O2 -g -Wall -Werror` compiler flags
- Structured logging via `log/slog` with JSON output — no `fmt.Printf` for application logs
- Use `//nolint` sparingly and always with a justification comment

## Architecture

- **eBPF datapath** (`bpf/`): TC egress classifier in C. Packet headers are parsed inline via `sni_parser.h` and `http_parser.h`. Decisions are cached in the LRU `conntrack` map. Deny events are emitted via ringbuf.
- **Go control plane** (`internal/`): controller-runtime reconciler watches `EgressPolicy` CRDs and programs BPF maps. The `internal/ebpf` package owns all BPF lifecycle (load, attach, map CRUD, events).
- **CRD types** (`api/v1alpha1/`): Kubernetes API types with manually written DeepCopy methods in `zz_generated.deepcopy.go`.
- **Single binary DaemonSet**: One binary per node — loads BPF, runs the controller, serves health/metrics.

### Key Design Decisions

- FNV-1a 64-bit hash is used to match hostnames between Go userspace and BPF kernel space. Both implementations **must** produce identical output.
- TC egress hook (not XDP) because we need to inspect outgoing traffic on pod veth interfaces.
- CRDs are in the Helm `crds/` directory (not templates) per Helm v3 convention.

## Build and Test

```bash
make docker/build    # Build Docker image (compiles BPF + Go)
make docker/test     # Run go vet + go test inside Docker
make test            # Run all tests (unit + integration)
make test/unit       # Run unit tests
make test/integration # Run integration tests (requires a deployed cluster)
make dev             # Full local cycle: k3d cluster + build + deploy + integration tests
make helm/lint       # Lint the Helm chart
```

BPF programs are compiled inside Docker (clang/llvm) via `go generate` using `cilium/ebpf/cmd/bpf2go`. The host machine does not need BPF toolchain installed.

## Conventions

- **BPF loop limits**: Never use `#pragma unroll` on loops with more than ~64 iterations. The BPF verifier handles bounded loops natively on kernel 5.3+. Large unrolled loops exceed the 512-byte stack limit.
- **Packet access**: Always bounds-check pointers against `data_end` before dereferencing. For variable-offset access (e.g. `ip->ihl * 4`), recompute pointers from a fixed base (`data + ETH_HLEN + offset`) so the verifier can track them.
- **BPF map structs**: Go-side struct layouts in `internal/ebpf/maps.go` must exactly match C-side structs in `bpf/maps.h` (field order, sizes, padding).
- **Hash consistency**: Any change to `FNV1aHash` in `internal/ebpf/hash.go` must be mirrored in `bpf/sni_parser.h`'s `fnv1a_hash()`, and vice versa. The `TestFNV1aHash_KnownValues` test guards against drift. Wildcard matching in `bpf/egress_filter.c`'s `check_wildcard()` also depends on this — it computes `FNV1a("*" + ".suffix")` which must equal Go's `FNV1aHash([]byte("*.suffix"))`.
- **Wildcard hostnames**: `*.example.com` patterns are matched in BPF by decomposing the extracted hostname at `.` boundaries. `check_wildcard()` (bounded to `MAX_WILDCARD_DEPTH=4` levels) hashes `*` + each suffix and checks the same `policy_hostnames` map. Go side stores `FNV1aHash([]byte("*.example.com"))` — no special expansion needed.
- **Testing**: Pure functions (hash, IP conversion, event parsing, policy hash) must have unit tests. Health endpoints are tested via `httptest`. BPF loading/attachment requires a real kernel and is only testable in Docker or CI. Integration tests in `test/integration/` run against a live k3d cluster with build tag `integration` and verify end-to-end egress filtering (HTTP Host header allow/deny, policy CRUD lifecycle, unlabeled pod bypass, multi-policy isolation, TLS SNI via external endpoints, wildcard hostname patterns). Each integration test creates an isolated namespace with its own pods, services, and policies, and cleans up on completion.
- **Container permissions**: The DaemonSet runs as root (`runAsUser: 0`) with `privileged: true` and `CAP_BPF`/`CAP_SYS_ADMIN` — required for BPF map creation and TC attachment. `rlimit.RemoveMemlock()` is called before loading BPF objects.
