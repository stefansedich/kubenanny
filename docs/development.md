# Development Guide

## Prerequisites

- **Go 1.25+** — the Go toolchain (BPF compilation uses Docker, not the host)
- **Docker** — required for building the Docker image and compiling BPF programs
- **k3d** — for local Kubernetes clusters
- **kubectl** — Kubernetes CLI
- **Helm v3** — for deploying the chart

BPF programs are compiled inside Docker using clang/llvm. You do **not** need a BPF toolchain on your host machine.

## Quick Start

```bash
# Full local dev cycle: create k3d cluster, build, deploy, run integration tests
make dev

# View logs
make k3d/logs

# Tear down
make k3d/delete
```

## Makefile Targets

Run `make help` for a complete, categorized list. Key targets:

### General

| Target | Description |
|--------|-------------|
| `make help` | Show all targets with descriptions |
| `make generate` | Run `go generate` (requires BPF toolchain) |
| `make build` | Cross-compile Go binary for linux/amd64 |
| `make clean` | Remove `bin/` build artifacts |
| `make test` | Run all tests (unit + integration) |
| `make test/unit` | Run unit tests only |
| `make test/integration` | Set up cluster + deploy + run integration tests |
| `make lint` | Run golangci-lint |
| `make dev` | Full local cycle: cluster + build + deploy + test |

### Docker

| Target | Description |
|--------|-------------|
| `make docker/build` | Build Docker image (compiles BPF + Go) |
| `make docker/test` | Run `go vet` + `go test` inside Docker |

### k3d

| Target | Description |
|--------|-------------|
| `make k3d/create` | Create k3d dev cluster (rancher/k3s:v1.31.4-k3s1) |
| `make k3d/delete` | Delete the k3d cluster |
| `make k3d/load` | Build image and import into k3d |
| `make k3d/deploy` | Build, load, Helm install into k3d |
| `make k3d/undeploy` | Helm uninstall + delete CRD |
| `make k3d/logs` | Tail kubenanny DaemonSet logs |

### Helm

| Target | Description |
|--------|-------------|
| `make helm/lint` | Lint the Helm chart |

## Building

### Docker Build (recommended)

```bash
make docker/build
```

This runs a multi-stage Docker build:
1. **Stage 1 (builder)**: Installs clang/llvm, runs `go generate` to compile BPF C → ELF objects via `bpf2go`, then builds the Go binary with `-ldflags="-s -w"`.
2. **Stage 2 (test)**: Runs `go vet` and `go test` (used by `make docker/test`).
3. **Stage 3 (runtime)**: Copies the static binary into `gcr.io/distroless/static-debian12`.

### Local Build

```bash
make build
```

Requires `go generate` to have run first (needs clang). The binary is output to `bin/kubenanny`.

## Testing

### Unit Tests

```bash
make test/unit
```

Runs `go test ./...`. On macOS, packages that depend on BPF-generated code or Linux-specific netlink APIs will fail to compile — this is expected. Use `make docker/test` for full test coverage.

Unit tests cover:
- **Hash functions** — FNV-1a determinism, known values, truncation, case sensitivity, wildcard consistency
- **Event parsing** — `parseDenyEvent` for ringbuf records
- **Map operations** — `ipToU32BE` roundtrip, BPF struct size validation
- **Controller logic** — `policyHash` determinism, collision resistance
- **Health endpoints** — HTTP handler tests via `httptest`
- **Metrics** — Prometheus counter/gauge registration and labeling
- **CRD types** — DeepCopy correctness
- **CLI** — Cobra flag parsing, version command, log level parsing

### Integration Tests

```bash
make test/integration
```

This target is self-contained — it creates a k3d cluster (if not already running), builds and deploys kubenanny, then runs the test suite:

```bash
go test -tags integration -v -count=1 -timeout 10m ./test/integration/
```

Integration tests use the `integration` build tag and run against a live cluster. Each test:
- Creates an isolated namespace.
- Deploys nginx and curl pods.
- Creates/updates/deletes `EgressPolicy` resources.
- Asserts allow/deny behavior via curl.
- Cleans up on completion.

Test files:

| File | Tests |
|------|-------|
| `helpers_test.go` | Shared kubectl wrappers, pod/service factories, assertion helpers |
| `daemonset_test.go` | DaemonSet pod readiness |
| `egress_http_test.go` | HTTP egress allow/deny lifecycle, default action, policy update/delete |
| `egress_https_test.go` | TLS SNI filtering against external endpoints |
| `multi_policy_test.go` | Multiple co-existing policies with different selectors |
| `policy_lifecycle_test.go` | Policy recreate, pod selector scoping |
| `wildcard_test.go` | Wildcard hostname patterns, mixed exact+wildcard policies |

### Docker Tests

```bash
make docker/test
```

Runs `go vet` and `go test` inside the Docker build environment where BPF-generated code and Linux headers are available. This is the most reliable way to run the full unit test suite.

## Project Structure

```
kubenanny/
├── api/v1alpha1/              # CRD type definitions
│   ├── egresspolicy_types.go  # EgressPolicy spec/status
│   ├── groupversion_info.go   # GVK registration
│   └── zz_generated.deepcopy.go
├── bpf/                       # BPF C source
│   ├── egress_filter.c        # Main TC classifier
│   ├── maps.h                 # Map definitions + scratch buffer
│   ├── sni_parser.h           # TLS SNI extraction
│   ├── http_parser.h          # HTTP Host extraction
│   └── vmlinux.h              # Kernel type stubs
├── charts/kubenanny/          # Helm v3 chart
│   ├── crds/                  # CRD YAML (installed by Helm)
│   ├── templates/             # DaemonSet, RBAC, Service, etc.
│   └── values.yaml
├── cmd/kubenanny/             # CLI entry point (Cobra)
├── deploy/                    # Raw K8s manifests (alternative to Helm)
├── docs/                      # Design documentation
├── internal/
│   ├── controller/            # EgressPolicy reconciler
│   ├── ebpf/                  # BPF loader, maps, events, hash
│   ├── metrics/               # Prometheus metrics
│   ├── netns/                 # Pod IP → veth resolution
│   └── server/                # Health/readiness/metrics HTTP
├── test/integration/          # Integration test suite
├── Dockerfile                 # Multi-stage build
├── Makefile                   # Build/test/deploy targets
└── go.mod
```

## Adding a New Hostname Parser

To support a new protocol (e.g., DNS queries):

1. Create `bpf/dns_parser.h` with a `parse_dns_query()` function following the same pattern as `parse_tls_sni()` — takes `(buf, buf_len, &hostname_hash, &host_off, &host_len)`.
2. Call it from `egress_filter.c` after the existing parsers.
3. No Go-side changes needed — the hash and map infrastructure is protocol-agnostic.

## Modifying BPF Maps

When changing BPF map struct layouts:

1. Update the C struct in `bpf/maps.h`.
2. Update the matching Go struct in `internal/ebpf/maps.go` — field order, sizes, and padding must match exactly.
3. Run `make docker/test` to verify struct size assertions in `maps_test.go` still pass.

## Hash Consistency

The FNV-1a hash is implemented in two places that **must stay in sync**:

- **Go**: `internal/ebpf/hash.go` — `FNV1aHash()`
- **BPF**: `bpf/sni_parser.h` — `fnv1a_hash_buf()`

Any change to one requires the same change in the other. The `TestFNV1aHash_KnownValues` test uses pre-computed reference hashes to detect drift. The wildcard matching in BPF (`check_wildcard()`) also depends on this — it computes `FNV-1a("*" + ".suffix")` which must equal Go's `FNV1aHash([]byte("*.suffix"))`.
