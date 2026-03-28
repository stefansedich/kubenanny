# BPF Datapath

The BPF datapath is a TC egress classifier that runs in the kernel, attached to pod veth interfaces. It inspects outgoing TCP packets, extracts hostnames from TLS SNI and HTTP Host headers, and enforces hostname-based allow/deny policies.

## Source Files

| File | Description |
|------|-------------|
| `bpf/egress_filter.c` | Main TC program: packet parsing, policy lookup, conntrack, wildcard matching |
| `bpf/maps.h` | BPF map definitions and shared struct layouts |
| `bpf/sni_parser.h` | TLS ClientHello → SNI hostname extraction |
| `bpf/http_parser.h` | HTTP request → Host header extraction |
| `bpf/vmlinux.h` | Minimal kernel type definitions (CO-RE) |

## Packet Processing Pipeline

```
Packet arrives on host-side veth (TCX ingress)
  │
  ├─ Not IPv4 TCP? ──────────────────────────▶ TC_ACT_OK (pass)
  │
  ├─ Source IP not in pod_policy map? ────────▶ TC_ACT_OK (pass)
  │
  ├─ 5-tuple in conntrack? ──────────────────▶ cached action
  │                                              (fast-path)
  │
  ├─ Linearize SKB + copy payload to scratch
  │
  ├─ Parse TLS SNI or HTTP Host header
  │    ├─ Hostname found:
  │    │    ├─ Exact hash match in policy_hostnames? ──▶ ALLOW
  │    │    ├─ Wildcard suffix match? ─────────────────▶ ALLOW
  │    │    └─ No match ───────────────────────────────▶ DENY
  │    │
  │    └─ No hostname extracted:
  │         └─ policy_default_action ──────────────────▶ allow/deny
  │
  └─ Cache decision in conntrack
     Emit deny_event to ringbuf (if denied)
```

## TLS SNI Parsing (`sni_parser.h`)

The parser handles TLS 1.0–1.3 ClientHello messages:

1. **TLS record header** (5 bytes): Checks `content_type == 0x16` (Handshake).
2. **Handshake header** (4 bytes): Checks `type == 0x01` (ClientHello).
3. **Skip fixed fields**: client_version (2B), random (32B).
4. **Variable-length fields**: session_id, cipher_suites, compression_methods — each prefixed with a length.
5. **Extensions iteration**: Bounded loop (max 16 extensions) looking for `type == 0x0000` (SNI).
6. **SNI extraction**: From the SNI extension, reads the `host_name` entry (type 0x00) and hashes it with FNV-1a.

Returns the hostname hash plus the offset and length within the scratch buffer (used for wildcard matching).

### Verifier Considerations

- All buffer access goes through `buf_byte()`, which uses `asm volatile("" : "+r"(off))` to prevent the compiler from eliminating bounds checks.
- Parsing operates on a **scratch buffer** (per-CPU array map), not direct packet pointers — BPF helper calls invalidate packet pointer ranges.
- Loop bounds are constant and verifier-friendly: 16 extensions, 32-byte hostname cap.

## HTTP Host Header Parsing (`http_parser.h`)

1. **Method check**: `is_http_method()` checks the first bytes for `GET `, `POST `, `PUT `, `DELETE `, `HEAD `, or `PATCH `.
2. **Header scan**: Searches the first 32 bytes (`MAX_HTTP_SCAN`) for `\r\nHost: ` (8-byte pattern match with `#pragma unroll`).
3. **Hostname extraction**: Reads bytes after `Host: ` until `\r` or `:` (port separator), capped at 32 bytes.
4. **Hashing**: FNV-1a of the extracted hostname, returning hash, offset, and length.

## Payload Loading Strategy

TCP payload lives in SKB data which may be non-linear (paged) on bridge-port veths. The loading uses a 3-tier approach:

```c
bpf_skb_pull_data(skb, skb->len);    // 1. Linearize paged data

bpf_skb_load_bytes(skb, off, buf, 512);  // 2. Try full 512B
bpf_skb_load_bytes(skb, off, buf, 256);  // 3. Fallback: 256B
for (i = 0; i < 80; i++) ...             // 4. Fallback: direct copy 80B
```

The `payload_len` variable stays constant at `SCRATCH_SIZE` (512) regardless of which path succeeds — this prevents verifier state explosion from tracking different buffer sizes.

## Wildcard Matching (`check_wildcard`)

After an exact hostname hash lookup fails, wildcard matching walks the hostname backward through `.` boundaries:

```
Input:  "api.staging.example.com"
Level 1: hash("*.staging.example.com") → lookup
Level 2: hash("*.example.com")         → lookup
Level 3: hash("*.com")                 → lookup (max depth reached)
```

For each level, the function computes `FNV-1a('*' + '.suffix')` — the same hash that Go stores when the user specifies `"*.example.com"` in their policy.

Bounded to `MAX_WILDCARD_DEPTH = 4` iterations. The inner dot-finding loop is bounded to `MAX_HOSTNAME_LEN = 32`.

## Conntrack Cache

The LRU hash map keyed by 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)` caches allow/deny decisions after the first packet of each connection. This means:

- Only the first data packet triggers full TLS/HTTP parsing.
- Subsequent packets on the same connection hit the early fast-path return.
- The LRU eviction (131,072 entries) automatically handles cleanup of old entries.
- On policy deletion, Go-side code explicitly flushes all conntrack entries.

## Deny Events

When a packet is denied, a `deny_event` struct is submitted to the ringbuf:

```c
struct deny_event {
    __be32 src_ip;        // Source pod IP
    __be32 dst_ip;        // Destination IP
    __be16 src_port;      // Source port
    __be16 dst_port;      // Destination port
    __u64  hostname_hash; // FNV-1a hash of the extracted hostname
    __u64  timestamp_ns;  // Kernel monotonic timestamp
    __u32  policy_id;     // Policy that triggered the deny
};
```

The Go-side `EventReader` consumes these events, logs them via `slog`, and increments Prometheus counters.

## Build Process

BPF programs are compiled via `bpf2go` (cilium/ebpf):

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I../../bpf" egressFilter ../../bpf/egress_filter.c
```

This runs during `go generate` inside the Docker build (which has clang/llvm installed). It produces:
- `egressfilter_bpfel.go` / `egressfilter_bpfeb.go` — Go bindings for both endiannesses
- `egressfilter_bpfel.o` / `egressfilter_bpfeb.o` — Compiled ELF objects

The host machine does not need BPF toolchain installed — compilation happens entirely inside the Docker multi-stage build.

## Key Constants

| Constant | Value | Defined In | Purpose |
|----------|-------|------------|---------|
| `SCRATCH_SIZE` | 512 | `maps.h` | Per-CPU scratch buffer size |
| `MAX_HOSTNAME_LEN` | 32 | `sni_parser.h` | Max hostname bytes hashed |
| `MAX_HTTP_SCAN` | 32 | `http_parser.h` | Bytes scanned for Host header |
| `MAX_WILDCARD_DEPTH` | 4 | `egress_filter.c` | Domain levels for wildcards |
| `PAYLOAD_COPY_MAX` | 80 | `egress_filter.c` | Direct-copy fallback size |
| `FNV_OFFSET_BASIS` | `14695981039346656037` | `sni_parser.h` | FNV-1a 64-bit seed |
| `FNV_PRIME` | `1099511628211` | `sni_parser.h` | FNV-1a 64-bit multiplier |

## Verifier Issues Encountered

During development, four BPF verifier issues were resolved:

1. **Packet pointer invalidation** — BPF helper calls invalidate packet pointer ranges. Fixed by copying payload to a per-CPU scratch buffer via `bpf_skb_load_bytes()`.

2. **1M instruction limit** — Nested loops exceeded the verifier's instruction budget. Fixed by reducing hostname, scan, and extension loop bounds.

3. **Bounds check elimination** — The compiler's inliner proved (from C semantics) that `off` was always in range and removed the bounds check, which the verifier needs to see. Fixed with `asm volatile("" : "+r"(off))`.

4. **Non-linear SKB data** — On bridge-port veths, TCP payload lives in paged fragments. Fixed with hybrid approach: `bpf_skb_pull_data(skb, skb->len)` + 3-tier fallback loading.
