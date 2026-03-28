#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* ── Key/value types ────────────────────────────────────────────── */

/* pod_policy: maps a pod's IPv4 address to a policy ID. */
struct pod_policy_key {
    __be32 pod_ip;
};

struct pod_policy_val {
    __u32 policy_id;
};

/* policy_hostnames: maps (policy_id, hostname_hash) → action.
 * action: 1 = allow, 0 = deny (used only when hostname is explicitly listed).
 */
struct policy_hostname_key {
    __u32 policy_id;
    __u32 _pad;          /* explicit padding — must be zero-initialized */
    __u64 hostname_hash;
};

struct policy_hostname_val {
    __u8 action; /* 1 = allow */
};

/* policy_default_action: fallback action when hostname is not in allowlist. */
struct policy_default_key {
    __u32 policy_id;
};

struct policy_default_val {
    __u8 action; /* 1 = allow, 0 = deny */
};

/* conntrack: caches per-connection allow/deny decision after first packet. */
struct conntrack_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   proto;
    __u8   _pad[3];
};

struct conntrack_val {
    __u8 action; /* 1 = allow, 0 = deny */
};

/* deny_event: sent to userspace via ringbuf on denied connections. */
struct deny_event {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u64  hostname_hash;
    __u64  timestamp_ns;
    __u32  policy_id;
};

/* ── Map definitions ────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct pod_policy_key);
    __type(value, struct pod_policy_val);
} pod_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct policy_hostname_key);
    __type(value, struct policy_hostname_val);
} policy_hostnames SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   struct policy_default_key);
    __type(value, struct policy_default_val);
} policy_default_action SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key,   struct conntrack_key);
    __type(value, struct conntrack_val);
} conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); /* 64 KiB */
} events SEC(".maps");

/* Scratch buffer for payload parsing — avoids packet-pointer verifier issues. */
#define SCRATCH_SIZE 512

struct scratch_buf {
    __u8 data[SCRATCH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_buf);
} scratch SEC(".maps");

#endif /* __MAPS_H__ */
