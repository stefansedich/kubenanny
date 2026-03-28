// +build ignore

/*
 * egress_filter.c — TC egress classifier for hostname-based egress filtering.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "sni_parser.h"
#include "http_parser.h"

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

#define ETH_HLEN      14
#define IP_MIN_HLEN   20
#define TCP_MIN_HLEN  20

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ACTION_DENY  0
#define ACTION_ALLOW 1

/* Maximum number of domain levels to try for wildcard matching.
 * e.g. for "a.b.example.com" we try *.b.example.com, *.example.com, *.com */
#define MAX_WILDCARD_DEPTH 4

/*
 * Wildcard matching uses bpf_loop() so the verifier analyses each callback
 * body exactly once, regardless of iteration count.  This keeps the total
 * verified-state count low enough to stay under the 1 M instruction limit.
 */

/* ---- find-dot callback ------------------------------------------------- */
struct find_dot_ctx {
    const __u8 *buf;
    __u32 cur_off;
    __u32 cur_len;
    __u32 dot_rel;
    int   found_dot;
};

static long find_dot_cb(__u32 idx, struct find_dot_ctx *ctx)
{
    if (idx >= ctx->cur_len)
        return 1;
    if (buf_byte(ctx->buf, ctx->cur_off + idx) == '.') {
        ctx->dot_rel  = idx;
        ctx->found_dot = 1;
        return 1;
    }
    return 0;
}

/* ---- hash-suffix callback ---------------------------------------------- */
struct hash_ctx {
    const __u8 *buf;
    __u32 suffix_off;
    __u32 suffix_len;
    __u64 hash;
};

static long hash_suffix_cb(__u32 idx, struct hash_ctx *ctx)
{
    if (idx >= ctx->suffix_len)
        return 1;
    ctx->hash ^= (__u64)buf_byte(ctx->buf, ctx->suffix_off + idx);
    ctx->hash *= FNV_PRIME;
    return 0;
}

/* ---- per-depth callback ------------------------------------------------ */
struct wildcard_ctx {
    const __u8 *buf;
    __u32 cur_off;
    __u32 cur_len;
    __u32 policy_id;
    int   result;
};

static long wildcard_depth_cb(__u32 idx, struct wildcard_ctx *ctx)
{
    if (ctx->result == ACTION_ALLOW)
        return 1;

    /* Find the next '.' */
    struct find_dot_ctx fd = {
        .buf       = ctx->buf,
        .cur_off   = ctx->cur_off,
        .cur_len   = ctx->cur_len,
        .dot_rel   = 0,
        .found_dot = 0,
    };
    bpf_loop(MAX_HOSTNAME_LEN, find_dot_cb, &fd, 0);
    if (!fd.found_dot)
        return 1;

    __u32 suffix_off = ctx->cur_off + fd.dot_rel;
    __u32 suffix_len = ctx->cur_len - fd.dot_rel;

    /* Compute FNV-1a("*" + suffix) */
    struct hash_ctx hc = {
        .buf        = ctx->buf,
        .suffix_off = suffix_off,
        .suffix_len = suffix_len,
        .hash       = FNV_OFFSET_BASIS,
    };
    hc.hash ^= (__u64)'*';
    hc.hash *= FNV_PRIME;
    bpf_loop(MAX_HOSTNAME_LEN - 1, hash_suffix_cb, &hc, 0);

    /* Map lookup */
    struct policy_hostname_key ph_key = {
        .policy_id     = ctx->policy_id,
        .hostname_hash = hc.hash,
    };
    struct policy_hostname_val *ph_val =
        bpf_map_lookup_elem(&policy_hostnames, &ph_key);
    if (ph_val && ph_val->action == ACTION_ALLOW) {
        ctx->result = ACTION_ALLOW;
        return 1;
    }

    ctx->cur_off = suffix_off + 1;
    ctx->cur_len = suffix_len - 1;
    if (ctx->cur_len == 0)
        return 1;

    return 0;
}

/*
 * check_wildcard — try *.suffix patterns against the policy_hostnames map.
 *
 * For hostname "api.staging.example.com", tries:
 *   1. hash("*.staging.example.com") → lookup
 *   2. hash("*.example.com")         → lookup
 *   3. hash("*.com")                 → lookup
 *
 * Returns ACTION_ALLOW if a wildcard match is found, -1 otherwise.
 */
static __always_inline int check_wildcard(const __u8 *buf, __u32 buf_len,
                                           __u32 name_off, __u32 name_len,
                                           __u32 policy_id)
{
    struct wildcard_ctx ctx = {
        .buf       = buf,
        .cur_off   = name_off,
        .cur_len   = name_len,
        .policy_id = policy_id,
        .result    = -1,
    };
    bpf_loop(MAX_WILDCARD_DEPTH, wildcard_depth_cb, &ctx, 0);
    return ctx.result;
}

static __always_inline void emit_deny_event(__be32 src_ip, __be32 dst_ip,
                                             __be16 src_port, __be16 dst_port,
                                             __u64 hostname_hash, __u32 policy_id)
{
    struct deny_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->hostname_hash = hostname_hash;
    evt->policy_id = policy_id;
    evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline int decide_and_cache(struct conntrack_key *ct_key,
                                             __u8 action,
                                             __be32 src_ip, __be32 dst_ip,
                                             __be16 src_port, __be16 dst_port,
                                             __u64 hostname_hash, __u32 policy_id)
{
    struct conntrack_val ct_val = { .action = action };
    bpf_map_update_elem(&conntrack, ct_key, &ct_val, BPF_ANY);

    if (action == ACTION_ALLOW)
        return TC_ACT_OK;

    emit_deny_event(src_ip, dst_ip, src_port, dst_port, hostname_hash, policy_id);
    return TC_ACT_SHOT;
}

SEC("tc")
int egress_filter(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ── ETH + min IP bounds check (34 bytes) ──────────────────── */
    if (data + ETH_HLEN + IP_MIN_HLEN > data_end)
        return TC_ACT_OK;

    if (*(__be16 *)(data + 12) != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    __u8 ip_byte0 = *(__u8 *)(data + ETH_HLEN);
    __u32 ip_hdr_len = (__u32)(ip_byte0 & 0x0F) * 4;
    if (ip_hdr_len < IP_MIN_HLEN || ip_hdr_len > 60)
        return TC_ACT_OK;

    if (*(__u8 *)(data + ETH_HLEN + 9) != IPPROTO_TCP)
        return TC_ACT_OK;

    __be32 src_ip = *(__be32 *)(data + ETH_HLEN + 12);
    __be32 dst_ip = *(__be32 *)(data + ETH_HLEN + 16);

    /* ── Pod policy lookup ─────────────────────────────────────── */
    struct pod_policy_key pp_key = { .pod_ip = src_ip };
    struct pod_policy_val *pp_val = bpf_map_lookup_elem(&pod_policy, &pp_key);
    if (!pp_val)
        return TC_ACT_OK;

    __u32 policy_id = pp_val->policy_id;

    /* ── Re-validate packet & parse TCP ────────────────────────── */
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    if (data + ETH_HLEN + ip_hdr_len + TCP_MIN_HLEN > data_end)
        return TC_ACT_OK;

    void *tcp = data + ETH_HLEN + ip_hdr_len;
    __be16 src_port = *(__be16 *)(tcp + 0);
    __be16 dst_port = *(__be16 *)(tcp + 2);
    __u8 doff_byte  = *(__u8 *)(tcp + 12);
    __u32 tcp_hdr_len = (__u32)(doff_byte >> 4) * 4;
    if (tcp_hdr_len < TCP_MIN_HLEN || tcp_hdr_len > 60)
        return TC_ACT_OK;

    /* ── Conntrack fast-path ───────────────────────────────────── */
    struct conntrack_key ct_key = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = IPPROTO_TCP,
    };

    struct conntrack_val *ct_val = bpf_map_lookup_elem(&conntrack, &ct_key);
    if (ct_val) {
        if (ct_val->action == ACTION_ALLOW)
            return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    /* ── Linearize and copy payload to scratch buffer ─────────── */
    __u32 payload_off = ETH_HLEN + ip_hdr_len + tcp_hdr_len;

    /* Linearize non-linear (paged) SKB data so both bpf_skb_load_bytes
     * and direct access work on bridge-port veths.  Must pass skb->len
     * (not 0) because bpf_skb_pull_data(skb, 0) only ensures the
     * current linear head is writable — it does NOT pull paged data. */
    bpf_skb_pull_data(skb, skb->len);
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    if (data + payload_off + 1 > data_end)
        return TC_ACT_OK;

    __u32 zero = 0;
    struct scratch_buf *sb = bpf_map_lookup_elem(&scratch, &zero);
    if (!sb)
        return TC_ACT_OK;

    /* Try full-size load first (large TLS ClientHellos).  Fall back to
     * 256 bytes (covers SNI in medium-sized ClientHellos), then to a
     * bounded direct-copy loop for small payloads (HTTP GET ~80 bytes).
     * payload_len stays SCRATCH_SIZE in all paths so the downstream
     * parsers see a constant buf_len — this avoids extra verifier states. */
    if (bpf_skb_load_bytes(skb, payload_off, sb->data, SCRATCH_SIZE) < 0) {
        if (bpf_skb_load_bytes(skb, payload_off, sb->data, 256) < 0) {
            __builtin_memset(sb->data, 0, SCRATCH_SIZE);
            __u8 *src = (__u8 *)(data + payload_off);
#define PAYLOAD_COPY_MAX 80
            for (__u32 i = 0; i < PAYLOAD_COPY_MAX; i++) {
                if (src + i + 1 > (__u8 *)data_end)
                    break;
                sb->data[i] = src[i];
            }
        }
    }
    __u32 payload_len = SCRATCH_SIZE;

    __u64 hostname_hash = 0;
    __u32 host_off = 0;
    __u32 host_len = 0;
    int found = -1;

    found = parse_tls_sni(sb->data, payload_len, &hostname_hash, &host_off, &host_len);
    if (found != 0)
        found = parse_http_host(sb->data, payload_len, &hostname_hash, &host_off, &host_len);

    /* ── Policy decision ───────────────────────────────────────── */
    if (found == 0) {
        struct policy_hostname_key ph_key = {
            .policy_id     = policy_id,
            .hostname_hash = hostname_hash,
        };
        struct policy_hostname_val *ph_val = bpf_map_lookup_elem(&policy_hostnames, &ph_key);
        if (ph_val && ph_val->action == ACTION_ALLOW) {
            return decide_and_cache(&ct_key, ACTION_ALLOW,
                                    src_ip, dst_ip, src_port, dst_port,
                                    hostname_hash, policy_id);
        }

        /* Exact match failed — try wildcard suffix patterns. */
        if (check_wildcard(sb->data, payload_len, host_off, host_len,
                           policy_id) == ACTION_ALLOW) {
            return decide_and_cache(&ct_key, ACTION_ALLOW,
                                    src_ip, dst_ip, src_port, dst_port,
                                    hostname_hash, policy_id);
        }

        return decide_and_cache(&ct_key, ACTION_DENY,
                                src_ip, dst_ip, src_port, dst_port,
                                hostname_hash, policy_id);
    }

    /* No hostname — apply default action */
    struct policy_default_key pd_key = { .policy_id = policy_id };
    struct policy_default_val *pd_val = bpf_map_lookup_elem(&policy_default_action, &pd_key);
    __u8 action = ACTION_DENY;
    if (pd_val)
        action = pd_val->action;

    return decide_and_cache(&ct_key, action,
                            src_ip, dst_ip, src_port, dst_port,
                            0, policy_id);
}

char _license[] SEC("license") = "GPL";
