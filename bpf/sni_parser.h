#ifndef __SNI_PARSER_H__
#define __SNI_PARSER_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Maximum hostname length we'll extract. Real hostnames rarely exceed 128 bytes.
 * 64 bytes covers most DNS names including K8s internal FQDNs. */
#define MAX_HOSTNAME_LEN 64

/* FNV-1a 64-bit hash — must match the Go-side implementation exactly. */
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME        1099511628211ULL

/*
 * Safe buffer read — uses asm volatile to prevent the compiler from
 * eliminating the bounds check via constant propagation.  Without
 * the barrier the compiler proves (from C semantics) that `off` is
 * always in range and removes the check; the BPF verifier then
 * rejects the program because *it* cannot prove the same thing.
 */
static __always_inline __u8 buf_byte(const __u8 *buf, __u32 off)
{
    asm volatile("" : "+r"(off));   /* compiler forgets off's range */
    if (off >= SCRATCH_SIZE)         /* verifier sees this guard     */
        return 0;
    return buf[off];
}

static __always_inline __u16 buf_u16be(const __u8 *buf, __u32 off)
{
    return ((__u16)buf_byte(buf, off) << 8) | buf_byte(buf, off + 1);
}

/* ---- bpf_loop callback for FNV-1a hashing ----------------------------- */
struct fnv_hash_ctx {
    const __u8 *buf;
    __u32 start;
    __u32 len;
    __u32 buf_len;
    __u64 hash;
};

static long fnv_hash_cb(__u32 idx, struct fnv_hash_ctx *ctx)
{
    if (idx >= ctx->len)
        return 1;
    if (ctx->start + idx >= ctx->buf_len)
        return 1;
    ctx->hash ^= (__u64)buf_byte(ctx->buf, ctx->start + idx);
    ctx->hash *= FNV_PRIME;
    return 0;
}

static __always_inline __u64 fnv1a_hash_buf(const __u8 *buf, __u32 start,
                                             __u32 len, __u32 buf_len)
{
    struct fnv_hash_ctx ctx = {
        .buf     = buf,
        .start   = start,
        .len     = len,
        .buf_len = buf_len,
        .hash    = FNV_OFFSET_BASIS,
    };
    bpf_loop(MAX_HOSTNAME_LEN, fnv_hash_cb, &ctx, 0);
    return ctx.hash;
}

/*
 * parse_tls_sni — extract the SNI hostname hash from a TLS ClientHello.
 *
 * @buf:           scratch buffer containing TCP payload bytes.
 * @buf_len:       number of valid bytes in buf (≤ SCRATCH_SIZE).
 * @hostname_hash: output — FNV-1a hash of the extracted SNI hostname.
 * @host_off:      output — offset of hostname in buf (for wildcard matching).
 * @host_len:      output — length of hostname in buf (for wildcard matching).
 *
 * Returns 0 on success, -1 if the packet is not a ClientHello or SNI not found.
 */
static __always_inline int parse_tls_sni(const __u8 *buf, __u32 buf_len,
                                          __u64 *hostname_hash,
                                          __u32 *host_off, __u32 *host_len)
{
    /* TLS record header (5 bytes) + handshake type (1 byte) */
    if (buf_len < 6)
        return -1;
    if (buf_byte(buf, 0) != 0x16) /* Not Handshake */
        return -1;
    if (buf_byte(buf, 5) != 0x01) /* Not ClientHello */
        return -1;

    /* Skip: record hdr(5) + handshake hdr(4) + client_version(2) + random(32) */
    __u32 off = 43;
    if (off + 1 > buf_len)
        return -1;

    /* Session ID */
    __u8 sid_len = buf_byte(buf, off);
    off += 1 + sid_len;
    if (off + 2 > buf_len)
        return -1;

    /* Cipher suites */
    __u16 cs_len = buf_u16be(buf, off);
    off += 2 + cs_len;
    if (off + 1 > buf_len)
        return -1;

    /* Compression methods */
    __u8 comp_len = buf_byte(buf, off);
    off += 1 + comp_len;
    if (off + 2 > buf_len)
        return -1;

    /* Extensions total length */
    __u16 ext_total = buf_u16be(buf, off);
    off += 2;

    __u32 ext_end = off + ext_total;
    if (ext_end > buf_len)
        ext_end = buf_len;

    /* Iterate extensions — bounded loop for BPF verifier */
    for (int i = 0; i < 16; i++) {
        if (off + 4 > ext_end)
            break;

        __u16 ext_type     = buf_u16be(buf, off);
        __u16 ext_data_len = buf_u16be(buf, off + 2);

        if (ext_type == 0x0000) { /* SNI extension */
            __u32 sni = off + 4;
            if (sni + 5 > buf_len)
                return -1;

            if (buf_byte(buf, sni + 2) != 0x00) /* Not host_name */
                return -1;

            __u16 name_len = buf_u16be(buf, sni + 3);
            if (name_len == 0 || name_len > MAX_HOSTNAME_LEN)
                return -1;

            __u32 name_off = sni + 5;
            if (name_off + name_len > buf_len)
                return -1;

            *hostname_hash = fnv1a_hash_buf(buf, name_off, name_len, buf_len);
            *host_off = name_off;
            *host_len = name_len;
            return 0;
        }

        off += 4 + ext_data_len;
    }

    return -1; /* SNI extension not found */
}

#endif /* __SNI_PARSER_H__ */
