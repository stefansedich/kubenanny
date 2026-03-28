#ifndef __HTTP_PARSER_H__
#define __HTTP_PARSER_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "sni_parser.h" /* for fnv1a_hash_buf, buf_byte, MAX_HOSTNAME_LEN, SCRATCH_SIZE */

/* ---- bpf_loop callback for counting Host header length ---------------- */
struct host_len_ctx {
    const __u8 *buf;
    __u32 host_start;
    __u32 buf_len;
    __u32 hlen;
    int   done;
};

static long host_len_cb(__u32 idx, struct host_len_ctx *ctx)
{
    if (ctx->done)
        return 1;
    if (ctx->host_start + idx >= ctx->buf_len) {
        ctx->done = 1;
        return 1;
    }
    __u8 c = buf_byte(ctx->buf, ctx->host_start + idx);
    if (c == '\r' || c == ':') {
        ctx->done = 1;
        return 1;
    }
    ctx->hlen++;
    return 0;
}

/*
 * is_http_method — check if the buffer starts with a known HTTP method.
 * Returns the length of the method string (including space), or 0 if not HTTP.
 */
static __always_inline int is_http_method(const __u8 *buf, __u32 buf_len)
{
    if (buf_len < 4)
        return 0;

    /* GET */
    if (buf_byte(buf, 0) == 'G' && buf_byte(buf, 1) == 'E' &&
        buf_byte(buf, 2) == 'T' && buf_byte(buf, 3) == ' ')
        return 4;
    /* PUT */
    if (buf_byte(buf, 0) == 'P' && buf_byte(buf, 1) == 'U' &&
        buf_byte(buf, 2) == 'T' && buf_byte(buf, 3) == ' ')
        return 4;

    if (buf_len < 5)
        return 0;
    /* POST */
    if (buf_byte(buf, 0) == 'P' && buf_byte(buf, 1) == 'O' &&
        buf_byte(buf, 2) == 'S' && buf_byte(buf, 3) == 'T' &&
        buf_byte(buf, 4) == ' ')
        return 5;
    /* HEAD */
    if (buf_byte(buf, 0) == 'H' && buf_byte(buf, 1) == 'E' &&
        buf_byte(buf, 2) == 'A' && buf_byte(buf, 3) == 'D' &&
        buf_byte(buf, 4) == ' ')
        return 5;

    if (buf_len < 7)
        return 0;
    /* DELETE */
    if (buf_byte(buf, 0) == 'D' && buf_byte(buf, 1) == 'E' &&
        buf_byte(buf, 2) == 'L' && buf_byte(buf, 3) == 'E' &&
        buf_byte(buf, 4) == 'T' && buf_byte(buf, 5) == 'E' &&
        buf_byte(buf, 6) == ' ')
        return 7;

    if (buf_len < 6)
        return 0;
    /* PATCH */
    if (buf_byte(buf, 0) == 'P' && buf_byte(buf, 1) == 'A' &&
        buf_byte(buf, 2) == 'T' && buf_byte(buf, 3) == 'C' &&
        buf_byte(buf, 4) == 'H' && buf_byte(buf, 5) == ' ')
        return 6;

    return 0;
}

/*
 * parse_http_host — extract the HTTP Host header value from a scratch buffer.
 *
 * @buf:           scratch buffer containing TCP payload bytes.
 * @buf_len:       number of valid bytes in buf (≤ SCRATCH_SIZE).
 * @hostname_hash: output — FNV-1a hash of the hostname.
 * @host_off:      output — offset of hostname in buf (for wildcard matching).
 * @host_len:      output — length of hostname in buf (for wildcard matching).
 *
 * Returns 0 on success, -1 if not an HTTP request or Host header not found.
 */
#define MAX_HTTP_SCAN 32

static __always_inline int parse_http_host(const __u8 *buf, __u32 buf_len,
                                            __u64 *hostname_hash,
                                            __u32 *host_off, __u32 *host_len)
{
    if (!is_http_method(buf, buf_len))
        return -1;

    /* Scan for "\r\nHost: " pattern in the first MAX_HTTP_SCAN bytes. */
    const __u8 host_marker[] = { '\r', '\n', 'H', 'o', 's', 't', ':', ' ' };

    for (int i = 0; i < MAX_HTTP_SCAN; i++) {
        if (i + 8 > (__s32)buf_len)
            break;

        if (buf_byte(buf, i) != '\r')
            continue;

        int match = 1;
#pragma unroll
        for (int j = 0; j < 8; j++) {
            if (buf_byte(buf, i + j) != host_marker[j]) {
                match = 0;
                break;
            }
        }

        if (!match)
            continue;

        /* Found "\r\nHost: " — extract hostname */
        __u32 host_start = i + 8;

        struct host_len_ctx hlc = {
            .buf        = buf,
            .host_start = host_start,
            .buf_len    = buf_len,
            .hlen       = 0,
            .done       = 0,
        };
        bpf_loop(MAX_HOSTNAME_LEN, host_len_cb, &hlc, 0);
        __u32 hlen = hlc.hlen;

        if (hlen == 0)
            return -1;

        *hostname_hash = fnv1a_hash_buf(buf, host_start, hlen, buf_len);
        *host_off = host_start;
        *host_len = hlen;
        return 0;
    }

    return -1; /* Host header not found */
}

#endif /* __HTTP_PARSER_H__ */
