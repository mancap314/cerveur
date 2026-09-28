/*
 * fuzz_proxy.c - the PROXY protocol v1/v2 header parser, and the address and
 * CIDR parsers used for X-Forwarded-For and --trust-proxy.
 * SPDX-License-Identifier: MIT
 *
 * Input: one control byte (how reads are split), then the bytes a proxy sends
 * first. The same bytes, split at commas, also go through ip_parse/cidr_parse.
 */
#define FUZZ_NAME "fuzz_proxy"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fz_init_common();
    if (size < 1) return 0;
    size_t piece = 1 + (data[0] & 127);
    ++data, --size;

    /* Addresses and CIDRs, read straight from the input (so an overread hits the guard). */
    const char* s = (const char*)data;
    for (size_t i = 0; i < size; ) {
        const char* comma = memchr(s + i, ',', size - i);
        size_t n = comma ? (size_t)(comma - (s + i)) : size - i;
        ipaddr a;
        cidr cd;
        char str[INET6_ADDRSTRLEN];
        if (ip_parse(s + i, n, &a)) {
            ip_to_str(&a, str, sizeof str);
            (void)ip_trusted(&a);
        }
        if (cidr_parse(s + i, n, &cd) && ip_parse(s + i, n, &a)) (void)ip_in(&a, &cd);
        i += n + 1;
    }

    /* The PROXY header, arriving in pieces. */
    struct conn* c = fz_conn();
    fz_ip(c, "127.0.0.1");
    for (;;) {
        int r = proxy_header_parse(c);
        if (r != 0) break;                      /* parsed, or rejected */
        if (!size) break;
        size_t k = fz_push(c, data, size < piece ? size : piece);
        if (!k) break;
        data += k, size -= k;
    }
    return 0;
}

static const fz_seed fuzz_seeds[] FZ_UNUSED = {
    FZ_SEED("\x05" "PROXY TCP4 192.168.1.2 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n"),
    FZ_SEED("\x03" "PROXY TCP6 2001:db8::7 ::1 5555 443\r\n"),
    FZ_SEED("\x10" "PROXY UNKNOWN\r\n"),
    /* v2, PROXY command, TCP over IPv4, with a TLS TLV (client used TLS) */
    FZ_SEED("\x08" "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x21\x11\x00\x10"
            "\x7f\x00\x00\x02\x7f\x00\x00\x01\x15\xb3\x01\xbb\x20\x00\x01\x01"),
    /* v2, LOCAL command */
    FZ_SEED("\x02" "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x20\x00\x00\x00"),
    FZ_SEED("\x01" "1.2.3.4,10.0.0.0/8,[2001:db8::1]:443,::ffff:1.2.3.4/120,unknown, 5.6.7.8:80 "),
};
static const fz_seed fuzz_dict[] FZ_UNUSED = {
    FZ_SEED("PROXY "), FZ_SEED("TCP4 "), FZ_SEED("TCP6 "), FZ_SEED("UNKNOWN"), FZ_SEED("\r\n"), FZ_SEED(" "),
    FZ_SEED("127.0.0.1"), FZ_SEED("::1"), FZ_SEED("2001:db8::"), FZ_SEED("/8"), FZ_SEED("/128"), FZ_SEED(":65535"),
    FZ_SEED("\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"), FZ_SEED("\x21"), FZ_SEED("\x20"), FZ_SEED("\x11"),
    FZ_SEED("\x21\x12"), FZ_SEED("\x31"), FZ_SEED("\x00\x0c"), FZ_SEED("\x00\x24"), FZ_SEED("\x00\xd8"),
    FZ_SEED("\x20\x00\x01\x01"), FZ_SEED("["), FZ_SEED("]"), FZ_SEED(","),
};
#include "fuzz_main.h"
