/*
 * fuzz.h - shared setup for the fuzz targets (fuzz_*.c).
 * SPDX-License-Identifier: MIT
 *
 * Each target includes the whole server (as a library, so without its demo
 * routes and main()) to reach its internal parsers, and defines
 * LLVMFuzzerTestOneInput(). Build a target either
 *   - with libFuzzer and sanitizers (clang, Linux):
 *       clang -g -O1 -fsanitize=fuzzer,address,undefined -Illhttp/include \
 *           fuzz/fuzz_http.c llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c -pthread -o fuzz_http
 *       ./fuzz_http -max_total_time=60 corpus_dir
 *   - or with any compiler and the standalone driver in fuzz_main.h
 *     (random mutations of the target's seeds, no coverage guidance):
 *       gcc -g -O1 -DFUZZ_STANDALONE -Illhttp/include fuzz/fuzz_http.c \
 *           llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c -pthread [-lws2_32]
 *       FUZZ_SECONDS=60 ./fuzz_http        or   ./fuzz_http crash-file...
 */
#ifndef FUZZ_H
#define FUZZ_H

#define SERVER_NO_MAIN
#include "../server.c"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/* Example inputs and dictionary tokens, for the standalone driver and for
   seeding a libFuzzer corpus (--write-seeds). Byte strings with a length, so
   they may contain zero bytes. */
typedef struct { const char* s; size_t n; } fz_seed;
#define FZ_SEED(lit) {lit, sizeof(lit) - 1}
#define FZ_UNUSED __attribute__((unused))       /* libFuzzer builds don't use them */

/* A reactor the fake connections belong to (only its request-context cache is used). */
static struct reactor fz_reactor;

static void fz_init_common(void) {
    static bool done;
    if (done) return;
    done = true;
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);   /* inet_ntop and friends */
#endif
    dlink_init(&fz_reactor.live);
    llhttp_settings_init(&g_parser_settings);
    g_parser_settings.on_url = on_url;
    g_parser_settings.on_header_field = on_header_field;
    g_parser_settings.on_header_value = on_header_value;
    g_parser_settings.on_headers_complete = on_headers_complete;
    g_parser_settings.on_body = on_body;
    g_parser_settings.on_message_complete = on_message_complete;
    const char* trusted = "10.0.0.0/8";
    if (cidr_parse(trusted, strlen(trusted), &g_trusted[0])) g_ntrusted = 1;
}

/* A fresh connection that isn't attached to any socket. */
static struct conn* fz_conn(void) {
    static struct conn* c;
    if (!c && !(c = malloc(sizeof *c))) abort();
    memset(c, 0, offsetof(struct conn, in_small));
    c->in = c->in_small;
    c->in_cap = IN_CAP;
    c->r = &fz_reactor;
    c->fd = BAD_SOCK;
    c->heap_idx = -1;
    dlink_init(&c->link);
    llhttp_init(&c->parser, HTTP_REQUEST, &g_parser_settings);
    c->parser.data = c;
#ifdef _WIN32
    c->rd.c = c->wr.c = c;
#endif
    return c;
}

/* Append up to n bytes to the connection's input, as a read would. */
static size_t fz_push(struct conn* c, const uint8_t* p, size_t n) {
    if (c->in_off > 0) {
        memmove(c->in, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
        c->in_len -= c->in_off;
        c->in_off = 0;
    }
    size_t room = (size_t)(c->in_cap - c->in_len);
    if (n > room) n = room;
    memcpy(c->in + c->in_len, p, n);
    c->in_len += (int)n;
    return n;
}

static void fz_ip(struct conn* c, const char* a) {
    ip_parse(a, strlen(a), &c->peer);
    c->client = c->peer;
}

#endif /* FUZZ_H */
