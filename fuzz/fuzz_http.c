/*
 * fuzz_http.c - requests through the parser callbacks, router, body handling
 * (buffered, streamed, discarded) and the request accessors, as the connection
 * loop drives them. SPDX-License-Identifier: MIT
 *
 * Input: one control byte (how reads are split, and whether the peer is a
 * trusted proxy), then the bytes a client sends: one or more pipelined requests.
 */
#define FUZZ_NAME "fuzz_http"
#include "fuzz.h"

static void fz_handler(http_ctx* x) {
    char q[256];
    http_str id = http_param(x, "id"), path = http_param(x, "path");
    bool has_q = http_query(x, "q", q, sizeof q);
    http_str ua = http_header_get(x, "user-agent");
    const char* ip = http_client_ip(x);
    const char* scheme = http_scheme(x);
    http_str body = http_body(x);
    http_set_header(x, "X-Fuzz", "1");
    http_respondf(x, 200, "text/plain", "%.*s|%.*s|%s|%.*s|%s|%s|%zu\n", (int)id.len, id.ptr,
                  (int)path.len, path.ptr, has_q ? q : "-", (int)ua.len, ua.ptr ? ua.ptr : "",
                  ip, scheme, body.len);
}

static int fz_stream(void* task) { (void)task; return cco_DONE; }  /* never started here */

static const http_route fz_routes[] = {
    {"GET",  "/users/:id",    .handle = fz_handler},
    {"POST", "/upload",       .handle = fz_handler, .body_limit = 8192},
    {"GET",  "/static/*path", .handle = fz_handler},
    {NULL,   "/any",          .handle = fz_handler},
    {"POST", "/stream",       .stream = fz_stream, .task_size = sizeof(struct http_task)},
    {"GET",  "/ws",           .websocket = fz_stream, .task_size = sizeof(struct http_task)},
    {0},
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fz_init_common();
    g_routes = fz_routes;
    if (size < 1) return 0;
    uint8_t ctl = data[0];
    ++data, --size;
    size_t piece = 1 + (ctl & 63);              /* bytes per simulated read */
    struct conn* c = fz_conn();
    fz_ip(c, ctl & 64 ? "10.1.2.3" : "203.0.113.7");    /* trusted proxy, or not */
    bool routed = false;
    for (;;) {
        bool progress = false;
        if (c->in_off < c->in_len || c->paused) {
            http_ctx* x = c->x;
            if (!x && !(x = c->x = ctx_acquire(c))) break;
            int before = c->in_len - c->in_off;
            if (feed(c) < 0) { respond_error(x); break; }      /* malformed: the connection ends */
            progress = c->in_len - c->in_off != before;
            if (x->head_done && !routed) {
                routed = progress = true;
                dispatch(x);
                if (x->err) { respond_error(x); break; }
                if (x->ws && ws_handshake(x)) break;
            }
            if (x->body_mode == BODY_STREAM)
                while (x->chunk.len) { (void)http_body_take(x); progress = true; }
            if (x->msg_done) {                  /* one request done: next one on the connection */
                if (x->route && x->route->handle) x->route->handle(x);
                ctx_release(c);
                routed = false;
                continue;
            }
        }
        if (progress) continue;
        if (!size) break;
        size_t k = fz_push(c, data, size < piece ? size : piece);
        if (!k) break;                          /* input buffer full, nothing consumed */
        data += k, size -= k;
    }
    conn_free_buffers(c);
    return 0;
}

static const fz_seed fuzz_seeds[] FZ_UNUSED = {
    FZ_SEED("\x05" "GET /users/42?verbose=1&q=a%20b+c HTTP/1.1\r\nHost: x\r\nUser-Agent: fz\r\n\r\n"),
    FZ_SEED("\x45" "GET /any HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4, 10.0.0.5\r\nX-Forwarded-Proto: https\r\n\r\n"),
    FZ_SEED("\x10" "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world"),
    FZ_SEED("\x03" "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
    FZ_SEED("\x07" "POST /stream HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n"),
    FZ_SEED("\x3f" "GET /static/a/b/c.txt HTTP/1.1\r\n\r\nGET /users/1 HTTP/1.1\r\n\r\nHEAD /any HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"),
    FZ_SEED("\x01" "PUT /users/9 HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc"),
    FZ_SEED("\x20" "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"),
};
static const fz_seed fuzz_dict[] FZ_UNUSED = {
    FZ_SEED("GET "), FZ_SEED("POST "), FZ_SEED("HEAD "), FZ_SEED(" HTTP/1.1\r\n"), FZ_SEED(" HTTP/1.0\r\n"),
    FZ_SEED("\r\n"), FZ_SEED("\r\n\r\n"), FZ_SEED(": "), FZ_SEED("?"), FZ_SEED("&"), FZ_SEED("="), FZ_SEED("%"),
    FZ_SEED("%2"), FZ_SEED("+"), FZ_SEED("/users/"), FZ_SEED("/static/"), FZ_SEED("/upload"), FZ_SEED("/stream"),
    FZ_SEED("/any"), FZ_SEED("/ws"), FZ_SEED("Content-Length: "), FZ_SEED("Transfer-Encoding: chunked\r\n"),
    FZ_SEED("Connection: close\r\n"), FZ_SEED("Connection: keep-alive\r\n"), FZ_SEED("Expect: 100-continue\r\n"),
    FZ_SEED("X-Forwarded-For: "), FZ_SEED("X-Forwarded-Proto: https\r\n"), FZ_SEED("10.0.0.1"), FZ_SEED("[::1]:80"),
    FZ_SEED("unknown"), FZ_SEED("0\r\n\r\n"), FZ_SEED("ffffffff\r\n"), FZ_SEED(";ext=1"), FZ_SEED("Upgrade: websocket\r\n"),
    FZ_SEED("\0"),
};
#include "fuzz_main.h"
