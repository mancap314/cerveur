/*
 * server.h - public API of server.c, for applications in C or C++.
 *
 * Build server.c as a library with -DSERVER_NO_MAIN (this leaves out its demo
 * routes and main()), and start the server from your own program with a
 * route table:
 *
 *   static const http_route routes[] = {
 *       {"GET", "/", hello},                  // method, pattern, handler, ...
 *       {},                                   // (C: {0}) ends the table
 *   };
 *   int main(int argc, char** argv) { return http_server_main(argc, argv, routes); }
 *
 * Linux:    gcc -c -O2 -pthread -Illhttp/include -DSERVER_NO_MAIN server.c llhttp/src/{api,http,llhttp}.c
 *           g++ -O2 -pthread app.cpp *.o -o app
 * Windows:  the same with -O3, linking -lws2_32 (MinGW-w64).
 * See example.cpp for buffered, streaming and WebSocket handlers in C++.
 *
 * The API is C (extern "C"), so it can be called from C++ as is. Streaming
 * and WebSocket handlers are STC coroutines (stc/coroutine.h). In C++, write
 * their bodies without initialized declarations between cco_async and the
 * last cco_await (the macros jump over them, which C++ rejects), keeping state
 * in the task struct instead; see example.cpp. On Windows, include
 * <windows.h> (if you need it) before this header.
 */
#ifndef SERVER_H
#define SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "stc/coroutine.h"

#ifdef __cplusplus
/* STC's cco_async begins with a dead `if (0) goto` (it only silences an
   unused-label warning) that C++ rejects, because it jumps over the
   initialization of _cco_st. The same macro, with _cco_st declared in an
   enclosing loop that runs once, before the part the jump crosses. */
#undef cco_async
#define cco_async(co) \
    for (_cco_state_t(co)* _cco_st = (_cco_assert_task_struct(co), (_cco_state_t(co)*) &(co)->base.state) \
         ; _cco_st; _cco_st = NULL) \
    if (0) goto _resume_lbl; \
    else for (; _cco_st->pos != cco_POS_DONE \
              ; _cco_st->pos = cco_POS_DONE, \
                (void)(sizeof((co)->base) > sizeof(cco_base) && (_cco_st->parent_grp ? --_cco_st->parent_grp->spawn_count : 0))) \
        _resume_lbl: switch (_cco_st->pos) case cco_POS_INIT:
#endif

#ifndef OUT_CAP                /* response buffer per active request (-DOUT_CAP=131072 moves
                                  large bodies with ~10% less CPU on Windows, but every open
                                  WebSocket / SSE stream keeps one for its whole life) */
#define OUT_CAP       32768
#endif

#if defined(__GNUC__) && defined(__MINGW32__)
#define HTTP_PRINTF(f, a) __attribute__((format(gnu_printf, f, a)))
#elif defined(__GNUC__)
#define HTTP_PRINTF(f, a) __attribute__((format(printf, f, a)))
#else
#define HTTP_PRINTF(f, a)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { const char* ptr; size_t len; } http_str;
typedef struct { http_str name, value; } http_header;
typedef struct http_ctx http_ctx;

typedef void (*http_handler_fn)(http_ctx* x);
typedef int  (*http_stream_fn)(void* task);

typedef struct {
    const char* method;        /* "GET", "POST", ... or NULL for any method */
    const char* pattern;       /* e.g. "/users/:id", or "/static/" followed by "*path" */
    http_handler_fn handle;    /* buffered handler, or ... */
    http_stream_fn  stream;    /* ... streaming handler coroutine, or ... */
    http_stream_fn  websocket; /* ... WebSocket handler coroutine */
    size_t task_size;          /* streaming/WebSocket: sizeof the task struct */
    size_t body_limit;         /* buffered: max request body (0 = default) */
} http_route;

/* Run the server with these routes (a table ended by an all-zero entry) until
   SIGINT/SIGTERM (Windows: Ctrl+C / Ctrl+Break). argv takes the usual
   options: [--bind=ADDR] [--keepalive=MS] [--trust-proxy=LIST]
   [--proxy-protocol] [port] [threads]. Returns the process exit code. */
int http_server_main(int argc, char* argv[], const http_route* routes);

/* Every streaming task struct starts with these two fields. The connection
   allocates the struct zeroed, sets x, and resumes it until it's done.

   IMPORTANT (stackless coroutines): local variables do not survive a
   cco_await. Anything used after an await, including inside the awaited
   condition itself (it is re-evaluated on every resume), must be a field of
   the task struct. GCC's -Wmaybe-uninitialized usually catches mistakes. */
#define HTTP_TASK cco_base base; http_ctx* x

/* Request accessors */
http_str    http_method(const http_ctx* x);
http_str    http_path(const http_ctx* x);
http_str    http_header_get(const http_ctx* x, const char* name);
http_str    http_param(const http_ctx* x, const char* name);
bool        http_query(const http_ctx* x, const char* key, char* buf, size_t cap);
http_str    http_body(const http_ctx* x);           /* buffered handlers */
/* The real client's address: from the PROXY protocol, or from X-Forwarded-For
   when the connection comes from a --trust-proxy address (walking the list
   right to left past trusted hops, so clients can't spoof it). */
const char* http_client_ip(http_ctx* x);
const char* http_scheme(http_ctx* x);   /* "https" if a trusted proxy says so */

/* Streaming request body (streaming handlers) */
bool        http_body_ready(http_ctx* x);   /* await: a chunk is ready or the body ended */
bool        http_body_done(const http_ctx* x);
http_str    http_body_take(http_ctx* x);    /* valid until the next http_body_ready();
                                               at most HTTP_SEND_MAX bytes */

/* Responses */
void        http_set_header(http_ctx* x, const char* name, const char* value);
void        http_respond(http_ctx* x, int status, const char* ctype, const void* body, size_t len);
void        http_respondf(http_ctx* x, int status, const char* ctype, const char* fmt, ...) HTTP_PRINTF(4, 5);
void        http_start(http_ctx* x, int status, const char* ctype);    /* streamed body */
bool        http_send(http_ctx* x, const void* data, size_t len);      /* await: all-or-nothing */
bool        http_sendf(http_ctx* x, const char* fmt, ...) HTTP_PRINTF(2, 3);
void        http_end(http_ctx* x);
#define HTTP_SEND_MAX (OUT_CAP - 64)   /* largest single http_send() */

/* Timers, for streaming and WebSocket handlers. A handler can wait for a
   timer and other events at once:
       cco_await(ws_recv_ready(x) || http_timer_done(x, &t->tick));
   While a handler waits on a timer, the connection's idle timeout is paused. */
typedef struct { int64_t when; } http_timer;
void http_timer_start(http_ctx* x, http_timer* t, int64_t ms);
bool http_timer_done(http_ctx* x, http_timer* t);                  /* await */
bool http_timer_expired(const http_ctx* x, const http_timer* t);   /* check only */
#define http_sleep(x, t, ms) do { http_timer_start(x, t, ms); cco_await(http_timer_done(x, t)); } while (0)

/* WebSocket (RFC 6455). A route with .websocket upgrades the connection and
   runs the handler coroutine. The server unmasks and reassembles fragmented
   messages, validates UTF-8 in text messages, answers pings, and runs the
   close handshake; protocol violations close with the proper status code.
   Once the close handshake completes, the handler is stopped (its
   cco_finalize block runs). */
enum { WS_TEXT = 1, WS_BINARY = 2 };
typedef struct { int opcode; const char* data; size_t len; } ws_message;
bool       ws_recv_ready(http_ctx* x);     /* await: a message arrived, or the connection closed */
bool       ws_has_message(const http_ctx* x);
ws_message ws_recv(http_ctx* x);           /* valid until the next ws_recv_ready() */
bool       ws_closed(const http_ctx* x);   /* closed, and no messages left to read */
int        ws_close_code(const http_ctx* x);   /* peer's code; 1006 if dropped */
bool       ws_send(http_ctx* x, int opcode, const void* data, size_t len);   /* await */
bool       ws_sendf(http_ctx* x, const char* fmt, ...) HTTP_PRINTF(2, 3);
void       ws_close(http_ctx* x, int code, const char* reason);

/* Publish/subscribe between connections, across all reactor threads.
   Any handler can publish. Streaming and WebSocket handlers can subscribe
   (up to 16 topics) and then wait for messages, alone or together with other
   events:
       cco_await(ws_recv_ready(x) || ps_ready(x));
   Messages from one publisher arrive in order. Publishing never blocks: a
   subscriber's mailbox grows with its backlog, and if it falls too far
   behind, its oldest messages are dropped and counted (ps_lagged): every
   message is either delivered or reported as skipped. Subscriptions end
   automatically with the handler, and follow the connection when it
   migrates to another thread. */
typedef struct { const char* topic; int opcode; const char* data; size_t len; } ps_message;
int        ps_publish(const char* topic, int opcode, const void* data, size_t len);  /* -> subscribers reached */
bool       ps_subscribe(http_ctx* x, const char* topic);
void       ps_unsubscribe(http_ctx* x, const char* topic);
bool       ps_ready(http_ctx* x);          /* await: a message is waiting */
ps_message ps_recv(http_ctx* x);           /* valid until the next ps_ready() */
unsigned   ps_lagged(http_ctx* x);         /* messages dropped since the last call */

static inline bool http_str_eq(http_str s, const char* lit) {
    size_t n = strlen(lit);
    return s.len == n && memcmp(s.ptr, lit, n) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SERVER_H */
