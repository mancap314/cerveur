/*
 * server.c - multi-core HTTP/1.1 server on STC stackless coroutines, with
 *            full HTTP/1.1 parsing (llhttp), streaming request and response
 *            bodies, a router with path parameters, and load-based
 *            rebalancing of connections between cores.
 *
 * Linux (epoll, SO_REUSEPORT, eventfd) and Windows 10 1703+ (I/O completion
 * ports, built with MinGW-w64; see "Platform layer" and "Windows: I/O
 * completion ports" below).
 *
 * Built as is, this is a demo program (the routes near the end). Built with
 * -DSERVER_NO_MAIN, it is a library for your own C or C++ program: the API is
 * in server.h, you start it with http_server_main(argc, argv, routes), and
 * example.cpp shows handlers written in C++.
 *
 * ------------------------------------------------------------------------
 * HTTP layer
 * ------------------------------------------------------------------------
 *   - Parsing: llhttp (Node.js's parser) handles request lines, headers,
 *     Content-Length and chunked request bodies, keep-alive rules for
 *     HTTP/1.0 and 1.1, and pipelining. It parses incrementally, so a request
 *     may arrive in any number of pieces.
 *   - Routing: method + pattern, with ":name" segment parameters and a
 *     trailing "*name" wildcard. Unknown paths get 404; a known path with the
 *     wrong method gets 405 with an Allow header. HEAD is served by GET routes.
 *   - Two kinds of handlers:
 *       .handle  - buffered: the whole body (up to .body_limit, default 1 MiB)
 *                  is read first, then the function is called once and
 *                  responds with http_respond()/http_respondf().
 *       .stream  - streaming: an STC coroutine that receives the request body
 *                  chunk by chunk and writes the response incrementally. It
 *                  suspends with cco_await(http_body_ready(x)) and
 *                  cco_await(http_send(x, ...)), and the connection resumes it
 *                  when data arrives or output space frees up. Memory stays
 *                  bounded however large the bodies are, and a slow client
 *                  naturally slows the handler down (backpressure).
 *   - Responses: Content-Length for buffered bodies; chunked transfer
 *     encoding for streamed ones (close-delimited for HTTP/1.0 clients).
 *     Small writes are coalesced into one chunk per flush. Date header is
 *     cached per reactor.
 *   - Protocol details: Expect: 100-continue, 413 for oversized bodies
 *     (rejected up front when Content-Length says so), 431 for oversized
 *     headers, 400 for malformed requests, unread request bodies drained so
 *     keep-alive connections stay usable.
 *
 * ------------------------------------------------------------------------
 * Runtime
 * ------------------------------------------------------------------------
 *   - One reactor per thread, each with its own SO_REUSEPORT listener and
 *     epoll set. Each connection is an STC coroutine resumed only when its
 *     socket is ready or its deadline expires.
 *   - Timeouts: a request's headers must arrive within TIMEOUT_MS; after
 *     that, the connection may sit idle at most TIMEOUT_MS between bytes
 *     received or sent, so long streams are fine but stalled ones are not.
 *     Between requests, a keep-alive connection may idle for --keepalive.
 *     WebSockets are pinged when quiet and closed if the peer stops
 *     answering; idle SSE streams get keepalive comments.
 *   - Handler timers live in a per-reactor min-heap.
 *   - Rebalancing: every REBALANCE_MS each reactor measures its CPU load and,
 *     if it's clearly the hot spot, migrates its heaviest connections to the
 *     least loaded reactor. A suspended connection (including an in-progress
 *     streaming handler) is a plain struct, so migration is a pointer handoff.
 *   - Graceful shutdown on SIGINT/SIGTERM: every connection and streaming
 *     handler runs its cco_finalize block.
 *
 *   - WebSockets: RFC 6455 upgrade and framing, with handlers written as
 *     coroutines just like streaming HTTP handlers.
 *   - Timers: streaming and WebSocket handlers can sleep or wait for a timer
 *     alongside other events (e.g. server-sent events, periodic pushes).
 *   - Pub/sub between connections on any thread (chat rooms, live feeds),
 *     safe across connection migration.
 *
 *   - Behind a proxy: real client address from X-Forwarded-For (only from
 *     --trust-proxy peers) or the PROXY protocol (--proxy-protocol), and
 *     X-Forwarded-Proto for the scheme. Keepalive pings/comments stop proxies
 *     from cutting quiet WebSockets and SSE streams.
 *
 * Deliberately left to a reverse proxy (Caddy, nginx, HAProxy): TLS, HTTP/2
 * and HTTP/3, response compression. See the example configs.
 * Not included: WebSocket permessage-deflate, JSON (de)serialization, middleware.
 *
 * Build:
 *   mkdir -p stc && curl -sSLo stc/coroutine.h \
 *     https://raw.githubusercontent.com/stclib/stcsingle/main/stc/coroutine.h
 *   git clone --depth 1 --branch release https://github.com/nodejs/llhttp.git
 *   gcc -std=gnu11 -O2 -Wall -pthread -Illhttp/include -o server server.c \
 *       llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c
 *
 * Build on Windows (MinGW-w64 gcc with posix threads, e.g. from Git Bash):
 *   the same two downloads, then
 *   gcc -std=gnu11 -O3 -Wall -pthread -Illhttp/include -o server.exe server.c \
 *       llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c -lws2_32
 *   (-O3 measured ~8% less CPU than -O2 on formatting-heavy responses;
 *   -march=... and -flto were slower there.)
 *   On Windows, "localhost" tries ::1 first and a refused IPv6 connect takes
 *   ~2 s to fall back, so use --bind=:: (dual stack) or connect to 127.0.0.1.
 *   Stop with Ctrl+C / Ctrl+Break.
 *
 * Run:   ./server [options] [port] [threads]    defaults: 8080, one per online CPU
 *   --bind=ADDR          listen address (default 0.0.0.0; use 127.0.0.1 behind a proxy)
 *   --keepalive=MS       idle keep-alive between requests (default 75000; set it
 *                        longer than the proxy's upstream idle timeout)
 *   --trust-proxy=LIST   comma-separated addresses/CIDRs of your proxies, e.g.
 *                        127.0.0.1,::1,10.0.0.0/8; only these may set
 *                        X-Forwarded-For/-Proto or send PROXY headers
 *   --proxy-protocol     every connection starts with a PROXY v1/v2 header
 *                        (trusts 127.0.0.1 and ::1 if --trust-proxy isn't given)
 * Try:   open http://localhost:8080/chat in two browser tabs (pub/sub chat)
 *        open http://localhost:8080/ws-test in a browser (WebSocket demo)
 *        curl -d 'hello room' localhost:8080/rooms/lobby   (publish over HTTP)
 *        curl -N localhost:8080/events?n=5      (server-sent events, 1/s)
 *        curl localhost:8080/users/42?verbose=1
 *        curl -N localhost:8080/stream?n=5
 *        curl --data-binary @bigfile localhost:8080/echo | cmp - bigfile
 */
#ifdef _WIN32
#define _WIN32_WINNT  0x0A00        /* Windows 10 */
#define NTDDI_VERSION 0x0A000003    /* ... 1703 or later: SIO_TCP_INFO */
#define __USE_MINGW_ANSI_STDIO 1    /* C99 printf formats (%zu, %lld) */
#include <winsock2.h>               /* before windows.h (and before STC, which checks for it) */
#include <ws2tcpip.h>
#include <mstcpip.h>                /* SIO_TCP_INFO */
#include <mswsock.h>                /* AcceptEx */
#include <windows.h>
#else
#define _GNU_SOURCE            /* accept4, pthread_setaffinity_np */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>       /* TCP_NODELAY */
#include <sched.h>
#include <linux/sockios.h>     /* SIOCOUTQ */
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#endif
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define i_implement            /* compile STC's coroutine implementation here */
#include "stc/coroutine.h"
#include "llhttp.h"

/* ---- Platform layer: sockets, wake-up handles, signals, threads ----
   Linux uses epoll, eventfd and SO_REUSEPORT directly. Windows uses an I/O
   completion port per reactor (see "Windows: I/O completion ports" below):
   reads and writes are overlapped WSARecv/WSASend straight into the
   connection's buffers, wake-ups are posted completion packets, and reactor 0
   accepts (AcceptEx) and deals new connections out round-robin through the
   other reactors' inboxes, as there is no SO_REUSEPORT. */
#ifdef _WIN32
typedef SOCKET sock_t;
typedef HANDLE poll_t;                      /* the reactor's completion port */
#define BAD_SOCK     INVALID_SOCKET
#define BAD_POLL     NULL
#define SHUT_WR      SD_SEND
#define poll_close   CloseHandle
/* The connection coroutine waits on these bits on both platforms; on Windows
   the reactor sets them from I/O completions. */
enum { EPOLLIN = 0x001, EPOLLOUT = 0x004, EPOLLERR = 0x008, EPOLLHUP = 0x010, EPOLLRDHUP = 0x2000 };
#define PRINTF_LIKE(f, a) __attribute__((format(gnu_printf, f, a)))   /* MinGW's C99 printf */

static struct tm* gmtime_r(const time_t* t, struct tm* out) { return gmtime_s(out, t) ? NULL : out; }

static ssize_t sock_send(sock_t s, const void* buf, size_t n) {
    return send(s, buf, n > INT_MAX ? INT_MAX : (int)n, 0);
}
static int sock_nonblock(sock_t s) { u_long on = 1; return ioctlsocket(s, FIONBIO, &on); }
static void sock_close(sock_t s) { closesocket(s); }
/* Pending overlapped operations complete (with an error) when the socket
   closes; the reactor waits for them before freeing the connection. */
static void sock_close_polled(poll_t ep, sock_t s) {
    (void)ep;
    closesocket(s);
}
/* Bytes handed to the kernel that the peer hasn't acknowledged yet (Linux's
   SIOCOUTQ), i.e. tx_total minus what was acknowledged. BytesOut counts
   retransmitted bytes too, including zero-window probes against a peer that
   has stopped reading, so those must not look like progress:
   acknowledged = BytesOut - BytesInFlight - BytesRetrans. -1 if unavailable. */
static int sock_outq(sock_t s, uint64_t tx_total) {
    DWORD ver = 0, got = 0;
    TCP_INFO_v0 ti;
    if (WSAIoctl(s, SIO_TCP_INFO, &ver, sizeof ver, &ti, sizeof ti, &got, NULL, NULL) != 0)
        return -1;
    int64_t acked = (int64_t)ti.BytesOut - (int64_t)ti.BytesInFlight - (int64_t)ti.BytesRetrans;
    int64_t q = (int64_t)tx_total - acked;
    return q < 0 ? 0 : q > INT_MAX ? INT_MAX : (int)q;
}

static int online_cpus(void) { return (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); }
static void pin_thread(pthread_t t, int cpu) {
    if (cpu < 64) SetThreadAffinityMask(pthread_gethandle(t), (DWORD_PTR)1 << cpu);
}
static void net_error(const char* what) {
    int e = WSAGetLastError();
    if (!e) { perror(what); return; }
    char msg[256] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)e, 0,
                   msg, sizeof msg, NULL);
    fprintf(stderr, "%s: winsock error %d: %s\n", what, e, msg);
}

/* Shutdown on Ctrl+C, Ctrl+Break or console close. */
static HANDLE g_stop_event;
static BOOL WINAPI on_console_ctrl(DWORD type) {
    (void)type;
    SetEvent(g_stop_event);
    return TRUE;
}
static void stop_signals_init(void) {
    g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);
}
static void stop_signals_wait(void) { WaitForSingleObject(g_stop_event, INFINITE); }

#else  /* Linux */
typedef int sock_t;
typedef int poll_t;
#define BAD_SOCK     (-1)
#define BAD_POLL     (-1)
#define poll_close   close
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))

static bool would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
static ssize_t sock_recv(sock_t s, void* buf, size_t n) { return recv(s, buf, n, 0); }
static ssize_t sock_send(sock_t s, const void* buf, size_t n) { return send(s, buf, n, MSG_NOSIGNAL); }
static void sock_close(sock_t s) { close(s); }
static sock_t sock_accept(sock_t l, struct sockaddr* sa, socklen_t* len) {
    sock_t s = accept4(l, sa, len, SOCK_NONBLOCK);
    int one = 1;
    if (s != BAD_SOCK) setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return s;
}
static void sock_close_polled(poll_t ep, sock_t s) {
    (void)ep;
    close(s);                       /* also removes it from the epoll set */
}
static int sock_outq(sock_t s, uint64_t tx_total) {
    (void)tx_total;
    int kq = 0;
    return ioctl(s, SIOCOUTQ, &kq) < 0 ? -1 : kq;
}

static sock_t notify_open(void) { return eventfd(0, EFD_NONBLOCK); }
static void notify_signal(sock_t fd) {
    uint64_t one = 1;
    if (write(fd, &one, sizeof one) < 0) { /* counter can't overflow here */ }
}
static void notify_drain(sock_t fd) {
    uint64_t v;
    if (read(fd, &v, sizeof v) < 0) { /* EAGAIN: nothing signalled */ }
}

static int online_cpus(void) { return (int)sysconf(_SC_NPROCESSORS_ONLN); }
static void pin_thread(pthread_t t, int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(t, sizeof set, &set);
}
static void net_error(const char* what) { perror(what); }

/* Block termination signals in every thread; main receives them via sigwait. */
static sigset_t g_stop_sigs;
static void stop_signals_init(void) {
    sigemptyset(&g_stop_sigs);
    sigaddset(&g_stop_sigs, SIGINT);
    sigaddset(&g_stop_sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &g_stop_sigs, NULL);
}
static void stop_signals_wait(void) {
    int sig;
    sigwait(&g_stop_sigs, &sig);
}
#endif

/* First occurrence of needle in hay (memmem isn't available everywhere). */
static const void* mem_find(const void* hay, size_t n, const void* needle, size_t m) {
    const char* h = hay;
    if (m == 0) return hay;
    for (size_t i = 0; i + m <= n; ++i)
        if (h[i] == *(const char*)needle && memcmp(h + i, needle, m) == 0) return h + i;
    return NULL;
}

/* ---- Limits ---- */
#define IN_CAP        16384    /* socket read buffer per connection */
#define IN_BIG_CAP    65536    /* ... grown to this while it receives bulk data */
#define HDR_ARENA     8192     /* request line + headers; beyond this -> 431 */
#define MAX_HEADERS   64
#define MAX_PARAMS    8
#define DEFAULT_BODY_LIMIT (1u << 20)   /* buffered handlers (axum's default is 2 MiB) */
#define MAX_DRAIN     (1u << 20)        /* unread body we'll discard to keep a connection */
#define CTX_CACHE     64       /* recycled request contexts per reactor */
#define WS_MAX_MSG    (1u << 20)   /* largest incoming WebSocket message -> else 1009 */
#ifndef WS_PING_MS
#define WS_PING_MS    20000    /* ping a WebSocket after this long without receiving anything */
#endif
#ifndef WS_PONG_MS
#define WS_PONG_MS    10000    /* ... and close it if nothing comes back within this */
#endif
#ifndef WS_STALL_MS
#define WS_STALL_MS   60000    /* a WebSocket peer may make no reading progress this long
                                  (plain HTTP responses: TIMEOUT_MS) */
#endif
#ifndef SSE_KEEPALIVE_MS
#define SSE_KEEPALIVE_MS 20000 /* idle server-sent-event streams get a comment line */
#endif
#define DEFAULT_KEEPALIVE_MS 75000   /* idle keep-alive between requests (--keepalive) */
#define MAX_TRUSTED   32       /* --trust-proxy entries */
#define PS_QUEUE      4096     /* per-subscriber mailbox limit (it grows from 16 as needed);
                                  beyond this the oldest messages are dropped */
#define PS_MAX_TOPICS 16       /* subscriptions per handler */
#define PS_BUCKETS    1024     /* topic registry hash buckets */
#define LINGER_MS     2000     /* lingering close: max time to discard unread input */
#define LINGER_MAX    (4u << 20)   /* ... and max bytes */
#ifndef TIMEOUT_MS
#define TIMEOUT_MS    10000    /* header timeout, and idle timeout between bytes;
                                  also the granularity of the timers below */
#endif
#define MAX_EVENTS    256
#ifndef WORK_US
#define WORK_US       200      /* CPU burned by /work, to simulate expensive requests */
#endif

/* ---- Rebalancing tunables (overridable with -D for testing) ---- */
#ifndef REBALANCE_MS
#define REBALANCE_MS  250
#endif
#ifndef MIN_LOAD
#define MIN_LOAD      0.20
#endif
#ifndef MIN_GAP
#define MIN_GAP       0.15
#endif
#ifndef COOLDOWN_MS
#define COOLDOWN_MS   2000
#endif
#ifndef MAX_MIGRATE
#define MAX_MIGRATE   64
#endif

#include "server.h"             /* the public API: types and functions for handlers */

struct http_task { HTTP_TASK; };

/* ======================================================================== */
/* Runtime structures                                                       */
/* ======================================================================== */

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static int64_t now_ms(void) { return now_ns() / 1000000; }
static int64_t thread_cpu_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* Intrusive doubly-linked list. */
typedef struct dlink { struct dlink *prev, *next; } dlink;
static void dlink_init(dlink* n) { n->prev = n->next = n; }
static bool dlink_empty(const dlink* l) { return l->next == l; }
static void dlink_remove(dlink* n) {
    n->prev->next = n->next;
    n->next->prev = n->prev;
    dlink_init(n);
}
static void dlink_insert_after(dlink* pos, dlink* n) {
    n->prev = pos;
    n->next = pos->next;
    pos->next->prev = n;
    pos->next = n;
}
static void dlink_push_back(dlink* l, dlink* n) { dlink_insert_after(l->prev, n); }

struct conn;
struct ps_sub;

/* An IPv4 or IPv6 address (IPv4 stored as IPv4-mapped IPv6). */
typedef struct { uint8_t b[16]; } ipaddr;
typedef struct { ipaddr net; int bits; } cidr;

/* Settings from the command line. */
static const char* g_bind = "0.0.0.0";
static int     g_keepalive_ms = DEFAULT_KEEPALIVE_MS;
static bool    g_proxy_protocol;
static cidr    g_trusted[MAX_TRUSTED];
static int     g_ntrusted;

/* I/O counters for benchmarking, compiled in with -DIO_STATS and shown by
   GET /stats: how many syscalls each request costs, and how many were wasted. */
enum {
    IO_RECV, IO_RECV_EMPTY,     /* recv() calls, and those that found nothing
                                   (Windows: WSARecv, and those that had to wait) */
    IO_SEND, IO_SEND_FULL,      /* send() calls, and those that found the socket full
                                   (Windows: WSASend, and those that had to wait) */
    IO_SEND_SHORT,              /* send() calls that took only part of what was offered */
    IO_MOD, IO_MOD_ADD,         /* interest changes, and those adding events */
    IO_WAIT, IO_EVENTS,         /* epoll_wait() calls, and connection events delivered */
    IO_ACCEPT, IO_ACCEPT_EMPTY, /* accept() calls, and those that found nothing */
    IO_NSTATS
};
#ifdef IO_STATS                 /* single writer, so no atomic read-modify-write */
static const char* const io_stat_names[IO_NSTATS] = {
    "recv", "recv_empty", "send", "send_full", "send_short", "mod", "mod_add",
    "wait", "events", "accept", "accept_empty",
};
#define IOSTAT(r, k, n) atomic_store_explicit(&(r)->io[k], \
            atomic_load_explicit(&(r)->io[k], memory_order_relaxed) + (n), memory_order_relaxed)
#else
#define IOSTAT(r, k, n) ((void)0)
#endif

/* Per-thread reactor. Atomics are the only fields other threads read; the
   inbox is the only field they write (under its lock). */
struct reactor {
    int id, port;
    sock_t lfd, wakefd, inboxfd;
    poll_t ep;
    pthread_t thread;
    int64_t now;               /* cached monotonic ms, refreshed after each epoll_wait */
    dlink live;                /* live connections, earliest deadline first */
    bool stopping;

    pthread_mutex_t inbox_lock;/* migration inbox: other reactors push, we drain */
    struct conn* inbox;
    bool inbox_closed;
    unsigned next_home;        /* Windows acceptor: round-robin cursor over reactors */

    int64_t next_tick, tick_wall_ns, tick_cpu_ns;

    sock_t psfd;               /* wake-up handle: subscribers here have mail */
    pthread_mutex_t wq_lock;   /* pub/sub wake queue: any thread pushes, we drain */
    struct ps_sub** wq;
    int nwq, wq_cap;
    struct ps_sub** wq_spare;  /* swapped with wq while draining */
    int wq_spare_cap;

    struct conn** heap;        /* handler timers: min-heap ordered by conn->wake_at */
    int nheap, heap_cap;

    struct conn* graveyard;    /* finished connections, freed after the current batch */

    http_ctx* ctx_cache[CTX_CACHE];
    int nctx_cache;
    time_t date_sec;
    char date[40];             /* cached IMF-fixdate for the Date header */

    _Atomic int  load_pm;      /* CPU load over the last window, per mille of one core */
    _Atomic int  active;
    _Atomic long requests, migrated_in, migrated_out;
    _Atomic long io[IO_NSTATS];/* -DIO_STATS counters; only this reactor writes them */
#ifdef _WIN32
    struct accept_op* acc;     /* reactor 0: its AcceptEx operations */
    int lfamily;               /* ... and the listener's address family */
    int naccept;               /* AcceptEx operations in flight */
    int ndraining;             /* closed connections waiting for their last completion */
    int nlimbo;                /* connections migrating away, waiting for a cancelled read */
#endif
};

static struct reactor* g_reactors;
static int g_nreactors;
static const http_route* g_routes;
static llhttp_settings_t g_parser_settings;

/* Wake a reactor: stop, adopt its inbox, or deliver pub/sub mail. */
enum { NOTE_STOP, NOTE_INBOX, NOTE_PS };
#ifdef _WIN32
enum { KEY_IO = 1, KEY_ACCEPT, KEY_STOP, KEY_INBOX, KEY_PS, KEY_KICK };   /* completion keys */
static void reactor_notify(struct reactor* r, int what) {
    PostQueuedCompletionStatus(r->ep, 0, what == NOTE_STOP ? KEY_STOP : what == NOTE_INBOX ? KEY_INBOX : KEY_PS, NULL);
}
#else
static void reactor_notify(struct reactor* r, int what) {
    notify_signal(what == NOTE_STOP ? r->wakefd : what == NOTE_INBOX ? r->inboxfd : r->psfd);
}
#endif

#ifndef _WIN32
/* epoll data.ptr tags for the non-connection fds */
static char LISTENER_TAG, WAKE_TAG, INBOX_TAG, PS_TAG;
#endif

static __thread struct reactor* tls_reactor;    /* the reactor running on this thread */

enum { BODY_DISCARD, BODY_BUFFER, BODY_STREAM };

/* Per-request state. Allocated when a request's first byte arrives and
   recycled through the reactor's cache afterwards, so idle keep-alive
   connections only cost their socket buffer. */
struct http_ctx {
    struct conn* c;
    const http_route* route;

    /* request head (all strings point into arena) */
    http_str method, target, path, query;
    int version_major, version_minor;
    http_header headers[MAX_HEADERS];
    int nheaders;
    struct { http_str name, value; } params[MAX_PARAMS];
    int nparams;
    int64_t content_length;    /* -1 if absent */
    bool chunked, expect_continue, is_head, keep_alive;
    bool head_done, msg_done;
    int hstate;                /* 0 none, 1 in header field, 2 in header value */

    /* request body */
    int body_mode;
    char* body;                /* buffered body (heap) */
    size_t body_len, body_cap, body_limit, discarded;
    http_str chunk;            /* streaming: current chunk, points into conn->in */
    bool want_body;            /* streaming handler is awaiting http_body_ready() */

    /* response */
    int err;                   /* nonzero: respond with this status and stop */
    bool head_sent, ended, chunked_out, close, want_write, sent_continue;
    int open_chunk;            /* offset of the reserved chunk-size field in out, or -1 */
    char* ext;                 /* large buffered response body (heap) */
    size_t ext_len, ext_off;
    int xhdr_len;
    char xhdr[1024];           /* extra response headers from http_set_header() */

    /* proxy awareness */
    char client_ip[INET6_ADDRSTRLEN];   /* resolved http_client_ip(), cached */
    bool sse;                  /* response is text/event-stream */
    bool sse_keepalive_due;    /* reactor asks for a keepalive comment */

    /* WebSocket */
    bool ws;                   /* connection has been upgraded */
    bool ws_ping_due;          /* reactor asks for a keepalive ping */
    bool ws_ping_out;          /* ping sent, waiting to hear anything back */
    int64_t ws_ping_at;
    bool want_ws;              /* handler is awaiting ws_recv_ready() */
    bool ws_in_frame, ws_frame_fin, ws_in_msg, ws_msg_ready, ws_msg_held;
    bool ws_close_received, ws_close_queued, ws_close_pending, ws_close_sent, ws_failed;
    bool ws_pong_pending;
    int ws_msg_op, ws_close_code, ws_pong_len, ws_close_len;
    uint64_t ws_frame_left, ws_mask_pos;
    uint8_t ws_mask[4];
    char* ws_msg;              /* message being assembled (heap, up to WS_MAX_MSG) */
    size_t ws_msg_len, ws_msg_cap;
    char ws_pong[125], ws_closebuf[125];

    /* buffers (not zeroed on reuse) */
    int arena_len;
    char arena[HDR_ARENA];
    int out_off, out_len;
    char out[OUT_CAP];
};

/* Connection task. Everything that must survive a suspension point lives
   here or in its http_ctx, which is also what makes migration a pointer handoff. */
cco_task_struct (conn) {
    conn_base base;            /* must be first */
    struct reactor* r;         /* current owner; changes on migration */
    dlink link;                /* position in r->live (deadline order) */
    struct conn* inbox_next;   /* link while queued in a reactor's inbox */
    int64_t deadline;
    int64_t win_ns;            /* coroutine run time in the current window */
    int64_t settled_at;        /* ms when it last migrated (cooldown reference) */
    int64_t last_io;           /* ms of the last byte in or out */
    int64_t last_rx, last_tx;  /* ms of the last byte received / sent */
    uint64_t tx_total;         /* bytes handed to the kernel */
    uint64_t acked_last;       /* tx_total minus the kernel's send queue at the last check:
                                  bytes the peer has actually taken (WebSocket liveness) */
    int64_t kq_moved_at;       /* ms the peer was last seen taking our data */
    ipaddr peer;               /* the TCP peer (often the proxy) */
    ipaddr client;             /* the client: the peer, or from a PROXY header */
    bool client_tls;           /* PROXY v2 says the client connection used TLS */
    bool served;               /* completed a request: now idling as keep-alive */
    char client_str[INET6_ADDRSTRLEN];
    int64_t wake_at;           /* handler timer, valid while heap_idx >= 0 */
    int heap_idx;              /* position in r->heap, or -1 */
    bool timer_moved;          /* timer detached during migration, re-add on arrival */
    bool fresh;                /* in an inbox, just accepted and not started yet */
    bool timed_out, eof, paused, progress, woken, rdhup, linger;
    bool dead;                 /* finished; freed at the end of the loop iteration */
    struct conn* dead_next;
    size_t lingered;           /* bytes discarded during a lingering close */
    sock_t fd;
    uint32_t ready;            /* epoll events delivered by the reactor */
    uint32_t interest;         /* events currently registered with epoll */
    bool tx_full;              /* socket buffer full: don't send() until EPOLLOUT (Linux) */
#ifdef _WIN32
    struct io_op {             /* one overlapped read or write (see "I/O completion ports") */
        OVERLAPPED ov;         /* first: a completion hands back &ov */
        struct conn* c;
        int state;             /* IO_IDLE, IO_PENDING, or IO_DONE (completed, result not taken yet) */
        DWORD bytes;
        bool failed, cancelled;
        bool probe;            /* read: zero-byte, only to learn that data or a close arrived */
        size_t out_n;          /* write: how much of it came from x->out (the rest from x->ext) */
    } rd, wr;
    bool skip;                 /* immediate successes queue no completion (io_set_modes) */
    bool probe_seen;           /* a probe found data or a close: don't probe again until it reads */
    bool kick_pending;         /* `kick` is queued: run it again next round (resume) */
    OVERLAPPED kick;
    bool migrating;            /* moving to migrate_to once its cancelled read completes */
    bool shrink_wanted;        /* shrinking `in` once its cancelled read completes */
    bool buried;               /* dead: freed when its last operation completes */
    struct reactor* migrate_to;
#endif
    http_ctx* x;               /* current request, or NULL between requests */
    struct http_task* task;    /* current streaming/WebSocket handler, or NULL */
    http_stream_fn task_fn;    /* ... and its function */
    struct ps_sub* sub;        /* pub/sub subscription of the current handler, or NULL */
    llhttp_t parser;
    int in_off, in_len;        /* unparsed input is in[in_off .. in_len) */
    int in_cap;                /* size of in: IN_CAP, or IN_BIG_CAP while grown (in_grow) */
    char* in;                  /* in_small, or a heap buffer while receiving bulk data */
    char in_small[IN_CAP];     /* last: not zeroed on accept */
};

#define conn_of(lnk) c_container_of(lnk, struct conn, link)

enum { IO_IDLE, IO_PENDING, IO_DONE };

/* Windows: the kernel owns part of `in` while a read is posted or its result
   hasn't been taken, and part of the output buffers while a write is. */
#ifdef _WIN32
static bool in_busy(const struct conn* c) { return c->rd.state != IO_IDLE && !c->rd.probe; }
static bool out_busy(const struct conn* c) { return c->wr.state == IO_PENDING; }
static bool io_busy(const struct conn* c) {
    return c->rd.state == IO_PENDING || c->wr.state == IO_PENDING || c->kick_pending;
}
#else
static bool in_busy(const struct conn* c) { (void)c; return false; }
static bool out_busy(const struct conn* c) { (void)c; return false; }
static bool io_busy(const struct conn* c) { (void)c; return false; }
#endif

/* ---- Deadlines ---- */

/* All deadlines armed here are now + TIMEOUT_MS, so appending keeps the list sorted. */
static void arm_deadline(struct conn* c) {
    c->deadline = c->r->now + TIMEOUT_MS;
    dlink_remove(&c->link);
    dlink_push_back(&c->r->live, &c->link);
}

/* Re-arm the deadline because bytes moved (or a request started). */
static void touch(struct conn* c) {
    c->last_io = c->r->now;
    arm_deadline(c);
}

/* A migrated connection keeps its original deadline, which may be earlier than
   ones already queued here, so walk back from the tail to its sorted place. */
static void insert_by_deadline(struct reactor* r, struct conn* c) {
    dlink* pos = r->live.prev;
    while (pos != &r->live && conn_of(pos)->deadline > c->deadline)
        pos = pos->prev;
    dlink_insert_after(pos, &c->link);
}

/* What the connection waits for. On Linux this is its epoll registration
   (EPOLLRDHUP goes with EPOLLIN: a streaming handler that stops reading then
   just drops EPOLLIN). On Windows io_arm() acts on it after the coroutine
   yields: EPOLLIN or EPOLLRDHUP keep a read posted. */
static void set_interest(struct conn* c, uint32_t events) {
    if ((events & EPOLLIN) && !c->rdhup) events |= EPOLLRDHUP;
#ifdef _WIN32
    c->interest = events;
#else
    if (c->interest == events) return;
    IOSTAT(c->r, IO_MOD, 1);
    IOSTAT(c->r, IO_MOD_ADD, (events & ~c->interest) != 0);
    struct epoll_event ev = {.events = events, .data.ptr = c};
    epoll_ctl(c->r->ep, EPOLL_CTL_MOD, c->fd, &ev);
    c->interest = events;
#endif
}

/* ---- Handler timers: per-reactor binary min-heap on conn->wake_at ---- */

static void heap_swap(struct reactor* r, int i, int j) {
    struct conn* t = r->heap[i];
    r->heap[i] = r->heap[j];
    r->heap[j] = t;
    r->heap[i]->heap_idx = i;
    r->heap[j]->heap_idx = j;
}
static void heap_up(struct reactor* r, int i) {
    while (i > 0) {
        int p = (i - 1) / 2;
        if (r->heap[p]->wake_at <= r->heap[i]->wake_at) break;
        heap_swap(r, i, p);
        i = p;
    }
}
static void heap_down(struct reactor* r, int i) {
    for (;;) {
        int l = 2 * i + 1, rt = l + 1, m = i;
        if (l < r->nheap && r->heap[l]->wake_at < r->heap[m]->wake_at) m = l;
        if (rt < r->nheap && r->heap[rt]->wake_at < r->heap[m]->wake_at) m = rt;
        if (m == i) return;
        heap_swap(r, i, m);
        i = m;
    }
}
static bool heap_push(struct reactor* r, struct conn* c) {
    if (r->nheap == r->heap_cap) {
        int cap = r->heap_cap ? r->heap_cap * 2 : 64;
        struct conn** h = realloc(r->heap, (size_t)cap * sizeof *h);
        if (!h) return false;
        r->heap = h;
        r->heap_cap = cap;
    }
    r->heap[r->nheap] = c;
    c->heap_idx = r->nheap++;
    heap_up(r, c->heap_idx);
    return true;
}
static void heap_remove(struct reactor* r, struct conn* c) {
    int i = c->heap_idx;
    if (i < 0) return;
    int last = --r->nheap;
    if (i != last) {
        r->heap[i] = r->heap[last];
        r->heap[i]->heap_idx = i;
        heap_down(r, i);
        heap_up(r, i);
    }
    c->heap_idx = -1;
}
/* Wake the connection at `when` (keeping an earlier wake-up if one is set). */
static void timer_arm(struct conn* c, int64_t when) {
    if (c->heap_idx >= 0) {
        if (c->wake_at <= when) return;
        heap_remove(c->r, c);
    }
    c->wake_at = when;
    heap_push(c->r, c);
}

/* ---- Request contexts ---- */

static http_ctx* ctx_acquire(struct conn* c) {
    struct reactor* r = c->r;
    http_ctx* x = r->nctx_cache ? r->ctx_cache[--r->nctx_cache] : malloc(sizeof *x);
    if (!x) return NULL;
    memset(x, 0, offsetof(http_ctx, arena));
    x->c = c;
    x->content_length = -1;
    x->open_chunk = -1;
    x->arena_len = x->out_off = x->out_len = 0;
    return x;
}

static void ctx_release(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return;
    free(x->body);
    free(x->ext);
    free(x->ws_msg);
    struct reactor* r = c->r;
    if (r->nctx_cache < CTX_CACHE) r->ctx_cache[r->nctx_cache++] = x;
    else free(x);
    c->x = NULL;
}

/* ======================================================================== */
/* llhttp callbacks: copy the request head into the context's arena, and    */
/* route body bytes according to the body mode                              */
/* ======================================================================== */

static http_ctx* parser_ctx(llhttp_t* p) { return ((struct conn*)p->data)->x; }

static int arena_append(http_ctx* x, const char* at, size_t n) {
    if (x->arena_len + n > HDR_ARENA) { x->err = 431; return -1; }
    memcpy(x->arena + x->arena_len, at, n);
    x->arena_len += (int)n;
    return 0;
}

static int on_url(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (!x->target.ptr) x->target.ptr = x->arena + x->arena_len;
    if (arena_append(x, at, n) < 0) return -1;
    x->target.len += n;
    return 0;
}

static int on_header_field(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (x->hstate != 1) {                       /* a new header begins */
        if (x->nheaders == MAX_HEADERS) { x->err = 431; return -1; }
        http_header* h = &x->headers[x->nheaders++];
        h->name = (http_str){x->arena + x->arena_len, 0};
        h->value = (http_str){"", 0};
        x->hstate = 1;
    }
    if (arena_append(x, at, n) < 0) return -1;
    x->headers[x->nheaders - 1].name.len += n;
    return 0;
}

static int on_header_value(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    http_header* h = &x->headers[x->nheaders - 1];
    if (x->hstate != 2) {
        h->value = (http_str){x->arena + x->arena_len, 0};
        x->hstate = 2;
    }
    if (arena_append(x, at, n) < 0) return -1;
    h->value.len += n;
    return 0;
}

static int on_headers_complete(llhttp_t* p) {
    http_ctx* x = parser_ctx(p);
    const char* m = llhttp_method_name((llhttp_method_t)llhttp_get_method(p));
    x->method = (http_str){m, strlen(m)};
    x->version_major = llhttp_get_http_major(p);
    x->version_minor = llhttp_get_http_minor(p);
    if (!x->target.ptr) x->target = (http_str){"/", 1};
    const char* q = memchr(x->target.ptr, '?', x->target.len);
    x->path = (http_str){x->target.ptr, q ? (size_t)(q - x->target.ptr) : x->target.len};
    x->query = q ? (http_str){q + 1, x->target.len - x->path.len - 1} : (http_str){"", 0};
    x->content_length = (p->flags & F_CONTENT_LENGTH) ? (int64_t)p->content_length : -1;
    x->chunked = (p->flags & F_CHUNKED) != 0;
    x->keep_alive = llhttp_should_keep_alive(p);
    x->is_head = http_str_eq(x->method, "HEAD");
    http_str ex = http_header_get(x, "expect");
    x->expect_continue = ex.len == 12 && strncasecmp(ex.ptr, "100-continue", 12) == 0;
    x->head_done = true;
    return HPE_PAUSED;          /* stop here: route before touching the body */
}

static int on_body(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (n == 0) return 0;       /* llhttp reports empty spans when resumed without input */
    switch (x->body_mode) {
    case BODY_STREAM:
        x->chunk = (http_str){at, n};           /* zero-copy: points into conn->in */
        return HPE_PAUSED;                      /* hold parsing until it's taken */
    case BODY_BUFFER:
        if (x->body_len + n > x->body_limit) { x->err = 413; return -1; }
        if (x->body_len + n > x->body_cap) {
            size_t cap = x->body_cap ? x->body_cap * 2 : 4096;
            while (cap < x->body_len + n) cap *= 2;
            if (cap > x->body_limit) cap = x->body_limit;
            char* b = realloc(x->body, cap);
            if (!b) { x->err = 500; return -1; }
            x->body = b;
            x->body_cap = cap;
        }
        memcpy(x->body + x->body_len, at, n);
        x->body_len += n;
        return 0;
    default:                                    /* BODY_DISCARD */
        x->discarded += n;
        if (x->discarded > MAX_DRAIN) { x->close = true; return -1; }
        return 0;
    }
}

static int on_message_complete(llhttp_t* p) {
    parser_ctx(p)->msg_done = true;
    return HPE_PAUSED;          /* don't start parsing a pipelined request yet */
}

/* ---- Input ---- */

/* Parse buffered input. Returns 0, or -1 on a protocol error (x->err set). */
static int feed(struct conn* c) {
    http_ctx* x = c->x;
    const char* start = c->in + c->in_off;
    llhttp_errno_t e = llhttp_execute(&c->parser, start, (size_t)(c->in_len - c->in_off));
    if (e == HPE_OK) {
        c->in_off = c->in_len;
        c->paused = false;
    } else if (e == HPE_PAUSED) {
        c->in_off = (int)(llhttp_get_error_pos(&c->parser) - c->in);
        llhttp_resume(&c->parser);
        c->paused = true;       /* a zero-byte feed may still make progress */
    } else {
        if (!x->err) x->err = 400;              /* HPE_USER keeps our own status */
        x->close = true;
        return -1;
    }
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
    return 0;
}

/* The input buffer starts as the 16 KiB one inside the connection. A read that
   fills it completely means more is waiting (a large body, a busy WebSocket),
   so it grows to IN_BIG_CAP: each recv() then moves 4x as much, and streaming
   handlers are resumed 4x less often, which matters most on Windows where each
   socket call costs more. It shrinks back once the connection sits idle
   between requests (in_shrink), so idle keep-alive connections stay small. */
static void in_grow(struct conn* c) {
    char* big = malloc(IN_BIG_CAP);
    if (!big) return;                           /* keep working with the small one */
    memcpy(big, c->in, (size_t)c->in_len);
    c->in = big;
    c->in_cap = IN_BIG_CAP;
}

static void in_shrink(struct conn* c) {
    if (c->in == c->in_small || c->in_len - c->in_off > IN_CAP || in_busy(c)) return;
    memcpy(c->in_small, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
    free(c->in);
    c->in = c->in_small;
    c->in_cap = IN_CAP;
    c->in_len -= c->in_off;
    c->in_off = 0;
}

#ifdef _WIN32
/* Post an overlapped read into the free end of `in`: the data lands in place,
   with no copy and no separate recv(). Leaves rd PENDING, or DONE if it
   completed at once (data was already waiting).
   A probe reads zero bytes instead: it only tells a connection that isn't
   reading that data or a close arrived, and never writes into `in` (a
   handler may still hold a body chunk pointing into it). */
static void rd_post(struct conn* c, bool probe) {
    struct io_op* op = &c->rd;
    memset(&op->ov, 0, sizeof op->ov);
    static char none;
    WSABUF b = probe ? (WSABUF){0, &none} : (WSABUF){(ULONG)(c->in_cap - c->in_len), c->in + c->in_len};
    DWORD n = 0, flags = 0;
    IOSTAT(c->r, IO_RECV, 1);
    int rc = WSARecv(c->fd, &b, 1, &n, &flags, &op->ov, NULL);
    op->cancelled = false;
    op->probe = probe;
    if (!probe) c->probe_seen = false;
    if (rc == 0 && c->skip) {
        op->state = IO_DONE;
        op->bytes = n;
        op->failed = false;
    } else if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) {
        op->state = IO_PENDING;                 /* a completion will follow */
        IOSTAT(c->r, IO_RECV_EMPTY, 1);
    } else {
        op->state = IO_DONE;
        op->bytes = 0;
        op->failed = true;
    }
}

/* Take a completed read's result, like recv(): bytes, or -1 on EOF or error. */
static int rd_take(struct conn* c) {
    struct io_op* op = &c->rd;
    op->state = IO_IDLE;
    if (op->failed || op->bytes == 0) return -1;
    c->in_len += (int)op->bytes;
    c->last_rx = c->r->now;
    if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
    return (int)op->bytes;
}

/* The event bits a completed read stands for. */
static uint32_t rd_bits(const struct conn* c) {
    return c->rd.failed ? EPOLLIN | EPOLLERR | EPOLLHUP : c->rd.bytes ? EPOLLIN : EPOLLIN | EPOLLRDHUP;
}

/* A probe completed: data waiting, the peer closed, or an error? (A zero-byte
   read completes the same way for data and for a close, so peek.) Returns the
   event bits, 0 if it was spurious; the read slot is free again either way. */
static uint32_t probe_result(struct conn* c) {
    c->rd.state = IO_IDLE;
    uint32_t bits;
    if (c->rd.failed) {
        bits = EPOLLIN | EPOLLERR | EPOLLHUP;
    } else {
        char b;
        int n = recv(c->fd, &b, 1, MSG_PEEK);
        bits = n > 0 ? EPOLLIN : n == 0 ? EPOLLIN | EPOLLRDHUP
             : WSAGetLastError() == WSAEWOULDBLOCK ? 0 : EPOLLIN | EPOLLERR | EPOLLHUP;
    }
    if (bits) c->probe_seen = true;     /* no new probe until it reads */
    return bits;
}
#endif

/* Read from the socket. Returns bytes read, 0 if nothing available (or no
   room), -1 on EOF or error. Only called when no stream chunk is outstanding,
   so compacting or growing the buffer can't invalidate a pointer a handler holds. */
static int fill(struct conn* c) {
#ifdef _WIN32
    if (c->rd.state == IO_PENDING) return 0;
    if (c->rd.state == IO_DONE) return rd_take(c);
#endif
    if (c->in_off > 0) {
        memmove(c->in, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
        c->in_len -= c->in_off;
        c->in_off = 0;
    }
    if (c->in_len == c->in_cap) return 0;
#ifdef _WIN32
    rd_post(c, false);
    return c->rd.state == IO_DONE ? rd_take(c) : 0;
#else
    ssize_t n = sock_recv(c->fd, c->in + c->in_len, (size_t)(c->in_cap - c->in_len));
    IOSTAT(c->r, IO_RECV, 1);
    if (n > 0) {
        c->in_len += (int)n;
        c->last_rx = c->r->now;
        if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
        return (int)n;
    }
    if (n < 0 && would_block()) { IOSTAT(c->r, IO_RECV_EMPTY, 1); return 0; }
    return -1;
#endif
}

/* ======================================================================== */
/* Request accessors                                                        */
/* ======================================================================== */

http_str http_method(const http_ctx* x) { return x->method; }
http_str http_path(const http_ctx* x) { return x->path; }
http_str http_body(const http_ctx* x) { return (http_str){x->body ? x->body : "", x->body_len}; }

http_str http_header_get(const http_ctx* x, const char* name) {
    size_t n = strlen(name);
    for (int i = 0; i < x->nheaders; ++i)
        if (x->headers[i].name.len == n && strncasecmp(x->headers[i].name.ptr, name, n) == 0)
            return x->headers[i].value;
    return (http_str){NULL, 0};
}

http_str http_param(const http_ctx* x, const char* name) {
    for (int i = 0; i < x->nparams; ++i)
        if (http_str_eq(x->params[i].name, name)) return x->params[i].value;
    return (http_str){NULL, 0};
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Percent-decode src into dst (NUL-terminated). Returns length, or -1 if it
   doesn't fit. plus_is_space applies to query strings. */
static int url_decode(http_str src, char* dst, size_t cap, bool plus_is_space) {
    size_t j = 0;
    for (size_t i = 0; i < src.len; ++i) {
        char ch = src.ptr[i];
        if (ch == '%' && i + 2 < src.len
            && hexval(src.ptr[i + 1]) >= 0 && hexval(src.ptr[i + 2]) >= 0) {
            ch = (char)(hexval(src.ptr[i + 1]) * 16 + hexval(src.ptr[i + 2]));
            i += 2;
        } else if (ch == '+' && plus_is_space) {
            ch = ' ';
        }
        if (j + 1 >= cap) return -1;
        dst[j++] = ch;
    }
    if (cap) dst[j] = '\0';
    return (int)j;
}

/* Find query parameter `key`, decode its value into buf. */
bool http_query(const http_ctx* x, const char* key, char* buf, size_t cap) {
    size_t klen = strlen(key);
    const char* p = x->query.ptr;
    const char* end = p + x->query.len;
    while (p < end) {
        const char* amp = memchr(p, '&', (size_t)(end - p));
        const char* stop = amp ? amp : end;
        const char* eq = memchr(p, '=', (size_t)(stop - p));
        const char* kend = eq ? eq : stop;
        if ((size_t)(kend - p) == klen && memcmp(p, key, klen) == 0) {
            http_str v = eq ? (http_str){eq + 1, (size_t)(stop - eq - 1)} : (http_str){"", 0};
            return url_decode(v, buf, cap, true) >= 0;
        }
        p = stop + 1;
    }
    return false;
}

/* ---- Streaming request body ---- */

bool http_body_ready(http_ctx* x) {
    if (x->chunk.len > 0 || x->msg_done) return true;
    x->want_body = true;        /* tells the connection to read and parse more */
    return false;
}
bool http_body_done(const http_ctx* x) { return x->msg_done && x->chunk.len == 0; }
/* At most HTTP_SEND_MAX bytes at a time, so a chunk can always be passed
straight to http_send(); the rest stays for the next call. */
http_str http_body_take(http_ctx* x) {
    http_str s = x->chunk;
    if (s.len > HTTP_SEND_MAX) s.len = HTTP_SEND_MAX;
    x->chunk.ptr += s.len;
    x->chunk.len -= s.len;
    if (!x->chunk.len) x->chunk.ptr = NULL;
    return s;
}

/* ======================================================================== */
/* Response writing                                                         */
/* ======================================================================== */

static const char* reason_phrase(int s) {
    switch (s) {
    case 100: return "Continue";            case 101: return "Switching Protocols";
    case 200: return "OK";                  case 426: return "Upgrade Required";
    case 201: return "Created";             case 202: return "Accepted";
    case 204: return "No Content";          case 301: return "Moved Permanently";
    case 302: return "Found";               case 304: return "Not Modified";
    case 400: return "Bad Request";         case 401: return "Unauthorized";
    case 403: return "Forbidden";           case 404: return "Not Found";
    case 405: return "Method Not Allowed";  case 408: return "Request Timeout";
    case 409: return "Conflict";            case 413: return "Content Too Large";
    case 414: return "URI Too Long";        case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content"; case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

static const char* cached_date(struct reactor* r) {
    time_t t = time(NULL);
    if (t != r->date_sec) {
        struct tm tm;
        gmtime_r(&t, &tm);
        strftime(r->date, sizeof r->date, "%a, %d %b %Y %H:%M:%S GMT", &tm);
        r->date_sec = t;
    }
    return r->date;
}

/* ---- Formatting ----
   printf is the main cost of handlers that format their output: 40-75 ns a
   call on Windows, several times the cost of the work itself. So the *printf
   handler APIs and the response headers go through fmt_v(), which does the
   common conversions itself: %d %i %u %x %X %c %s and %%, with the l, ll and z
   length modifiers, the '-' and '0' flags, a field width, and a precision for
   %s (width and precision may be '*'). On anything else it starts over with
   vsnprintf, from a copy of the arguments taken on entry. Same result as
   vsnprintf: returns the full length, writes at most cap-1 characters and a NUL. */

typedef struct { char* p; size_t room, n; } fmt_out;    /* room: capacity minus the NUL */

static void fmt_put(fmt_out* o, const char* s, size_t len) {
    if (o->n < o->room) {
        size_t k = o->room - o->n;
        if (len < k) k = len;
        char* d = o->p + o->n;
        if (k <= 16) while (k--) *d++ = *s++;   /* most pieces are short: skip the call */
        else memcpy(d, s, k);
    }
    o->n += len;
}

static void fmt_pad(fmt_out* o, char c, size_t len) {
    if (o->n < o->room) {
        size_t k = o->room - o->n;
        memset(o->p + o->n, c, len < k ? len : k);
    }
    o->n += len;
}

static int fmt_v(char* buf, size_t cap, const char* f, va_list ap) {
    const char* start = f;
    va_list ap0;
    va_copy(ap0, ap);
    fmt_out o = {buf, cap ? cap - 1 : 0, 0};
    while (*f) {
        const char* lit = f;
        while (*f && *f != '%') ++f;
        if (f > lit) fmt_put(&o, lit, (size_t)(f - lit));
        if (!*f) break;
        if (*++f == '%') { fmt_put(&o, "%", 1); ++f; continue; }
        bool left = false, zero = false;
        for (;; ++f) {
            if (*f == '-') left = true;
            else if (*f == '0') zero = true;
            else break;
        }
        int width = 0, prec = -1;
        if (*f == '*') {
            width = va_arg(ap, int);
            if (width < 0) { left = true; width = width == INT_MIN ? INT_MAX : -width; }
            ++f;
        } else {
            while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        }
        bool has_prec = *f == '.';
        if (has_prec) {
            prec = 0;
            if (*++f == '*') { prec = va_arg(ap, int); ++f; }   /* negative: no precision */
            else while (*f >= '0' && *f <= '9') prec = prec * 10 + (*f++ - '0');
        }
        int size = 0;                                       /* 0 int, 1 long, 2 long long, 3 size_t */
        if (*f == 'l') { size = 1; if (*++f == 'l') { size = 2; ++f; } }
        else if (*f == 'z') { size = 3; ++f; }
        char conv = *f++;

        char tmp[24];
        const char* s;
        size_t n;
        bool neg = false;
        if (conv == 's' && size == 0) {
            s = va_arg(ap, const char*);
            if (!s) s = "(null)";
            if (prec >= 0) { const char* e = memchr(s, '\0', (size_t)prec); n = e ? (size_t)(e - s) : (size_t)prec; }
            else n = strlen(s);
            zero = false;
        } else if (conv == 'c' && size == 0 && !has_prec) {
            tmp[0] = (char)va_arg(ap, int);
            s = tmp;
            n = 1;
            zero = false;
        } else if ((conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x' || conv == 'X') && !has_prec) {
            unsigned long long v;
            if (conv == 'd' || conv == 'i') {
                long long sv = size == 0 ? va_arg(ap, int) : size == 1 ? va_arg(ap, long)
                             : size == 2 ? va_arg(ap, long long) : (long long)va_arg(ap, ptrdiff_t);
                neg = sv < 0;
                v = neg ? 0ULL - (unsigned long long)sv : (unsigned long long)sv;
            } else {
                v = size == 0 ? va_arg(ap, unsigned) : size == 1 ? va_arg(ap, unsigned long)
                  : size == 2 ? va_arg(ap, unsigned long long) : va_arg(ap, size_t);
            }
            char* e = tmp + sizeof tmp;
            char* d = e;
            if (conv == 'x' || conv == 'X') {       /* constant bases: shifts and multiplies */
                const char* digits = conv == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
                do *--d = digits[v & 15]; while ((v >>= 4));
            } else if (v <= UINT32_MAX) {           /* 32-bit division is cheaper still */
                uint32_t w = (uint32_t)v;
                do *--d = (char)('0' + w % 10); while ((w /= 10));
            } else {
                do *--d = (char)('0' + v % 10); while ((v /= 10));
            }
            s = d;
            n = (size_t)(e - d);
        } else {                                    /* not ours (or a stray '%' at the end) */
            int r = vsnprintf(buf, cap, start, ap0);
            va_end(ap0);
            return r;
        }
        size_t body = n + neg;
        size_t fill = (size_t)width > body ? (size_t)width - body : 0;
        if (!left && !zero) fmt_pad(&o, ' ', fill);
        if (neg) fmt_put(&o, "-", 1);
        if (!left && zero) fmt_pad(&o, '0', fill);
        fmt_put(&o, s, n);
        if (left) fmt_pad(&o, ' ', fill);
    }
    va_end(ap0);
    if (cap) buf[o.n < o.room ? o.n : o.room] = '\0';
    return o.n > INT_MAX ? INT_MAX : (int)o.n;
}

static int fmt_to(char* buf, size_t cap, const char* f, ...) PRINTF_LIKE(3, 4);
static int fmt_to(char* buf, size_t cap, const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = fmt_v(buf, cap, f, ap);
    va_end(ap);
    return n;
}

static void out_compact(http_ctx* x) {
    if (x->out_off == 0 || out_busy(x->c)) return;     /* the kernel is still reading it */
    memmove(x->out, x->out + x->out_off, (size_t)(x->out_len - x->out_off));
    if (x->open_chunk >= 0) x->open_chunk -= x->out_off;
    x->out_len -= x->out_off;
    x->out_off = 0;
}

void http_set_header(http_ctx* x, const char* name, const char* value) {
    if (x->head_sent) return;
    int n = fmt_to(x->xhdr + x->xhdr_len, sizeof x->xhdr - (size_t)x->xhdr_len,
                   "%s: %s\r\n", name, value);
    if (n > 0 && x->xhdr_len + n < (int)sizeof x->xhdr) x->xhdr_len += n;
}

/* Status line + headers. content_length < 0 means a streamed body. */
static void write_head(http_ctx* x, int status, const char* ctype, int64_t content_length) {
    if (x->head_sent) return;
    bool streamed = content_length < 0;
    x->chunked_out = streamed && (x->version_major > 1 || x->version_minor >= 1);
    if (streamed && !x->chunked_out) x->close = true;   /* HTTP/1.0: body ends at close */
    bool keep = x->keep_alive && !x->close;

    out_compact(x);
    char* p = x->out + x->out_len;
    size_t cap = OUT_CAP - (size_t)x->out_len;
    int n = fmt_to(p, cap, "HTTP/1.1 %d %s\r\nDate: %s\r\n", status, reason_phrase(status),
                   cached_date(x->c->r));
    if (ctype) n += fmt_to(p + n, cap - (size_t)n, "Content-Type: %s\r\n", ctype);
    if (streamed && ctype && strncmp(ctype, "text/event-stream", 17) == 0) {
        x->sse = true;          /* eligible for keepalive comments */
        n += fmt_to(p + n, cap - (size_t)n, "X-Accel-Buffering: no\r\n");   /* nginx: don't buffer */
    }
    if (!streamed)
        n += fmt_to(p + n, cap - (size_t)n, "Content-Length: %lld\r\n", (long long)content_length);
    else if (x->chunked_out)
        n += fmt_to(p + n, cap - (size_t)n, "Transfer-Encoding: chunked\r\n");
    if (!keep)
        n += fmt_to(p + n, cap - (size_t)n, "Connection: close\r\n");
    else if (x->version_minor == 0)
        n += fmt_to(p + n, cap - (size_t)n, "Connection: keep-alive\r\n");
    n += fmt_to(p + n, cap - (size_t)n, "%.*s\r\n", x->xhdr_len, x->xhdr);
    x->out_len += n;
    x->head_sent = true;
}

void http_respond(http_ctx* x, int status, const char* ctype, const void* body, size_t len) {
    if (x->head_sent) return;
    write_head(x, status, ctype, (int64_t)len);
    x->ended = true;
    if (x->is_head || len == 0) return;
    if (len <= OUT_CAP - (size_t)x->out_len) {
        memcpy(x->out + x->out_len, body, len);
        x->out_len += (int)len;
    } else {                                    /* too big for the buffer: keep a copy */
        x->ext = malloc(len);
        if (!x->ext) { x->close = true; return; }
        memcpy(x->ext, body, len);
        x->ext_len = len;
        x->ext_off = 0;
    }
}

void http_respondf(http_ctx* x, int status, const char* ctype, const char* fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
    http_respond(x, status, ctype, buf, (size_t)n);
}

void http_start(http_ctx* x, int status, const char* ctype) {
    write_head(x, status, ctype, -1);
}

/* Close the open chunk: fill in its reserved size field and add the CRLF. */
static void close_chunk(http_ctx* x) {
    if (x->open_chunk < 0) return;
    size_t size = (size_t)(x->out_len - x->open_chunk - 10);
    if (size == 0) {
        x->out_len = x->open_chunk;             /* nothing was written: drop the header */
    } else {
        char hdr[24];           /* size < OUT_CAP, so it always fits in 8 hex digits */
        fmt_to(hdr, sizeof hdr, "%08x\r\n", (unsigned)size);     /* leading zeros are valid */
        memcpy(x->out + x->open_chunk, hdr, 10);
        memcpy(x->out + x->out_len, "\r\n", 2);
        x->out_len += 2;
    }
    x->open_chunk = -1;
}

/* Queue body bytes. All-or-nothing: returns false (and asks the connection to
   flush) if they don't fit yet, so handlers write cco_await(http_send(...)).
   Consecutive sends between flushes are coalesced into one chunk. */
bool http_send(http_ctx* x, const void* data, size_t len) {
    if (!x->head_sent) http_start(x, 200, "application/octet-stream");
    if (x->ended || x->is_head || len == 0) return true;
    if (len > HTTP_SEND_MAX) len = HTTP_SEND_MAX;   /* contract violation: truncate */
    size_t need = len;
    if (x->chunked_out) need += (x->open_chunk < 0 ? 10 : 0) + 2 + 5;  /* size, CRLF, room for end */
    if (need > OUT_CAP - (size_t)x->out_len) out_compact(x);
    if (need > OUT_CAP - (size_t)x->out_len) {
        x->want_write = true;
        return false;
    }
    if (x->chunked_out && x->open_chunk < 0) {
        x->open_chunk = x->out_len;
        x->out_len += 10;
    }
    memcpy(x->out + x->out_len, data, len);
    x->out_len += (int)len;
    return true;
}

bool http_sendf(http_ctx* x, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return true;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
return http_send(x, buf, (size_t)n);
}

void http_end(http_ctx* x) {
    if (!x->head_sent) http_start(x, 200, "application/octet-stream");
    if (x->ended) return;
    x->ended = true;
    if (!x->chunked_out || x->is_head) return;
    close_chunk(x);
    if (5 > OUT_CAP - x->out_len) out_compact(x);
    memcpy(x->out + x->out_len, "0\r\n\r\n", 5);   /* space was reserved by http_send */
    x->out_len += 5;
}

#ifdef _WIN32
/* Largest single WSASend: an overlapped send completes only once all of it is
   handed over, and progress (last_tx) is only seen at completion, so a large
   body goes out in steps rather than as one multi-megabyte operation. */
#define SEND_STEP (256 * 1024)

/* Account for a completed write. -1 if it failed. */
static int wr_take(struct conn* c) {
    struct io_op* op = &c->wr;
    http_ctx* x = c->x;
    op->state = IO_IDLE;
    if (op->failed) return -1;
    size_t n = op->bytes, a = n < op->out_n ? n : op->out_n;
    x->out_off += (int)a;
    x->ext_off += n - a;
    if (n) {
        c->progress = true;
        c->last_tx = c->r->now;
        c->tx_total += n;
    }
    return 0;
}

/* Send what's queued: one overlapped WSASend covering x->out and x->ext.
   Returns 1 when everything went out, 0 while a send is in flight, -1 on
   error. Sets c->progress when bytes were handed over. */
static int flush(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return 1;
    for (;;) {
        if (c->wr.state == IO_PENDING) return 0;
        if (c->wr.state == IO_DONE && wr_take(c) < 0) return -1;
        close_chunk(x);
        size_t a = (size_t)(x->out_len - x->out_off), b = x->ext_len - x->ext_off;
        if (a + b == 0) break;
        if (a > SEND_STEP) a = SEND_STEP;
        if (b > SEND_STEP - a) b = SEND_STEP - a;
        WSABUF bufs[2];
        DWORD nb = 0, sent = 0;
        if (a) bufs[nb++] = (WSABUF){(ULONG)a, x->out + x->out_off};
        if (b) bufs[nb++] = (WSABUF){(ULONG)b, x->ext + x->ext_off};
        struct io_op* op = &c->wr;
        memset(&op->ov, 0, sizeof op->ov);
        op->out_n = a;
        op->cancelled = false;
        IOSTAT(c->r, IO_SEND, 1);
        int rc = WSASend(c->fd, bufs, nb, &sent, 0, &op->ov, NULL);
        if (rc == 0 && c->skip) {               /* done at once: account and go on */
            op->state = IO_DONE;
            op->bytes = sent;
            op->failed = false;
            continue;
        }
        if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) {
            op->state = IO_PENDING;
            IOSTAT(c->r, IO_SEND_FULL, 1);
            return 0;
        }
        return -1;
    }
    x->out_off = x->out_len = 0;
    if (x->ext) {
        free(x->ext);
        x->ext = NULL;
        x->ext_len = x->ext_off = 0;
    }
    return 1;
}
#else
/* Send buf[*off .. len). Returns 1 when all of it went out, 0 if the socket
   is full, -1 on error. Sets c->progress when any byte was written. */
static int send_from(struct conn* c, const char* buf, size_t len, size_t* off) {
    if (*off < len && c->tx_full) return 0;     /* until the reactor sees EPOLLOUT */
    while (*off < len) {
        size_t want = len - *off;
        ssize_t n = sock_send(c->fd, buf + *off, want);
        IOSTAT(c->r, IO_SEND, 1);
        if (n > 0) {
            *off += (size_t)n;
            c->progress = true;
            c->last_tx = c->r->now;
            c->tx_total += (uint64_t)n;
            /* A short write means the socket buffer just filled up: another
               send() now would only fail with EAGAIN, so wait for EPOLLOUT. */
            if ((size_t)n < want) IOSTAT(c->r, IO_SEND_SHORT, 1);
            if ((size_t)n < want && want <= INT_MAX) { c->tx_full = true; return 0; }
            continue;
        }
        if (n < 0 && would_block()) { IOSTAT(c->r, IO_SEND_FULL, 1); c->tx_full = true; return 0; }
        return -1;
    }
    return 1;
}

/* Send what's queued. Returns 1 when everything went out, 0 if the socket
   is full, -1 on error. Sets c->progress when any byte was written. */
static int flush(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return 1;
    close_chunk(x);
    size_t off = (size_t)x->out_off;
    int r = send_from(c, x->out, (size_t)x->out_len, &off);
    x->out_off = (int)off;
    if (r <= 0) return r;
    x->out_off = x->out_len = 0;
    r = send_from(c, x->ext, x->ext_len, &x->ext_off);
    if (r <= 0) return r;
    if (x->ext) {
        free(x->ext);
        x->ext = NULL;
        x->ext_len = x->ext_off = 0;
    }
    return 1;
}
#endif

static void respond_error(http_ctx* x) {
    const char* msg;
    switch (x->err) {
    case 404: msg = "not found\n"; break;
    case 405: msg = "method not allowed\n"; break;
    case 413: msg = "request body too large\n"; break;
    case 431: msg = "request headers too large\n"; break;
    case 426: msg = "this endpoint requires a WebSocket upgrade\n"; break;
    case 500: msg = "internal server error\n"; break;
    default:  msg = "bad request\n"; break;
    }
    if (!x->head_sent) {
        if (x->err != 405 && x->err != 426) x->xhdr_len = 0;  /* keep Allow / Upgrade headers */
        http_respond(x, x->err, "text/plain", msg, strlen(msg));
    } else {
        x->close = true;        /* a response was already under way: cut it off */
    }
}

/* ======================================================================== */
/* Router                                                                   */
/* ======================================================================== */

/* Match a pattern against x->path. ":name" matches one non-empty segment,
   "*name" (only at the end) matches the rest of the path. Parameters are
   percent-decoded into the arena. */
static bool match_pattern(http_ctx* x, const char* pat) {
    const char* p = x->path.ptr;
    const char* pend = p + x->path.len;
    x->nparams = 0;
    int arena_mark = x->arena_len;
    while (*pat) {
        if (*pat == ':' || *pat == '*') {
            bool rest = *pat == '*';
            const char* name = ++pat;
            while (*pat && *pat != '/') ++pat;
            const char* seg = p;
            if (rest) p = pend;
            else while (p < pend && *p != '/') ++p;
            if (!rest && p == seg) goto fail;   /* ":param" must not be empty */
            if (x->nparams == MAX_PARAMS) goto fail;
            int cap = HDR_ARENA - x->arena_len;
            int n = url_decode((http_str){seg, (size_t)(p - seg)}, x->arena + x->arena_len,
                               (size_t)cap, false);
            if (n < 0) goto fail;
            x->params[x->nparams].name = (http_str){name, (size_t)(pat - name)};
            x->params[x->nparams].value = (http_str){x->arena + x->arena_len, (size_t)n};
            x->nparams++;
            x->arena_len += n + 1;
            continue;
        }
        if (p == pend || *p != *pat) goto fail;
        ++p, ++pat;
    }
    if (p == pend) return true;
fail:
    x->nparams = 0;
    x->arena_len = arena_mark;
    return false;
}

static bool method_matches(const http_route* rt, const http_ctx* x) {
    if (!rt->method) return true;
    if (http_str_eq(x->method, rt->method)) return true;
    return x->is_head && strcmp(rt->method, "GET") == 0;
}

/* Pick the route and body mode, or set x->err. */
static void dispatch(http_ctx* x) {
    char allow[128] = "";
    size_t alen = 0;
    bool path_found = false;
    for (const http_route* rt = g_routes; rt->pattern; ++rt) {
        if (!match_pattern(x, rt->pattern)) continue;
        path_found = true;
        if (method_matches(rt, x)) { x->route = rt; break; }
        if (rt->method && alen + strlen(rt->method) + 3 < sizeof allow)
            alen += (size_t)snprintf(allow + alen, sizeof allow - alen, "%s%s", alen ? ", " : "", rt->method);
    }
    if (!x->route) {
        x->err = path_found ? 405 : 404;
        if (alen) http_set_header(x, "Allow", allow);
        x->body_mode = BODY_DISCARD;
        return;
    }
    bool has_body = x->content_length > 0 || x->chunked;
    if (x->route->websocket) {
        x->body_mode = BODY_DISCARD;
        if (has_body) { x->err = 400; x->close = true; }
        return;
    }
    if (x->route->stream) {
        x->body_mode = BODY_STREAM;
    } else {
        x->body_mode = BODY_BUFFER;
        x->body_limit = x->route->body_limit ? x->route->body_limit : DEFAULT_BODY_LIMIT;
        if (x->content_length > (int64_t)x->body_limit) {
            x->err = 413;                       /* reject before reading anything */
            x->close = true;                    /* the body isn't worth draining */
            x->body_mode = BODY_DISCARD;
            return;
        }
    }
    if (x->expect_continue && has_body) {       /* client is waiting for our go-ahead */
        static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
        memcpy(x->out + x->out_len, cont, sizeof cont - 1);
        x->out_len += (int)sizeof cont - 1;
        x->sent_continue = true;
    }
}

/* ======================================================================== */
/* Handler timers                                                           */
/* ======================================================================== */

void http_timer_start(http_ctx* x, http_timer* t, int64_t ms) {
    t->when = x->c->r->now + ms;
}
bool http_timer_expired(const http_ctx* x, const http_timer* t) {
    return x->c->r->now >= t->when;
}
bool http_timer_done(http_ctx* x, http_timer* t) {
    if (http_timer_expired(x, t)) return true;
    timer_arm(x->c, t->when);   /* wake the connection then */
    return false;
}

/* ======================================================================== */
/* WebSocket                                                                */
/* ======================================================================== */

/* ---- SHA-1 and base64, for the Sec-WebSocket-Accept header ---- */

static uint32_t rol32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t nblocks = (len + 1 + 8 + 63) / 64;
    for (size_t b = 0; b < nblocks; ++b) {
        uint8_t block[64];
        for (size_t i = 0; i < 64; ++i) {
            size_t idx = b * 64 + i;
            if (idx < len) block[i] = data[idx];
            else if (idx == len) block[i] = 0x80;
            else if (idx >= nblocks * 64 - 8)
                block[i] = (uint8_t)(((uint64_t)len * 8) >> (8 * (nblocks * 64 - 1 - idx)));
            else block[i] = 0;
        }
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)block[4*i] << 24 | (uint32_t)block[4*i+1] << 16 | (uint32_t)block[4*i+2] << 8 | block[4*i+3];
        for (int i = 16; i < 80; ++i) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (bb & c) | (~bb & d);           k = 0x5A827999; }
            else if (i < 40) { f = bb ^ c ^ d;                     k = 0x6ED9EBA1; }
            else if (i < 60) { f = (bb & c) | (bb & d) | (c & d);  k = 0x8F1BBCDC; }
            else             { f = bb ^ c ^ d;                     k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol32(bb, 30); bb = a; a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
    }
    for (int i = 0; i < 5; ++i) {
        out[4*i] = (uint8_t)(h[i] >> 24); out[4*i+1] = (uint8_t)(h[i] >> 16);
        out[4*i+2] = (uint8_t)(h[i] >> 8); out[4*i+3] = (uint8_t)h[i];
    }
}

static void base64_encode(const uint8_t* in, size_t n, char* out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i+1] << 8 : 0) | (i + 2 < n ? in[i+2] : 0);
        out[j++] = tbl[(v >> 18) & 63];
        out[j++] = tbl[(v >> 12) & 63];
        out[j++] = i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < n ? tbl[v & 63] : '=';
    }
    out[j] = '\0';
}

static bool utf8_valid(const uint8_t* s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c0 = s[i];
        if (c0 < 0x80) { ++i; continue; }
        size_t len;
        uint32_t cp, min;
        if ((c0 & 0xE0) == 0xC0)      { len = 2; cp = c0 & 0x1F; min = 0x80; }
        else if ((c0 & 0xF0) == 0xE0) { len = 3; cp = c0 & 0x0F; min = 0x800; }
        else if ((c0 & 0xF8) == 0xF0) { len = 4; cp = c0 & 0x07; min = 0x10000; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

/* Is `tok` one of the comma-separated tokens in v (case-insensitive)? */
static bool header_has_token(http_str v, const char* tok) {
    size_t tl = strlen(tok);
    const char* p = v.ptr;
    const char* end = p + v.len;
    while (p && p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) ++p;
        const char* q = p;
        while (q < end && *q != ',') ++q;
        const char* e = q;
        while (e > p && (e[-1] == ' ' || e[-1] == '\t')) --e;
        if ((size_t)(e - p) == tl && strncasecmp(p, tok, tl) == 0) return true;
        p = q;
    }
    return false;
}

/* Validate the upgrade request and queue the 101 response. Returns 0, or an
   HTTP status to reject with. */
static int ws_handshake(http_ctx* x) {
    if (!header_has_token(http_header_get(x, "upgrade"), "websocket") ||
        !header_has_token(http_header_get(x, "connection"), "upgrade")) {
        http_set_header(x, "Upgrade", "websocket");
        return 426;
    }
    if (!http_str_eq(x->method, "GET")) return 400;
    http_str ver = http_header_get(x, "sec-websocket-version");
    if (!ver.ptr || !(ver.len == 2 && memcmp(ver.ptr, "13", 2) == 0)) {
        http_set_header(x, "Sec-WebSocket-Version", "13");
        return 426;
    }
    http_str key = http_header_get(x, "sec-websocket-key");
    if (!key.ptr || key.len != 24) return 400;

    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t buf[24 + sizeof guid - 1], digest[20];
    memcpy(buf, key.ptr, 24);
    memcpy(buf + 24, guid, sizeof guid - 1);
    sha1(buf, sizeof buf, digest);
    char accept[32];
    base64_encode(digest, 20, accept);

    out_compact(x);
    x->out_len += fmt_to(x->out + x->out_len, OUT_CAP - (size_t)x->out_len,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    x->head_sent = x->ended = true;   /* the HTTP part is over */
    x->ws = true;
    x->close = true;                  /* no HTTP keep-alive after a WebSocket */
    return 0;
}

/* ---- Outgoing frames (server frames are never masked) ---- */

static size_t ws_frame_header(uint8_t* h, int op, size_t len) {
    h[0] = (uint8_t)(0x80 | op);
    if (len < 126) { h[1] = (uint8_t)len; return 2; }
    if (len <= 0xFFFF) { h[1] = 126; h[2] = (uint8_t)(len >> 8); h[3] = (uint8_t)len; return 4; }
    h[1] = 127;
    for (int i = 0; i < 8; ++i) h[2 + i] = (uint8_t)((uint64_t)len >> (56 - 8 * i));
    return 10;
}

/* Queue one frame. Frames go into the output buffer; a frame too large for
   it is sent from a heap copy, but only once nothing else is queued, so
   frames can't be reordered. Returns false if it must wait for a flush. */
static bool ws_put_frame(http_ctx* x, int op, const void* data, size_t len) {
    if (x->ext_off < x->ext_len) return false;          /* a large frame is still going out */
    uint8_t h[10];
    size_t hl = ws_frame_header(h, op, len);
    if (hl + len > OUT_CAP - (size_t)x->out_len) out_compact(x);
    if (hl + len <= OUT_CAP - (size_t)x->out_len) {
        memcpy(x->out + x->out_len, h, hl);
        if (len) memcpy(x->out + x->out_len + hl, data, len);
        x->out_len += (int)(hl + len);
        return true;
    }
    if (hl + len <= OUT_CAP || x->out_len > x->out_off) return false;   /* wait for room */
    char* copy = malloc(len);
    if (!copy) { x->ws_failed = true; x->close = true; return true; }
    memcpy(copy, data, len);
    x->ext = copy;
    x->ext_len = len;
    x->ext_off = 0;
    memcpy(x->out + x->out_len, h, hl);
    x->out_len += (int)hl;
    return true;
}

/* Emit pending control frames (pong, then close) when there's room. */
static void ws_queue_control(http_ctx* x) {
    if (x->ws_pong_pending && ws_put_frame(x, 0xA, x->ws_pong, (size_t)x->ws_pong_len))
        x->ws_pong_pending = false;
    if (x->ws_ping_due && !x->ws_close_queued && ws_put_frame(x, 0x9, "", 0))
        x->ws_ping_due = false;     /* keepalive ping requested by the reactor */
    if (x->ws_close_pending && !x->ws_pong_pending &&
        ws_put_frame(x, 0x8, x->ws_closebuf, (size_t)x->ws_close_len)) {
        x->ws_close_pending = false;
        x->ws_close_sent = true;
    }
}

static void ws_request_close(http_ctx* x, int code, const char* reason, size_t rlen) {
    if (x->ws_close_queued) return;
    x->ws_close_queued = x->ws_close_pending = true;
    size_t n = 0;
    if (code) {
        x->ws_closebuf[0] = (char)(code >> 8);
        x->ws_closebuf[1] = (char)(code & 0xFF);
        if (rlen > 123) rlen = 123;
        if (rlen) memcpy(x->ws_closebuf + 2, reason, rlen);
        n = 2 + rlen;
    }
    x->ws_close_len = (int)n;
    ws_queue_control(x);
}

/* Protocol violation: close with `code` and stop reading. */
static void ws_fail(http_ctx* x, int code) {
    x->ws_failed = true;
    if (!x->ws_close_code) x->ws_close_code = code;
    ws_request_close(x, code, NULL, 0);
}

static void ws_control(http_ctx* x, int op, const char* pl, size_t len) {
    if (op == 0x9) {                                    /* ping -> pong (latest wins) */
        if (x->ws_close_queued) return;
        memcpy(x->ws_pong, pl, len);
        x->ws_pong_len = (int)len;
        x->ws_pong_pending = true;
        ws_queue_control(x);
    } else if (op == 0x8) {                             /* close */
        int code = 1005;                                /* "no status received" */
        if (len == 1) { ws_fail(x, 1002); return; }
        if (len >= 2) {
            code = (uint8_t)pl[0] << 8 | (uint8_t)pl[1];
            bool valid = (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014)
                      || (code >= 3000 && code <= 4999);
            if (!valid) { ws_fail(x, 1002); return; }
            if (!utf8_valid((const uint8_t*)pl + 2, len - 2)) { ws_fail(x, 1007); return; }
        }
        x->ws_close_received = true;
        x->ws_close_code = code;
        ws_request_close(x, code == 1005 ? 0 : code, NULL, 0);   /* echo the code */
    }                                                   /* pong: nothing to do */
}

/* ---- Incoming frames: parse buffered input while the message slot is free ---- */

static void ws_parse(struct conn* c) {
    http_ctx* x = c->x;
    while (!x->ws_msg_ready && !x->ws_msg_held && !x->ws_close_received && !x->ws_failed) {
        size_t avail = (size_t)(c->in_len - c->in_off);
        const uint8_t* p = (const uint8_t*)c->in + c->in_off;

        if (x->ws_in_frame) {                           /* payload of a data frame */
            if (!avail && x->ws_frame_left) break;
            size_t n = avail < x->ws_frame_left ? avail : (size_t)x->ws_frame_left;
            char* dst = x->ws_msg + x->ws_msg_len;
            for (size_t i = 0; i < n; ++i) dst[i] = (char)(p[i] ^ x->ws_mask[(x->ws_mask_pos + i) & 3]);
            x->ws_mask_pos += n;
            x->ws_msg_len += n;
            x->ws_frame_left -= n;
            c->in_off += (int)n;
            if (x->ws_frame_left) break;
            x->ws_in_frame = false;
            if (x->ws_frame_fin) {
                x->ws_in_msg = false;
                if (x->ws_msg_op == WS_TEXT && !utf8_valid((const uint8_t*)x->ws_msg, x->ws_msg_len)) {
                    ws_fail(x, 1007);
                    break;
                }
                x->ws_msg_ready = true;
            }
            continue;
        }

        if (avail < 2) break;                           /* frame header */
        bool fin = p[0] & 0x80, masked = p[1] & 0x80;
        int rsv = p[0] & 0x70, op = p[0] & 0x0F;
        uint64_t len = p[1] & 0x7F;
        size_t hl = 2 + (len == 126 ? 2 : len == 127 ? 8 : 0) + 4;
        if (rsv || !masked) { ws_fail(x, 1002); break; }   /* no extensions; clients must mask */
        if (avail < hl) break;
        if (len == 126) len = (uint64_t)p[2] << 8 | p[3];
        else if (len == 127) {
            len = 0;
            for (int i = 0; i < 8; ++i) len = len << 8 | p[2 + i];
            if (len >> 63) { ws_fail(x, 1002); break; }
        }
        const uint8_t* mask = p + hl - 4;

        if (op >= 0x8) {                                /* control frame: whole, <= 125 bytes */
            if (!fin || len > 125 || op > 0xA) { ws_fail(x, 1002); break; }
            if (avail < hl + len) break;
            char pl[125];
            for (size_t i = 0; i < len; ++i) pl[i] = (char)(p[hl + i] ^ mask[i & 3]);
            c->in_off += (int)(hl + len);
            ws_control(x, op, pl, (size_t)len);
            continue;
        }
        /* data frame: text/binary starts a message, continuation extends it */
        if (op == 0 ? !x->ws_in_msg : (op > 2 || x->ws_in_msg)) { ws_fail(x, 1002); break; }
        if (op != 0) { x->ws_msg_op = op; x->ws_in_msg = true; x->ws_msg_len = 0; }
        if (x->ws_msg_len + len > WS_MAX_MSG) { ws_fail(x, 1009); break; }
        size_t need = x->ws_msg_len + (size_t)len;
        if (need > x->ws_msg_cap) {
            size_t cap = x->ws_msg_cap ? x->ws_msg_cap : 4096;
            while (cap < need) cap *= 2;
            if (cap > WS_MAX_MSG) cap = WS_MAX_MSG;
            char* m = realloc(x->ws_msg, cap);
            if (!m) { ws_fail(x, 1011); break; }
            x->ws_msg = m;
            x->ws_msg_cap = cap;
        }
        memcpy(x->ws_mask, mask, 4);
        x->ws_mask_pos = 0;
        x->ws_frame_left = len;
        x->ws_frame_fin = fin;
        x->ws_in_frame = true;
        c->in_off += (int)hl;
    }
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
}

/* ---- Handler API ---- */

bool ws_has_message(const http_ctx* x) { return x->ws_msg_ready; }
bool ws_closed(const http_ctx* x) {
    return !x->ws_msg_ready && (x->ws_close_received || x->ws_failed);
}
int ws_close_code(const http_ctx* x) { return x->ws_close_code ? x->ws_close_code : 1006; }

bool ws_recv_ready(http_ctx* x) {
    if (x->ws_msg_held) {                               /* release the previous message */
        x->ws_msg_held = false;
        x->ws_msg_len = 0;
    }
    if (x->ws_msg_ready || ws_closed(x)) return true;
    x->want_ws = true;
    return false;
}

ws_message ws_recv(http_ctx* x) {
    if (!x->ws_msg_ready) return (ws_message){0, "", 0};
    x->ws_msg_ready = false;
    x->ws_msg_held = true;
    return (ws_message){x->ws_msg_op, x->ws_msg ? x->ws_msg : "", x->ws_msg_len};
}

bool ws_send(http_ctx* x, int opcode, const void* data, size_t len) {
    if (x->ws_close_queued || x->ws_failed) return true;   /* closing: drop */
    ws_queue_control(x);                                /* control frames go first */
    if (!x->ws_pong_pending && ws_put_frame(x, opcode, data, len)) return true;
    x->want_write = true;
    return false;
}

bool ws_sendf(http_ctx* x, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return true;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
return ws_send(x, WS_TEXT, buf, (size_t)n);
}

void ws_close(http_ctx* x, int code, const char* reason) {
    ws_request_close(x, code, reason, reason ? strlen(reason) : 0);
}

/* ======================================================================== */
/* Pub/sub between connections                                              */
/* ======================================================================== */
/*
 * Threading model:
 *   - The topic registry (topic -> subscribers) is global, behind a rwlock:
 *     publishers take it shared, (un)subscribers exclusive.
 *   - Each subscription has a mailbox (ring of message pointers) behind its
 *     own mutex. A publisher appends to every subscriber's mailbox, then
 *     wakes the subscriber's current owner reactor by pushing the
 *     subscription onto that reactor's wake queue (coalesced with an atomic
 *     wake_pending flag, and an eventfd write only when the queue was empty).
 *   - Messages are immutable and reference-counted: one allocation per
 *     publish, shared by all subscribers on all threads.
 *   - Migration: the owner is an atomic pointer, switched when the
 *     connection is handed to another reactor. A wake-up that lands on the
 *     old owner is forwarded to the new one, and the new owner resumes a
 *     subscribed connection on arrival, so mail is never lost or duplicated.
 *   - Queue entries and the registry hold references to the subscription,
 *     so it outlives any in-flight wake-up after its connection has closed.
 */

struct ps_msg {
    _Atomic int refs;
    int opcode;
    size_t len;
    const char* topic;         /* stored after the payload */
    char data[];
};

struct ps_sub {
    _Atomic int refs;
    _Atomic(struct reactor*) owner;
    _Atomic bool alive;
    _Atomic bool wake_pending;
    pthread_mutex_t mu;        /* guards the mailbox and lagged */
    struct ps_msg** q;         /* ring buffer, grows with the backlog up to PS_QUEUE */
    int qcap, qhead, qlen;
    unsigned lagged;
    /* owner thread only: */
    struct conn* conn;
    struct ps_msg* held;       /* message returned by ps_recv(), released by ps_ready() */
    char* topics[PS_MAX_TOPICS];
    int ntopics;
};

struct ps_topic {
    char* name;
    struct ps_sub** subs;
    int n, cap;
    struct ps_topic* next;
};

static pthread_rwlock_t g_ps_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct ps_topic* g_ps_table[PS_BUCKETS];

static void ps_msg_unref(struct ps_msg* m) {
    if (atomic_fetch_sub_explicit(&m->refs, 1, memory_order_acq_rel) == 1) free(m);
}

static void ps_sub_unref(struct ps_sub* s) {
    if (atomic_fetch_sub_explicit(&s->refs, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_destroy(&s->mu);
        free(s->q);
        free(s);
    }
}

/* Append to a mailbox (caller holds s->mu). Grows the ring while below
   PS_QUEUE; at the limit (or out of memory) drops the oldest message. */
static void ps_enqueue(struct ps_sub* s, struct ps_msg* m) {
    if (s->qlen == s->qcap && s->qcap < PS_QUEUE) {
        int cap = s->qcap ? s->qcap * 2 : 16;
        struct ps_msg** q = malloc((size_t)cap * sizeof *q);
        if (q) {                                    /* unwrap into the new ring */
            for (int i = 0; i < s->qlen; ++i) q[i] = s->q[(s->qhead + i) % s->qcap];
            free(s->q);
            s->q = q;
            s->qcap = cap;
            s->qhead = 0;
        }
    }
    if (s->qlen == s->qcap) {
        if (s->qcap == 0) { ps_msg_unref(m); s->lagged++; return; }   /* no memory at all */
        ps_msg_unref(s->q[s->qhead]);               /* full: drop the oldest */
        s->qhead = (s->qhead + 1) % s->qcap;
        s->qlen--;
        s->lagged++;
    }
    s->q[(s->qhead + s->qlen) % s->qcap] = m;
    s->qlen++;
}

static struct ps_msg* ps_dequeue(struct ps_sub* s) {  /* caller holds s->mu */
    if (!s->qlen) return NULL;
    struct ps_msg* m = s->q[s->qhead];
    s->qhead = (s->qhead + 1) % s->qcap;
    s->qlen--;
    return m;
}

static unsigned ps_hash(const char* s) {
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char)*s++) * 16777619u;
    return h % PS_BUCKETS;
}

/* Registry lookup; caller holds g_ps_lock. */
static struct ps_topic* ps_find(const char* topic, struct ps_topic*** link) {
    struct ps_topic** pp = &g_ps_table[ps_hash(topic)];
    while (*pp && strcmp((*pp)->name, topic) != 0) pp = &(*pp)->next;
    if (link) *link = pp;
    return *pp;
}

/* Queue a wake-up for s on reactor r. Takes over one reference to s. */
static void ps_post_wake(struct reactor* r, struct ps_sub* s) {
    pthread_mutex_lock(&r->wq_lock);
    if (r->nwq == r->wq_cap) {
        int cap = r->wq_cap ? r->wq_cap * 2 : 64;
        struct ps_sub** q = realloc(r->wq, (size_t)cap * sizeof *q);
        if (!q) {                                   /* can't queue: drop the wake-up */
            pthread_mutex_unlock(&r->wq_lock);
            atomic_store(&s->wake_pending, false);
            ps_sub_unref(s);
            return;
        }
        r->wq = q;
        r->wq_cap = cap;
    }
    bool was_empty = r->nwq == 0;
    r->wq[r->nwq++] = s;
    pthread_mutex_unlock(&r->wq_lock);
    /* Our own reactor drains its queue before sleeping, so no syscall needed. */
    if (was_empty && r != tls_reactor)
        reactor_notify(r, NOTE_PS);
}

static void ps_wake(struct ps_sub* s) {
    if (atomic_exchange(&s->wake_pending, true)) return;   /* one already on its way */
    atomic_fetch_add(&s->refs, 1);
    ps_post_wake(atomic_load(&s->owner), s);
}

int ps_publish(const char* topic, int opcode, const void* data, size_t len) {
    size_t tlen = strlen(topic);
    struct ps_msg* m = malloc(sizeof *m + len + tlen + 1);
    if (!m) return 0;
    atomic_init(&m->refs, 1);                       /* the publisher's reference */
    m->opcode = opcode;
    m->len = len;
    if (len) memcpy(m->data, data, len);
    memcpy(m->data + len, topic, tlen + 1);
    m->topic = m->data + len;

    int n = 0;
    pthread_rwlock_rdlock(&g_ps_lock);
    struct ps_topic* t = ps_find(topic, NULL);
    for (int i = 0; t && i < t->n; ++i) {
        struct ps_sub* s = t->subs[i];
        atomic_fetch_add_explicit(&m->refs, 1, memory_order_relaxed);
        pthread_mutex_lock(&s->mu);
        ps_enqueue(s, m);
        pthread_mutex_unlock(&s->mu);
        ps_wake(s);
        ++n;
    }
    pthread_rwlock_unlock(&g_ps_lock);
    ps_msg_unref(m);
    return n;
}

bool ps_subscribe(http_ctx* x, const char* topic) {
    struct conn* c = x->c;
    struct ps_sub* s = c->sub;
    if (!s) {
        s = calloc(1, sizeof *s);
        if (!s) return false;
        atomic_init(&s->refs, 1);                   /* the connection's reference */
        atomic_init(&s->owner, c->r);
        atomic_init(&s->alive, true);
        atomic_init(&s->wake_pending, false);
        pthread_mutex_init(&s->mu, NULL);
        s->conn = c;
        c->sub = s;
    }
    for (int i = 0; i < s->ntopics; ++i)
        if (strcmp(s->topics[i], topic) == 0) return true;
    if (s->ntopics == PS_MAX_TOPICS) return false;
    char* name = strdup(topic);
    if (!name) return false;

    bool ok = false;
    pthread_rwlock_wrlock(&g_ps_lock);
    struct ps_topic** link;                         /* where the topic is, or would go */
    struct ps_topic* t = ps_find(topic, &link);
    if (!t) {                                       /* first subscriber: create the topic */
        t = calloc(1, sizeof *t);
        if (t && !(t->name = strdup(topic))) { free(t); t = NULL; }
        if (t) *link = t;
    }
    if (t) {
        if (t->n == t->cap) {
            int cap = t->cap ? t->cap * 2 : 8;
            struct ps_sub** a = realloc(t->subs, (size_t)cap * sizeof *a);
            if (a) { t->subs = a; t->cap = cap; }
        }
        if (t->n < t->cap) {
            t->subs[t->n++] = s;
            atomic_fetch_add(&s->refs, 1);          /* the registry's reference */
            ok = true;
        } else if (t->n == 0) {                     /* out of memory: don't leave it empty */
            *link = t->next;
            free(t->subs);
            free(t->name);
            free(t);
        }
    }
    pthread_rwlock_unlock(&g_ps_lock);
    if (!ok) { free(name); return false; }
    s->topics[s->ntopics++] = name;
    return true;
}

/* Remove s from one topic's subscriber list (caller holds the write lock). */
static void ps_detach(struct ps_sub* s, const char* topic) {
    struct ps_topic** link;
    struct ps_topic* t = ps_find(topic, &link);
    if (!t) return;
    for (int i = 0; i < t->n; ++i) {
        if (t->subs[i] != s) continue;
        t->subs[i] = t->subs[--t->n];
        ps_sub_unref(s);                            /* drop the registry's reference */
        break;
    }
    if (t->n == 0) {                                /* last subscriber: forget the topic */
        *link = t->next;
        free(t->subs);
        free(t->name);
        free(t);
    }
}

void ps_unsubscribe(http_ctx* x, const char* topic) {
    struct ps_sub* s = x->c->sub;
    if (!s) return;
    for (int i = 0; i < s->ntopics; ++i) {
        if (strcmp(s->topics[i], topic) != 0) continue;
        pthread_rwlock_wrlock(&g_ps_lock);
        ps_detach(s, topic);
        pthread_rwlock_unlock(&g_ps_lock);
        free(s->topics[i]);
        s->topics[i] = s->topics[--s->ntopics];
        return;
    }
}

/* End the subscription (handler finished or connection closing). */
static void ps_release(struct conn* c) {
    struct ps_sub* s = c->sub;
    if (!s) return;
    if (s->ntopics) {
        pthread_rwlock_wrlock(&g_ps_lock);
        for (int i = 0; i < s->ntopics; ++i) ps_detach(s, s->topics[i]);
        pthread_rwlock_unlock(&g_ps_lock);
        for (int i = 0; i < s->ntopics; ++i) free(s->topics[i]);
        s->ntopics = 0;
    }
    atomic_store(&s->alive, false);                 /* in-flight wake-ups will be ignored */
    pthread_mutex_lock(&s->mu);
    for (struct ps_msg* m; (m = ps_dequeue(s)); ) ps_msg_unref(m);
    pthread_mutex_unlock(&s->mu);
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }
    s->conn = NULL;
    c->sub = NULL;
    ps_sub_unref(s);                                /* drop the connection's reference */
}

bool ps_ready(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return false;
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }   /* done with the previous one */
    pthread_mutex_lock(&s->mu);
    bool has = s->qlen > 0;
    pthread_mutex_unlock(&s->mu);
    return has;
}

ps_message ps_recv(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return (ps_message){"", 0, "", 0};
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }
    pthread_mutex_lock(&s->mu);
    struct ps_msg* m = ps_dequeue(s);
    pthread_mutex_unlock(&s->mu);
    if (!m) return (ps_message){"", 0, "", 0};
    s->held = m;
    return (ps_message){m->topic, m->opcode, m->data, m->len};
}

unsigned ps_lagged(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return 0;
    pthread_mutex_lock(&s->mu);
    unsigned n = s->lagged;
    s->lagged = 0;
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* Does this connection's handler have live subscriptions to wait on? */
static bool ps_listening(const struct conn* c) { return c->sub && c->sub->ntopics > 0; }

/* ======================================================================== */
/* Behind a proxy: client addresses and the PROXY protocol                  */
/* ======================================================================== */

static void ip_from_sockaddr(const struct sockaddr* sa, ipaddr* out) {
    memset(out, 0, sizeof *out);
    if (sa->sa_family == AF_INET6) {
        memcpy(out->b, &((const struct sockaddr_in6*)sa)->sin6_addr, 16);
    } else if (sa->sa_family == AF_INET) {      /* store as ::ffff:a.b.c.d */
        out->b[10] = out->b[11] = 0xFF;
        memcpy(out->b + 12, &((const struct sockaddr_in*)sa)->sin_addr, 4);
    }
}

static bool ip_is_v4(const ipaddr* a) {
    static const uint8_t prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
    return memcmp(a->b, prefix, 12) == 0;
}

static void ip_to_str(const ipaddr* a, char* buf, size_t cap) {
    if (ip_is_v4(a)) inet_ntop(AF_INET, a->b + 12, buf, (socklen_t)cap);
    else inet_ntop(AF_INET6, a->b, buf, (socklen_t)cap);
}

/* Parse "1.2.3.4", "1.2.3.4:80", "2001:db8::1", "[2001:db8::1]:443" (surrounding
   spaces allowed). Anything else ("unknown", junk) fails. */
static bool ip_parse(const char* s, size_t n, ipaddr* out) {
    while (n && (*s == ' ' || *s == '\t')) ++s, --n;
    while (n && (s[n-1] == ' ' || s[n-1] == '\t')) --n;
    char buf[64];
    if (n == 0 || n >= sizeof buf) return false;
    memcpy(buf, s, n);
    buf[n] = '\0';
    char* a = buf;
    if (*a == '[') {                            /* [v6] or [v6]:port */
        char* close = strchr(a, ']');
        if (!close) return false;
        *close = '\0';
        ++a;
    } else if (strchr(a, '.') && strchr(a, ':') && strchr(a, ':') == strrchr(a, ':')) {
        *strchr(a, ':') = '\0';                 /* v4:port */
    }
    memset(out, 0, sizeof *out);
    uint8_t v4[4];
    if (inet_pton(AF_INET, a, v4) == 1) {
        out->b[10] = out->b[11] = 0xFF;
        memcpy(out->b + 12, v4, 4);
        return true;
    }
    return inet_pton(AF_INET6, a, out->b) == 1;
}

/* "addr" or "addr/bits"; IPv4 prefixes are relative to the mapped form. */
static bool cidr_parse(const char* s, size_t n, cidr* out) {
    const char* slash = memchr(s, '/', n);
    if (!ip_parse(s, slash ? (size_t)(slash - s) : n, &out->net)) return false;
    int max = ip_is_v4(&out->net) ? 32 : 128;
    int bits = max;
    if (slash) {
        char buf[8];
        size_t bl = n - (size_t)(slash - s) - 1;
        if (bl == 0 || bl >= sizeof buf) return false;
        memcpy(buf, slash + 1, bl);
        buf[bl] = '\0';
        char* end;
        long v = strtol(buf, &end, 10);
        if (*end || v < 0 || v > max) return false;
        bits = (int)v;
    }
    out->bits = bits + (max == 32 ? 96 : 0);
    return true;
}

static bool ip_in(const ipaddr* a, const cidr* c) {
    int full = c->bits / 8, rest = c->bits % 8;
    if (memcmp(a->b, c->net.b, (size_t)full) != 0) return false;
    if (!rest) return true;
    uint8_t mask = (uint8_t)(0xFF << (8 - rest));
    return (a->b[full] & mask) == (c->net.b[full] & mask);
}

static bool ip_trusted(const ipaddr* a) {
    for (int i = 0; i < g_ntrusted; ++i)
        if (ip_in(a, &g_trusted[i])) return true;
    return false;
}

static bool header_name_is(const http_header* h, const char* name) {
    size_t n = strlen(name);
    return h->name.len == n && strncasecmp(h->name.ptr, name, n) == 0;
}

const char* http_client_ip(http_ctx* x) {
    if (x->client_ip[0]) return x->client_ip;
    ipaddr who = x->c->client;
    if (ip_trusted(&who)) {
        /* All X-Forwarded-For entries, in order (the header may repeat).
           Keep the rightmost 64: we walk from the right. */
        http_str ent[64];
        int n = 0;
        for (int i = 0; i < x->nheaders; ++i) {
            if (!header_name_is(&x->headers[i], "x-forwarded-for")) continue;
            const char* p = x->headers[i].value.ptr;
            const char* end = p + x->headers[i].value.len;
            while (p < end) {
                const char* comma = memchr(p, ',', (size_t)(end - p));
                const char* stop = comma ? comma : end;
                if (n == 64) { memmove(ent, ent + 1, sizeof ent - sizeof ent[0]); n = 63; }
                ent[n++] = (http_str){p, (size_t)(stop - p)};
                p = stop + 1;
            }
        }
        /* Right to left: each trusted hop vouches for the entry before it.
           Stop at the first untrusted address, which is the client. */
        for (int k = n - 1; k >= 0; --k) {
            ipaddr a;
            if (!ip_parse(ent[k].ptr, ent[k].len, &a)) break;   /* junk: keep the last good hop */
            who = a;
            if (!ip_trusted(&a)) break;
        }
    }
    ip_to_str(&who, x->client_ip, sizeof x->client_ip);
    return x->client_ip;
}

const char* http_scheme(http_ctx* x) {
    struct conn* c = x->c;
    if (c->client_tls) return "https";
    if (ip_trusted(&c->client)) {
        http_str p = http_header_get(x, "x-forwarded-proto");
        if (p.ptr) {
            size_t n = 0;
            while (n < p.len && p.ptr[n] != ',' && p.ptr[n] != ' ') ++n;
            if (n == 5 && strncasecmp(p.ptr, "https", 5) == 0) return "https";
        }
    }
    return "http";
}

/* Parse a PROXY protocol (v1 or v2) header at the start of the input.
   Returns 1 once parsed and consumed, 0 if more input is needed, -1 if invalid. */
static int proxy_header_parse(struct conn* c) {
    const uint8_t* p = (const uint8_t*)c->in + c->in_off;
    size_t n = (size_t)(c->in_len - c->in_off);
    static const uint8_t sig2[12] = {0x0D,0x0A,0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A};

    if (n && p[0] == 0x0D) {                                /* ---- v2 (binary) ---- */
        if (n < 16) return memcmp(p, sig2, n < 12 ? n : 12) ? -1 : 0;
        if (memcmp(p, sig2, 12) != 0) return -1;
        int ver = p[12] >> 4, cmd = p[12] & 0x0F, fam = p[13];
        size_t len = (size_t)p[14] << 8 | p[15];
        if (ver != 2 || cmd > 1) return -1;
        if (16 + len > IN_CAP) return -1;
        if (n < 16 + len) return 0;
        const uint8_t* a = p + 16;
        if (cmd == 1) {                                     /* PROXY (cmd 0 = LOCAL: keep the peer) */
            size_t off;
            ipaddr src;
            memset(&src, 0, sizeof src);
            if (fam == 0x11 || fam == 0x12) {               /* TCP/UDP over IPv4 */
                if (len < 12) return -1;
                src.b[10] = src.b[11] = 0xFF;
                memcpy(src.b + 12, a, 4);
                c->client = src;
                off = 12;
            } else if (fam == 0x21 || fam == 0x22) {        /* TCP/UDP over IPv6 */
                if (len < 36) return -1;
                memcpy(src.b, a, 16);
                c->client = src;
                off = 36;
            } else if (fam == 0x31 || fam == 0x32) {        /* unix sockets: no address */
                if (len < 216) return -1;
                off = 216;
            } else if (fam == 0x00) {
                off = 0;
            } else {
                return -1;
            }
            while (off + 3 <= len) {                        /* TLVs: look for "client used TLS" */
                int type = a[off];
                size_t tl = (size_t)a[off + 1] << 8 | a[off + 2];
                if (off + 3 + tl > len) return -1;
                if (type == 0x20 && tl >= 1 && (a[off + 3] & 0x01)) c->client_tls = true;
                off += 3 + tl;
            }
        }
        c->in_off += (int)(16 + len);
    } else {                                                /* ---- v1 (text) ---- */
        if (n < 6) return memcmp(p, "PROXY ", n) ? -1 : 0;
        if (memcmp(p, "PROXY ", 6) != 0) return -1;
        const uint8_t* eol = mem_find(p, n < 107 ? n : 107, "\r\n", 2);
        if (!eol) return n >= 107 ? -1 : 0;                 /* v1 lines are at most 107 bytes */
        char line[108], proto[8], src[64], dst[64];
        size_t ll = (size_t)(eol - p);
        memcpy(line, p, ll);
        line[ll] = '\0';
        unsigned sport, dport;
        ipaddr a;
        if (strncmp(line, "PROXY UNKNOWN", 13) == 0) {
            /* keep the peer address */
        } else if (sscanf(line, "PROXY %7s %63s %63s %u %u", proto, src, dst, &sport, &dport) == 5
                   && (strcmp(proto, "TCP4") == 0 || strcmp(proto, "TCP6") == 0)
                   && sport <= 65535 && dport <= 65535 && ip_parse(src, strlen(src), &a)) {
            c->client = a;
        } else {
            return -1;
        }
        c->in_off += (int)(ll + 2);
    }
    ip_to_str(&c->client, c->client_str, sizeof c->client_str);
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
    return 1;
}

/* The request context and a grown input buffer. Idempotent. */
static void conn_free_buffers(struct conn* c) {
    ctx_release(c);
    if (c->in != c->in_small) {
        free(c->in);
        c->in = c->in_small;
    }
}

/* ======================================================================== */
/* Connection coroutine                                                     */
/* ======================================================================== */

/* After waking from a wait in a handler phase: did the peer go away?
   EPOLLRDHUP is reported once, then dropped from the interest set. */
static bool peer_gone(struct conn* c, bool request_complete) {
    if (c->ready & (EPOLLERR | EPOLLHUP)) return true;
    if (c->ready & EPOLLRDHUP) {
        c->rdhup = true;
        return request_complete;    /* nothing more should come: the client left */
    }
    return false;
}

/* Should the WebSocket loop read frames? Only while the message slot is free. */
static bool ws_reading(const http_ctx* x) {
    return !x->ws_msg_ready && !x->ws_msg_held && !x->ws_close_received && !x->ws_failed;
}

/* Start a streaming or WebSocket handler task. */
static bool task_start(struct conn* c, http_stream_fn fn) {
    c->task = calloc(1, c->x->route->task_size);
    if (!c->task) return false;
    c->task->x = c->x;
    c->task_fn = fn;
    return true;
}

/* Stop a handler that hasn't finished (runs its cco_finalize) and free it. */
static void task_end(struct conn* c) {
    if (!c->task) return;
    if (!cco_is_done(c->task)) {
        cco_stop(c->task);
        c->task_fn(c->task);
    }
    free(c->task);
    c->task = NULL;
    ps_release(c);              /* subscriptions end with the handler */
}

/* One loop iteration per request:
     1. read the request head (header timeout applies)
     2. route it
     3. run the handler: buffered (read body, call once), streaming (resume
        the handler coroutine, doing I/O on its behalf in between), or
        WebSocket (upgrade, then the same for frames)
     4. flush the response
     5. drain any unread request body so the connection can be reused
     6. keep-alive: next request; otherwise close
   It refers to its reactor only through c->r, so it keeps working unchanged
   after being migrated to another thread. */
static int conn_run(struct conn* c) {
    http_ctx* x = c->x;                         /* re-read on every resume */
    cco_async (c) {
        /* ---- 0. PROXY protocol header, if configured: only trusted peers,
               and it must arrive within TIMEOUT_MS ---- */
        if (g_proxy_protocol) {
            if (!ip_trusted(&c->peer)) cco_return;
            touch(c);
            for (;;) {
                int pr = proxy_header_parse(c);
                if (pr > 0) break;
                if (pr < 0 || c->eof) cco_return;
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
                if (fill(c) < 0) c->eof = true;
            }
        }

        for (;;) {
            /* ---- 1. Request head: must arrive within TIMEOUT_MS ---- */
            set_interest(c, EPOLLIN);
            touch(c);
            while (!(x && x->head_done)) {
                if (c->in_off < c->in_len) {
                    if (!x && !(x = c->x = ctx_acquire(c))) cco_return;
                    if (feed(c) < 0) break;             /* malformed: x->err set */
                    continue;
                }
                if (c->eof) cco_return;
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
                if (fill(c) < 0) c->eof = true;
            }
            atomic_fetch_add_explicit(&c->r->requests, 1, memory_order_relaxed);

            /* ---- 2. Route ---- */
            if (!x->err) dispatch(x);

            /* ---- 3. Handle ---- */
            if (x->err) {
                respond_error(x);
            } else if (x->body_mode == BODY_BUFFER) {
                /* Read the whole body (bounded by body_limit), then call once. */
                while (!x->msg_done && !x->err) {
                    if (c->in_off < c->in_len || c->paused) { feed(c); continue; }
                    if (c->eof) cco_return;
                    int fr = flush(c);                  /* e.g. a queued 100 Continue */
                    if (fr < 0) cco_return;
                    set_interest(c, fr ? EPOLLIN : EPOLLIN | EPOLLOUT);
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                    int n = fill(c);
                    if (n < 0) c->eof = true;
                    else if (n > 0) touch(c);
                }
                if (x->err) {
                    respond_error(x);
                } else {
                    x->route->handle(x);
                    if (!x->head_sent) { x->err = 500; respond_error(x); }
                }
            } else if (x->route->stream) {
                /* Streaming: resume the handler; whenever it waits, do the I/O
                   it's waiting for (parse more body, or flush output). Timers
                   wake it through c->woken. */
                if (!task_start(c, x->route->stream)) { x->err = 500; respond_error(x); goto flush_response; }
                for (;;) {
                    x->want_body = x->want_write = false;
                    if (c->task_fn(c->task) == cco_DONE) break;
                    if (x->sse_keepalive_due) {         /* idle SSE stream: send a comment */
                        x->sse_keepalive_due = false;   /* (only between fully sent events) */
                        if (x->out_off == x->out_len && x->ext_off == x->ext_len)
                            http_send(x, ": keepalive\n\n", 13);
                    }
                    c->progress = false;
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (x->want_body && x->chunk.len == 0 && !x->msg_done) {
                        if (c->in_off < c->in_len || c->paused) {
                            int before = c->in_len - c->in_off;
                            if (feed(c) < 0) break;     /* malformed body: x->err set */
                            /* progress only if input was consumed or something
                               changed; a no-op parse must fall through to recv */
                            if (c->in_len - c->in_off != before || x->chunk.len || x->msg_done)
                                c->progress = true;
                            else if (!c->eof && fill(c) != 0)
                                c->progress = true;
                        } else if (c->eof) {
                            cco_return;                 /* body truncated by the client */
                        } else {
                            int n = fill(c);
                            if (n != 0) c->progress = true;
                            if (n < 0) c->eof = true;
                        }
                    }
                    if (c->progress) { touch(c); continue; }
                    if (!x->want_body && fr == 1 && c->heap_idx < 0 && !ps_listening(c))
                        cco_return;                     /* waits on nothing */
                    set_interest(c, (x->want_body ? EPOLLIN : 0) | (fr ? 0 : EPOLLOUT)
                                    | (c->rdhup ? 0 : EPOLLRDHUP));
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out) cco_return;
                    if (peer_gone(c, x->msg_done)) cco_return;
                    c->ready = 0;
                    c->woken = false;
                }
                task_end(c);
                if (x->err) respond_error(x);
                else if (!x->head_sent) { x->err = 500; respond_error(x); }
                else if (!x->ended) http_end(x);
            } else {
                /* WebSocket: upgrade, then run the handler, reading frames
                   whenever the message slot is free (that's the backpressure),
                   answering pings and running the close handshake. */
                int st = ws_handshake(x);
                if (st) { x->err = st; x->close = true; respond_error(x); goto flush_response; }
                if (!task_start(c, x->route->websocket)) cco_return;
                for (;;) {
                    x->want_ws = x->want_write = false;
                    if (c->task_fn(c->task) == cco_DONE) break;
                    if (x->ws_failed || (x->ws_close_received && x->ws_close_sent)) break;
                    c->progress = false;
                    ws_queue_control(x);
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (ws_reading(x)) {
                        int before = c->in_len - c->in_off;
                        ws_parse(c);
                        if (c->in_len - c->in_off != before || x->ws_msg_ready || ws_closed(x)) {
                            c->progress = true;
                        } else if (c->eof) {
                            x->ws_failed = true;        /* dropped without a close frame */
                            x->ws_close_code = 1006;
                            c->progress = true;
                        } else {
                            int n = fill(c);
                            if (n != 0) c->progress = true;
                            if (n < 0) c->eof = true;
                        }
                    }
                    if (c->progress) { touch(c); continue; }
                    if (!ws_reading(x) && fr == 1 && c->heap_idx < 0 && !ps_listening(c)
                        && !x->ws_pong_pending && !x->ws_close_pending) cco_return;  /* waits on nothing */
                    set_interest(c, (ws_reading(x) ? EPOLLIN : 0) | (fr ? 0 : EPOLLOUT)
                                    | (c->rdhup || ws_reading(x) ? 0 : EPOLLRDHUP));
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out) cco_return;
                    /* locals don't survive the await, so re-derive from state */
                    if (peer_gone(c, true) && !ws_reading(x)) cco_return;
                    c->ready = 0;
                    c->woken = false;
                }
                task_end(c);
                /* Say goodbye (unless the peer vanished), then close the TCP connection. */
                if (!(c->eof && !x->ws_close_received)) ws_request_close(x, 1000, NULL, 0);
                for (;;) {
                    ws_queue_control(x);
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (fr == 1 && !x->ws_close_pending && !x->ws_pong_pending) break;
                    set_interest(c, EPOLLOUT);
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                }
                x->close = true;
            }

            /* ---- 4. Flush the response ---- */
            flush_response:
            for (;;) {
                c->progress = false;
                int fr = flush(c);
                if (fr < 0) cco_return;
                if (fr == 1) break;
                if (c->progress) touch(c);
                set_interest(c, EPOLLOUT);
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
            }
            set_interest(c, EPOLLIN);

            /* ---- 5. Drain an unread body so the connection stays usable. If
                   we rejected an Expect: 100-continue request, the client never
                   sends it, so close instead. ---- */
            if (!x->msg_done && !x->close && !(x->expect_continue && !x->sent_continue)) {
                x->body_mode = BODY_DISCARD;
                x->chunk = (http_str){NULL, 0};
                while (!x->msg_done && !x->close) {
                    if (c->in_off < c->in_len || c->paused) { if (feed(c) < 0) break; continue; }
                    if (c->eof) cco_return;
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                    int n = fill(c);
                    if (n < 0) c->eof = true;
                    else if (n > 0) touch(c);
                }
            }

            /* ---- 6. Keep-alive or close ---- */
            /* Input may still be arriving: an unread request body, or WebSocket
               frames when we closed first (e.g. 1009) and the peer hasn't sent
               its close frame yet. */
            c->linger = x->ws ? !x->ws_close_received : !x->msg_done;
            if (x->msg_done && x->keep_alive && !x->close) {
                ctx_release(c);
                x = NULL;
                c->served = true;       /* idle time now counts against --keepalive */
                continue;
            }
            ctx_release(c);
            x = NULL;

            /* Lingering close: if the client may still be sending (e.g. we
               answered 413 mid-upload), closing now would make the kernel
               reset the connection and the client might never read our
               response. Stop sending, discard input for up to LINGER_MS
               (bounded by LINGER_MAX bytes), then close. */
            if (c->linger && !c->eof) {
                shutdown(c->fd, SHUT_WR);
                timer_arm(c, c->r->now + LINGER_MS);
                set_interest(c, EPOLLIN);
                c->lingered = 0;
                for (;;) {
                    c->in_off = c->in_len;                  /* discard what's buffered */
                    if (!in_busy(c)) c->in_off = c->in_len = 0;
                    int n = fill(c);
                    if (n > 0) {
                        c->lingered += (size_t)n;
                        if (c->lingered > LINGER_MAX) break;
                        continue;
                    }
                    if (n < 0) break;
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out || c->woken) break;
                    c->ready = 0;
                }
            }
            cco_return;
        }

        cco_finalize:                   /* runs on normal exit, cco_return, or cco_stop */
        task_end(c);                    /* interrupted mid-handler: let it clean up */
        if (c->x && c->x->ws && !c->x->ws_close_sent && !c->eof && !out_busy(c)
            && c->x->out_off == c->x->out_len && c->x->ext_off == c->x->ext_len) {
            /* Shutdown or timeout: tell the peer we're going away (best effort;
               only when no frame is half-sent, or this would corrupt it). */
            static const uint8_t going_away[] = {0x88, 2, 1001 >> 8, 1001 & 0xFF};
            if (sock_send(c->fd, going_away, sizeof going_away) < 0) { /* peer gone */ }
        }
        heap_remove(c->r, c);
        dlink_remove(&c->link);
        sock_close_polled(c->r->ep, c->fd);
        if (!io_busy(c)) conn_free_buffers(c);  /* else once its operations complete */
        atomic_fetch_sub_explicit(&c->r->active, 1, memory_order_relaxed);
    }
    return cco_DONE;
}

/* ======================================================================== */
/* Reactor: scheduling, migration, rebalancing                              */
/* ======================================================================== */

#ifdef _WIN32
static bool io_arm(struct conn* c);
static void io_set_modes(struct conn* c);
static bool io_rebind(struct conn* c, struct reactor* to);

/* Run it again on the next round, after the others. */
static void io_kick(struct conn* c) {
    if (c->kick_pending) return;
    c->kick_pending = true;
    memset(&c->kick, 0, sizeof c->kick);
    PostQueuedCompletionStatus(c->r->ep, 0, KEY_KICK, &c->kick);
}
#else
static bool io_arm(struct conn* c) { (void)c; return false; }
static void io_kick(struct conn* c) { (void)c; }
#endif

/* Resume a connection. Returns false once it has finished. A finished
   connection isn't freed yet: other connections resumed in the same batch
   (e.g. by pub/sub mail) may finish while their events are still pending in
   the batch, so frees wait until the batch is done. On Windows, io_arm() then
   posts the read it may be waiting for; if that completes at once (data was
   already there), it runs again, a few times, and then yields to the other
   connections with a kick rather than hogging the reactor. */
static bool resume(struct conn* c) {
    for (int again = 0;; ++again) {
        if (c->dead) return false;
        if (cco_resume(c) == cco_DONE) {
            c->dead = true;
            c->dead_next = c->r->graveyard;
            c->r->graveyard = c;
            return false;
        }
        if (!io_arm(c)) return true;            /* waiting for a completion */
        if (again == 8) {                       /* ready again, but others go first */
            io_kick(c);
            return true;
        }
    }
}

static void bury_dead(struct reactor* r) {
    while (r->graveyard) {
        struct conn* c = r->graveyard;
        r->graveyard = c->dead_next;
#ifdef _WIN32
        if (io_busy(c)) {               /* its closed socket's operations are still completing */
            c->buried = true;
            r->ndraining++;
            continue;                   /* io_done() frees it */
        }
#endif
        conn_free_buffers(c);
        free(c);
    }
}

/* Resume and charge the coroutine's run time to the connection. */
static void resume_timed(struct conn* c) {
    int64_t t0 = now_ns();
    if (resume(c))
        c->win_ns += now_ns() - t0;
}

static void conn_start(struct reactor* r, struct conn* c);
#ifdef _WIN32
static bool hand_off_new(struct reactor* to, struct conn* c);
#endif

/* A connection for an accepted socket, not started yet (conn_start). */
static struct conn* conn_new(struct reactor* r, sock_t fd, const struct sockaddr* sa) {
    struct conn* c = malloc(sizeof *c);
    if (!c) return NULL;
    memset(c, 0, offsetof(struct conn, in_small));   /* the 16 KiB buffer needn't be zeroed */
    c->in = c->in_small;
    c->in_cap = IN_CAP;
    c->base.func = conn_run;
    c->r = r;
    c->fd = fd;
    c->settled_at = r->now - COOLDOWN_MS;       /* cooldown only applies after a migration */
    c->heap_idx = -1;
    c->last_io = c->last_rx = c->last_tx = c->kq_moved_at = r->now;
    ip_from_sockaddr(sa, &c->peer);
    c->client = c->peer;
    ip_to_str(&c->client, c->client_str, sizeof c->client_str);
    dlink_init(&c->link);
    llhttp_init(&c->parser, HTTP_REQUEST, &g_parser_settings);
    c->parser.data = c;
    /* Wait for the first EPOLLIN rather than reading right away: accept
       returns once the handshake completes, before the client's request
       has arrived, so an immediate recv() nearly always comes back empty. */
    c->interest = EPOLLIN | EPOLLRDHUP;     /* see set_interest() */
#ifdef _WIN32
    c->rd.c = c->wr.c = c;
#endif
    return c;
}

#ifndef _WIN32
static void accept_all(struct reactor* r) {
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;
    for (;;) {
        sock_t fd = sock_accept(r->lfd, (struct sockaddr*)&sa, &salen);
        salen = sizeof sa;
        IOSTAT(r, IO_ACCEPT, 1);
        if (fd == BAD_SOCK) { IOSTAT(r, IO_ACCEPT_EMPTY, 1); break; }
        struct conn* c = conn_new(r, fd, (struct sockaddr*)&sa);
        if (!c) { sock_close(fd); continue; }
        conn_start(r, c);
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Deadlines: keep-alive, pings and keepalive comments                 */
/* ------------------------------------------------------------------ */

/* A connection's deadline (TIMEOUT_MS after its last activity) has passed.
   Return true to keep it: its deadline is re-armed, and if a WebSocket ping
   or SSE keepalive was requested here it is resumed to send it. */
static bool conn_still_wanted(struct reactor* r, struct conn* c) {
    http_ctx* x = c->x;
    if (!x)                     /* between requests: keep-alive, but a fresh connection
                                   gets only the header timeout to start its first one */
        return c->served && r->now - c->last_io < g_keepalive_ms;
    bool out_pending = x->out_off < x->out_len || x->ext_off < x->ext_len;
    if (!x->ws && out_pending && r->now - c->last_tx >= TIMEOUT_MS)
        return false;                                       /* client stopped reading */
    if (x->ws) {
        /* Backlog includes what the kernel still holds for the peer: a ping
           queued behind megabytes can't be answered until they're read.
           Progress = bytes the peer has acknowledged (sent minus still
           queued), which only grows when it actually reads; the kernel
           enlarging its buffer doesn't count. */
        int kq = sock_outq(c->fd, c->tx_total);
        if (kq < 0) kq = 0;
        uint64_t acked = c->tx_total - (uint64_t)kq;
        if (acked != c->acked_last) {
            c->acked_last = acked;
            c->kq_moved_at = r->now;
        }
        if (out_pending || kq > 0) {
            if (r->now - c->kq_moved_at >= WS_STALL_MS) return false;   /* stopped reading */
            if (x->ws_ping_out) x->ws_ping_at = r->now;     /* its answer can't be due yet */
            return true;
        }
        if (x->ws_ping_out) {                               /* heard anything since the ping? */
            if (c->last_rx >= x->ws_ping_at) x->ws_ping_out = false;
            else return r->now - x->ws_ping_at < WS_PONG_MS;
        }
        if (r->now - c->last_rx >= WS_PING_MS) {            /* quiet: ping it */
            x->ws_ping_due = x->ws_ping_out = true;
            x->ws_ping_at = r->now;
        }
        return true;
    }
    if (c->heap_idx >= 0 || ps_listening(c)) {              /* handler sleeping / subscribed */
        if (x->sse && !out_pending && r->now - c->last_tx >= SSE_KEEPALIVE_MS)
            x->sse_keepalive_due = true;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Pub/sub wake-ups                                                    */
/* ------------------------------------------------------------------ */

/* Resume subscribers on this reactor that have mail. A wake-up for a
   subscription that has since migrated is forwarded to its new owner. */
static int ps_drain(struct reactor* r) {
    pthread_mutex_lock(&r->wq_lock);
    struct ps_sub** q = r->wq;
    int n = r->nwq, cap = r->wq_cap;
    r->wq = r->wq_spare;
    r->wq_cap = r->wq_spare_cap;
    r->nwq = 0;
    pthread_mutex_unlock(&r->wq_lock);

    for (int i = 0; i < n; ++i) {
        struct ps_sub* s = q[i];
        struct reactor* owner = atomic_load(&s->owner);
        if (!atomic_load(&s->alive)) { ps_sub_unref(s); continue; }
        if (owner != r) { ps_post_wake(owner, s); continue; }    /* it moved: forward */
        atomic_store(&s->wake_pending, false);   /* before the handler checks its mail */
        struct conn* c = s->conn;
        if (c && c->r == r) {                    /* (not yet adopted: adoption resumes it) */
            c->woken = true;
            resume_timed(c);
        }
        ps_sub_unref(s);
    }
    r->wq_spare = q;
    r->wq_spare_cap = cap;
    return n;
}

static bool ps_pending(struct reactor* r) {
    pthread_mutex_lock(&r->wq_lock);
    bool pending = r->nwq > 0;
    pthread_mutex_unlock(&r->wq_lock);
    return pending;
}

/* ------------------------------------------------------------------ */
/* Migration                                                          */
/* ------------------------------------------------------------------ */

/* Start a connection on this reactor: register it and run it until it first
   waits (which arms its deadline). */
static void conn_start(struct reactor* r, struct conn* c) {
    c->r = r;
#ifdef _WIN32
    if (!CreateIoCompletionPort((HANDLE)c->fd, r->ep, KEY_IO, 0)) {
        closesocket(c->fd);
        free(c);
        return;
    }
    io_set_modes(c);
#else
    struct epoll_event ev = {.events = c->interest, .data.ptr = c};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, c->fd, &ev);
#endif
    atomic_fetch_add_explicit(&r->active, 1, memory_order_relaxed);
    resume_timed(c);
}

/* Make a connection handed over by another reactor ours (or one that could
   not leave, back ours): its deadline, timer and load count. */
static void adopt_one(struct reactor* r, struct conn* c, bool moved) {
    c->r = r;
    c->win_ns = 0;
    c->settled_at = r->now;
#ifndef _WIN32
    struct epoll_event ev = {.events = c->interest, .data.ptr = c};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, c->fd, &ev);
#endif
    insert_by_deadline(r, c);
    if (c->timer_moved) {
        c->timer_moved = false;
        heap_push(r, c);
    }
    atomic_fetch_add_explicit(&r->active, 1, memory_order_relaxed);
    if (moved) atomic_fetch_add_explicit(&r->migrated_in, 1, memory_order_relaxed);
#ifdef _WIN32
    if (c->sub) atomic_store(&c->sub->owner, r);        /* (it may be coming back) */
    if (c->rd.state == IO_DONE) c->ready |= rd_bits(c);  /* input that arrived in transit */
    if (c->ready || c->sub) {
        c->woken = c->sub != NULL;      /* mail may have arrived in transit */
        resume_timed(c);
    } else if (io_arm(c)) {
        resume_timed(c);
    }
#else
    if (c->sub) {                       /* mail may have arrived while in transit */
        c->woken = true;
        resume_timed(c);
    }
#endif
}

/* Take ownership of everything other reactors have sent us. */
static void adopt_inbox(struct reactor* r) {
#ifndef _WIN32
    notify_drain(r->inboxfd);
#endif
    pthread_mutex_lock(&r->inbox_lock);
    struct conn* list = r->inbox;
    r->inbox = NULL;
    pthread_mutex_unlock(&r->inbox_lock);

    while (list) {
        struct conn* c = list;
        list = c->inbox_next;
        if (c->fresh) {                 /* dealt out by the acceptor, not migrated */
            c->fresh = false;
            conn_start(r, c);
            continue;
        }
        adopt_one(r, c, true);
    }
}

#ifdef _WIN32
/* Give a just-accepted connection (not started yet) to another reactor.
   Returns false if the target is shutting down. */
static bool hand_off_new(struct reactor* to, struct conn* c) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed, was_empty = !to->inbox;
    if (ok) {
        c->fresh = true;
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    /* A non-empty inbox has a wake-up on its way already. */
    if (ok && was_empty) reactor_notify(to, NOTE_INBOX);
    return ok;
}

/* A socket can only move to another completion port with no I/O pending, so
   migration is two steps: migrate() cancels the connection's posted read, and
   when that completes, migrate_finish() rebinds the socket to the target's
   port and hands the connection over. In between it is on no list. */
static void migrate_finish(struct reactor* from, struct conn* c) {
    if (c->migrating) {
        c->migrating = false;
        from->nlimbo--;
    }
    struct reactor* to = c->migrate_to;
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed && io_rebind(c, to);
    if (ok) {
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    if (ok) {
        atomic_fetch_add_explicit(&from->migrated_out, 1, memory_order_relaxed);
        reactor_notify(to, NOTE_INBOX);
    } else {
        adopt_one(from, c, false);      /* can't move it after all: it stays */
    }
}

/* Can this connection move now? Not with a send in flight (its buffers must
   stay put), nor while it's already waiting for a cancelled read. */
static bool can_migrate(const struct conn* c) {
    return c->wr.state != IO_PENDING && !c->kick_pending && !c->migrating && !c->shrink_wanted;
}

/* Hand a suspended connection to another reactor. Returns false (and leaves
   the connection untouched and still ours) if the target is shutting down. */
static bool migrate(struct reactor* from, struct conn* c, struct reactor* to) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed;
    pthread_mutex_unlock(&to->inbox_lock);
    if (!ok) return false;
    dlink_remove(&c->link);
    c->timer_moved = c->heap_idx >= 0;   /* the timer heap is per reactor */
    heap_remove(from, c);
    if (c->sub) atomic_store(&c->sub->owner, to);   /* new mail wakes the new owner */
    c->ready = 0;
    c->migrate_to = to;
    atomic_fetch_sub_explicit(&from->active, 1, memory_order_relaxed);
    if (c->rd.state == IO_PENDING) {
        c->migrating = true;
        from->nlimbo++;
        CancelIoEx((HANDLE)c->fd, &c->rd.ov);
        return true;
    }
    migrate_finish(from, c);
    return true;
}
#else
static bool can_migrate(const struct conn* c) { (void)c; return true; }

/* Hand a suspended connection to another reactor. Returns false (and leaves the
   connection untouched and still ours) if the target is shutting down. */
static bool migrate(struct reactor* from, struct conn* c, struct reactor* to) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed;
    if (ok) {
        epoll_ctl(from->ep, EPOLL_CTL_DEL, c->fd, NULL);
        dlink_remove(&c->link);
        c->timer_moved = c->heap_idx >= 0;   /* the timer heap is per reactor */
        heap_remove(from, c);
        if (c->sub) atomic_store(&c->sub->owner, to);   /* new mail wakes the new owner */
        c->ready = 0;                   /* level-triggered: the new epoll set re-reports */
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    /* From here on, c belongs to `to` and must not be touched. */
    if (ok) {
        atomic_fetch_sub_explicit(&from->active, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&from->migrated_out, 1, memory_order_relaxed);
        reactor_notify(to, NOTE_INBOX);
    }
    return ok;
}
#endif

/* An idle keep-alive connection gives back a grown input buffer. On Windows a
   read is posted into it, so that is cancelled first and io_done() shrinks
   the buffer when the cancellation completes. */
static void in_release_idle(struct conn* c) {
#ifdef _WIN32
    if (c->in != c->in_small && c->rd.state == IO_PENDING && !c->rd.probe
        && c->in_off == c->in_len && !c->shrink_wanted) {
        c->shrink_wanted = true;
        CancelIoEx((HANDLE)c->fd, &c->rd.ov);
        return;
    }
#endif
    in_shrink(c);
}

/* Once per window: publish our load, and if we're clearly the hot spot, move
   our heaviest connections to the least loaded reactor. */
static void rebalance_tick(struct reactor* r) {
    int64_t wall = now_ns(), cpu = thread_cpu_ns();
    int64_t window = wall - r->tick_wall_ns;
    int load = window > 0 ? (int)((cpu - r->tick_cpu_ns) * 1000 / window) : 0;
    r->tick_wall_ns = wall;
    r->tick_cpu_ns = cpu;
    atomic_store_explicit(&r->load_pm, load, memory_order_relaxed);

    /* Find the least loaded peer. */
    struct reactor* target = NULL;
    int tload = INT_MAX;
    for (int i = 0; i < g_nreactors; ++i) {
        if (&g_reactors[i] == r) continue;
        int l = atomic_load_explicit(&g_reactors[i].load_pm, memory_order_relaxed);
        if (l < tload) { tload = l; target = &g_reactors[i]; }
    }
    int gap = target ? load - tload : 0;
    bool act = target && load >= (int)(MIN_LOAD * 1000) && gap >= (int)(MIN_GAP * 1000);

    /* One pass over our connections: reset every window counter, and keep the
       heaviest movable connections in cand[] sorted by weight, descending. */
    struct conn* cand[MAX_MIGRATE];
    int64_t weight[MAX_MIGRATE];
    int ncand = 0;
    for (dlink* p = r->live.next; p != &r->live; p = p->next) {
        struct conn* c = conn_of(p);
        int64_t w = c->win_ns;
        c->win_ns = 0;
        if (!act || w <= 0 || r->now - c->settled_at < COOLDOWN_MS || !can_migrate(c)) continue;
        if (ncand == MAX_MIGRATE) {
            if (w <= weight[ncand - 1]) continue;       /* lighter than all kept */
            --ncand;                                    /* drop the lightest */
        }
        int j = ncand++;
        while (j > 0 && weight[j - 1] < w) {
            cand[j] = cand[j - 1];
            weight[j] = weight[j - 1];
            --j;
        }
        cand[j] = c;
        weight[j] = w;
    }
    if (!act) return;

    /* Greedy: move heaviest first until we've shifted about half the gap. A
       connection bigger than the budget is still worth moving if it's the
       first one and smaller than the whole gap (it still narrows the gap). */
    int budget = gap / 2, moved = 0, nmoved = 0;
    for (int i = 0; i < ncand && moved < budget; ++i) {
        int share = (int)(weight[i] * 1000 / window);   /* per mille of a core */
        if (share <= budget - moved || (nmoved == 0 && share < gap)) {
            if (!migrate(r, cand[i], target)) break;    /* target shutting down */
            moved += share;
            ++nmoved;
        }
    }
    if (moved > 0) {
        /* Pre-adjust published loads so other reactors don't pile onto the
           same target before the next measurement. */
        atomic_fetch_add_explicit(&target->load_pm, moved, memory_order_relaxed);
        atomic_fetch_sub_explicit(&r->load_pm, moved, memory_order_relaxed);
    }
}

/* ------------------------------------------------------------------ */
/* Reactor setup and event loop                                       */
/* ------------------------------------------------------------------ */
/* A non-blocking listening socket on g_bind:port, or BAD_SOCK. */
static sock_t listen_open(int port) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof addr);
    socklen_t addrlen;
    struct sockaddr_in* a4 = (struct sockaddr_in*)&addr;
    struct sockaddr_in6* a6 = (struct sockaddr_in6*)&addr;
    if (inet_pton(AF_INET, g_bind, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons((uint16_t)port);
        addrlen = sizeof *a4;
    } else if (inet_pton(AF_INET6, g_bind, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons((uint16_t)port);
        addrlen = sizeof *a6;
    } else {
        errno = EINVAL;
        return BAD_SOCK;
    }
    int one = 1, zero = 0;
#ifdef _WIN32
    sock_t s = socket(addr.ss_family, SOCK_STREAM, 0);
    if (s == BAD_SOCK) return BAD_SOCK;
    /* Windows' SO_REUSEADDR would let another process steal the port. */
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof one);
    /* Accepted sockets inherit TCP_NODELAY from the listener on Windows. */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
    if (sock_nonblock(s) != 0) goto fail;
#else
    sock_t s = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s == BAD_SOCK) return BAD_SOCK;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) < 0) goto fail;
#endif
    if (addr.ss_family == AF_INET6)             /* "::" also accepts IPv4 */
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&zero, sizeof zero);
    if (bind(s, (struct sockaddr*)&addr, addrlen) < 0) goto fail;
    if (listen(s, SOMAXCONN) < 0) goto fail;
    return s;
fail:
    sock_close(s);
    return BAD_SOCK;
}

#ifdef _WIN32
/* ------------------------------------------------------------------ */
/* Windows: I/O completion ports                                       */
/* ------------------------------------------------------------------ */
/* Each reactor has its own completion port. A connection's reads and writes
   are overlapped WSARecv/WSASend into its own buffers (rd_post, flush); their
   completions set the same event bits epoll would (io_done), and the
   connection coroutine runs unchanged. Sockets are put in "skip completion on
   success" mode, so an operation that completes at once (data already
   waiting, room in the send buffer) costs one call and no completion packet.
   Wake-ups (stop, inbox, pub/sub mail) are posted packets. Reactor 0 accepts
   for everyone with AcceptEx. */

#define ACCEPT_OPS  16                          /* AcceptEx operations kept posted */
#define ACCEPT_ADDR (sizeof(SOCKADDR_STORAGE) + 16)
#define STATUS_CANCELLED_ ((LONG)0xC0000120)    /* CancelIoEx'd operation */

struct accept_op { OVERLAPPED ov; sock_t s; char addr[2 * ACCEPT_ADDR]; };

static LPFN_ACCEPTEX g_AcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS g_GetAcceptExSockaddrs;

typedef struct { HANDLE port; PVOID key; } completion_info;         /* FILE_COMPLETION_INFORMATION */
typedef struct { union { LONG status; PVOID ptr; }; ULONG_PTR info; } io_status;
typedef LONG (NTAPI* set_info_fn)(HANDLE, io_status*, PVOID, ULONG, int);
static set_info_fn g_NtSetInformationFile;
static bool g_skip_ok;                          /* all TCP providers are IFS: skip mode is safe */

/* Skipping completions on success is only safe when no layered service
   provider sits between Winsock and the kernel. */
static bool tcp_providers_are_ifs(void) {
    DWORD len = 0;
    WSAEnumProtocolsW(NULL, NULL, &len);
    WSAPROTOCOL_INFOW* p = len ? malloc(len) : NULL;
    int n = p ? WSAEnumProtocolsW(NULL, p, &len) : -1;
    bool ok = n > 0;
    for (int i = 0; i < n; ++i)
        if (p[i].iProtocol == IPPROTO_TCP && !(p[i].dwServiceFlags1 & XP1_IFS_HANDLES)) ok = false;
    free(p);
    return ok;
}

static void iocp_init(void) {
    g_NtSetInformationFile = (set_info_fn)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    g_skip_ok = tcp_providers_are_ifs();
}

static void io_set_modes(struct conn* c) {
    c->skip = g_skip_ok && SetFileCompletionNotificationModes((HANDLE)c->fd,
                  FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);
}

/* Move a socket (with no I/O pending) to another reactor's completion port.
   The move resets the skip-on-success mode, so it is set again. */
static bool io_rebind(struct conn* c, struct reactor* to) {
    if (!g_NtSetInformationFile) return false;
    completion_info ci = {to->ep, (PVOID)(ULONG_PTR)KEY_IO};
    io_status st;
    if (g_NtSetInformationFile((HANDLE)c->fd, &st, &ci, sizeof ci, 61 /* FileReplaceCompletionInformation */) < 0)
        return false;
    io_set_modes(c);
    return true;
}

/* After the coroutine yields: if it waits for input, keep a read posted into
   `in`; if it only watches for the peer hanging up, keep a probe posted.
   Returns true if that completed at once, so the coroutine should run again. */
static bool io_arm(struct conn* c) {
    if (c->rd.state != IO_IDLE || c->migrating || c->shrink_wanted || !(c->interest & (EPOLLIN | EPOLLRDHUP)))
        return false;
    if (!(c->interest & EPOLLIN)) {     /* not reading: a handler may hold a pointer into `in` */
        if (c->probe_seen) return false;
        rd_post(c, true);
        if (c->rd.state != IO_DONE) return false;
        uint32_t bits = probe_result(c);
        c->ready |= bits;
        return bits != 0;
    }
    if (c->in_off > 0) {                /* reading: nothing points into `in` */
        memmove(c->in, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
        c->in_len -= c->in_off;
        c->in_off = 0;
    }
    if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
    if (c->in_len == c->in_cap) return false;
    rd_post(c, false);
    if (c->rd.state != IO_DONE) return false;
    c->ready |= rd_bits(c);
    return true;
}

/* A connection's read or write completed. */
static void io_done(struct reactor* r, OVERLAPPED_ENTRY* e) {
    struct io_op* op = (struct io_op*)e->lpOverlapped;
    struct conn* c = op->c;
    LONG st = (LONG)e->lpOverlapped->Internal;
    op->state = IO_DONE;
    op->bytes = e->dwNumberOfBytesTransferred;
    op->cancelled = st == STATUS_CANCELLED_;
    op->failed = st < 0 && !op->cancelled;
    IOSTAT(r, IO_EVENTS, 1);
    if (c->dead) {                      /* closed: it was only waiting for this */
        if (c->buried && !io_busy(c)) {
            conn_free_buffers(c);
            free(c);
            r->ndraining--;
        }
        return;
    }
    bool is_rd = op == &c->rd;
    if (is_rd && op->cancelled) op->state = IO_IDLE;     /* nothing arrived */
    if (c->migrating) {                 /* its read is out of the way: move it */
        migrate_finish(r, c);
        return;
    }
    if (is_rd && c->shrink_wanted) {
        c->shrink_wanted = false;
        if (op->state == IO_IDLE) {     /* cancelled as asked: shrink, then read again */
            in_shrink(c);
            if (io_arm(c)) resume_timed(c);
            return;
        }
    }
    if (is_rd && op->state == IO_IDLE) return;
    if (is_rd && op->probe) {           /* data or a close arrived while it wasn't reading */
        uint32_t bits = probe_result(c);
        if (!bits) {                    /* spurious: watch again */
            if (io_arm(c)) resume_timed(c);
            return;
        }
        c->ready |= bits;
        resume_timed(c);
        return;
    }
    c->ready |= is_rd ? rd_bits(c) : op->failed ? EPOLLOUT | EPOLLERR | EPOLLHUP : EPOLLOUT;
    resume_timed(c);
}

/* A connection's kick (io_kick) came round: run it. */
static void kick_done(struct reactor* r, OVERLAPPED* ov) {
    struct conn* c = c_container_of(ov, struct conn, kick);
    c->kick_pending = false;
    if (c->dead) {                      /* closed meanwhile: it was only waiting for this */
        if (c->buried && !io_busy(c)) {
            conn_free_buffers(c);
            free(c);
            r->ndraining--;
        }
        return;
    }
    resume_timed(c);
}

static void accept_post(struct reactor* r, struct accept_op* op) {
    memset(&op->ov, 0, sizeof op->ov);
    op->s = WSASocketW(r->lfamily, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (op->s == BAD_SOCK) return;
    DWORD got = 0;
    if (!g_AcceptEx(r->lfd, op->s, op->addr, 0, ACCEPT_ADDR, ACCEPT_ADDR, &got, &op->ov)
        && WSAGetLastError() != ERROR_IO_PENDING) {
        closesocket(op->s);
        op->s = BAD_SOCK;
        return;
    }
    r->naccept++;
}

/* An AcceptEx completed: set up the connection, deal it out, post another. */
static void accept_done(struct reactor* r, OVERLAPPED_ENTRY* e) {
    struct accept_op* op = (struct accept_op*)e->lpOverlapped;
    sock_t fd = op->s;
    op->s = BAD_SOCK;
    r->naccept--;
    IOSTAT(r, IO_ACCEPT, 1);
    struct conn* c = NULL;
    if ((LONG)e->lpOverlapped->Internal >= 0 && !r->stopping
        && setsockopt(fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char*)&r->lfd, sizeof r->lfd) == 0
        && sock_nonblock(fd) == 0) {
        struct sockaddr *la, *ra;
        INT lal, ral;
        g_GetAcceptExSockaddrs(op->addr, 0, ACCEPT_ADDR, ACCEPT_ADDR, &la, &lal, &ra, &ral);
        c = conn_new(r, fd, ra);
    }
    if (!c) {
        IOSTAT(r, IO_ACCEPT_EMPTY, 1);
        closesocket(fd);
    } else {
        /* Reactor 0 alone accepts, so it deals connections out round-robin. */
        struct reactor* home = &g_reactors[r->next_home++ % (unsigned)g_nreactors];
        if (home == r || !hand_off_new(home, c)) conn_start(r, c);
    }
    if (!r->stopping && r->lfd != BAD_SOCK) accept_post(r, op);
}

/* Wait up to `timeout` ms (-1: no limit) and handle what completed. */
static void reactor_poll(struct reactor* r, int timeout) {
    OVERLAPPED_ENTRY ev[MAX_EVENTS];
    ULONG n = 0;
    if (!GetQueuedCompletionStatusEx(r->ep, ev, MAX_EVENTS, &n, timeout < 0 ? INFINITE : (DWORD)timeout, FALSE))
        n = 0;                          /* timed out */
    r->now = now_ms();
    IOSTAT(r, IO_WAIT, 1);
    for (ULONG i = 0; i < n; ++i) {
        switch (ev[i].lpCompletionKey) {
        case KEY_IO:     io_done(r, &ev[i]); break;
        case KEY_ACCEPT: accept_done(r, &ev[i]); break;
        case KEY_INBOX:  adopt_inbox(r); break;
        case KEY_PS:     ps_drain(r); break;         /* other threads posted mail */
        case KEY_KICK:   kick_done(r, ev[i].lpOverlapped); break;
        case KEY_STOP:   r->stopping = true; break;
        }
    }
}

static int reactor_open(struct reactor* r) {
    dlink_init(&r->live);
    pthread_mutex_init(&r->inbox_lock, NULL);
    pthread_mutex_init(&r->wq_lock, NULL);
    r->lfd = BAD_SOCK;
    r->ep = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!r->ep) return -1;
    if (r->id != 0) return 0;
    /* Reactor 0 accepts for everyone (there is no SO_REUSEPORT). */
    r->lfd = listen_open(r->port);
    if (r->lfd == BAD_SOCK) return -1;
    struct sockaddr_storage la;
    int lal = sizeof la;
    GUID g1 = WSAID_ACCEPTEX, g2 = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD got;
    if (getsockname(r->lfd, (struct sockaddr*)&la, &lal) != 0
        || WSAIoctl(r->lfd, SIO_GET_EXTENSION_FUNCTION_POINTER, &g1, sizeof g1,
                    &g_AcceptEx, sizeof g_AcceptEx, &got, NULL, NULL) != 0
        || WSAIoctl(r->lfd, SIO_GET_EXTENSION_FUNCTION_POINTER, &g2, sizeof g2,
                    &g_GetAcceptExSockaddrs, sizeof g_GetAcceptExSockaddrs, &got, NULL, NULL) != 0
        || !CreateIoCompletionPort((HANDLE)r->lfd, r->ep, KEY_ACCEPT, 0))
        return -1;
    r->lfamily = la.ss_family;
    r->acc = calloc(ACCEPT_OPS, sizeof *r->acc);
    if (!r->acc) return -1;
    for (int i = 0; i < ACCEPT_OPS; ++i) accept_post(r, &r->acc[i]);
    return r->naccept ? 0 : -1;
}

#else  /* Linux: epoll */

/* Wait up to `timeout` ms (-1: no limit) and handle what's ready. */
static void reactor_poll(struct reactor* r, int timeout) {
    struct epoll_event evs[MAX_EVENTS];
    int nev = epoll_wait(r->ep, evs, MAX_EVENTS, timeout);
    r->now = now_ms();
    IOSTAT(r, IO_WAIT, 1);

    for (int i = 0; i < nev; ++i) {
        void* tag = evs[i].data.ptr;
        if (tag == &LISTENER_TAG) { accept_all(r); continue; }
        if (tag == &INBOX_TAG)    { adopt_inbox(r); continue; }
        if (tag == &PS_TAG) {                    /* other threads posted mail */
            notify_drain(r->psfd);
            ps_drain(r);
            continue;
        }
        if (tag == &WAKE_TAG)     { r->stopping = true; continue; }
        struct conn* c = tag;
        if (c->dead) continue;                   /* finished earlier in this batch */
        IOSTAT(r, IO_EVENTS, 1);
        if (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) c->tx_full = false;
        c->ready |= evs[i].events;
        resume_timed(c);                         /* only ready connections run */
    }
}

static int reactor_open(struct reactor* r) {
    dlink_init(&r->live);
    pthread_mutex_init(&r->inbox_lock, NULL);
    pthread_mutex_init(&r->wq_lock, NULL);
    r->lfd = listen_open(r->port);
    if (r->lfd == BAD_SOCK) return -1;

    r->ep = epoll_create1(0);
    r->wakefd = notify_open();
    r->inboxfd = notify_open();
    r->psfd = notify_open();
    if (r->ep == BAD_POLL || r->wakefd == BAD_SOCK || r->inboxfd == BAD_SOCK || r->psfd == BAD_SOCK)
        return -1;
    struct epoll_event pev = {.events = EPOLLIN, .data.ptr = &PS_TAG};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->psfd, &pev);
    struct epoll_event lev = {.events = EPOLLIN, .data.ptr = &LISTENER_TAG};
    struct epoll_event wev = {.events = EPOLLIN, .data.ptr = &WAKE_TAG};
    struct epoll_event iev = {.events = EPOLLIN, .data.ptr = &INBOX_TAG};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->lfd, &lev);
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->wakefd, &wev);
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->inboxfd, &iev);
    return 0;
}
#endif

static void* reactor_run(void* arg) {
    struct reactor* r = arg;
    bool balancing = g_nreactors > 1;

    tls_reactor = r;
    r->now = now_ms();
    r->next_tick = r->now + REBALANCE_MS;
    r->tick_wall_ns = now_ns();
    r->tick_cpu_ns = thread_cpu_ns();

    while (!r->stopping) {
        /* Deliver pub/sub mail posted by this thread (it skips the eventfd).
           Bounded, in case handlers keep publishing to each other. */
        for (int round = 0; round < 4 && ps_drain(r) > 0; ++round) {}

        /* Sleep until the earliest of: an event, the next deadline, the next tick. */
        int64_t wake_at = balancing ? r->next_tick : INT64_MAX;
        if (!dlink_empty(&r->live) && conn_of(r->live.next)->deadline < wake_at)
            wake_at = conn_of(r->live.next)->deadline;
        if (r->nheap && r->heap[0]->wake_at < wake_at)
            wake_at = r->heap[0]->wake_at;
        int timeout = -1;
        if (wake_at != INT64_MAX) {
            int64_t ms = wake_at - now_ms();
            timeout = ms < 0 ? 0 : (int)ms;
        }
        if (ps_pending(r)) timeout = 0;              /* more mail: don't sleep */
        reactor_poll(r, timeout);

        /* Fire handler timers that are due. */
        while (r->nheap && r->heap[0]->wake_at <= r->now) {
            struct conn* c = r->heap[0];
            heap_remove(r, c);
            c->woken = true;
            resume_timed(c);
        }

        /* Expire overdue connections; they sit at the front of the list.
           conn_still_wanted() decides who lives on (keep-alive, WebSocket
           pings, sleeping or subscribed handlers). */
        while (!dlink_empty(&r->live) && conn_of(r->live.next)->deadline <= r->now) {
            struct conn* c = conn_of(r->live.next);
            if (conn_still_wanted(r, c)) {
                arm_deadline(c);                     /* moves it to the tail */
                if (!c->x) in_release_idle(c);       /* idle keep-alive: give back a grown buffer */
                if (c->x && (c->x->ws_ping_due || c->x->sse_keepalive_due)) {
                    c->woken = true;                 /* let it send the ping / comment */
                    resume_timed(c);
                }
                continue;
            }
            c->timed_out = true;
            resume(c);                               /* cco_return -> finalize -> unlinks */
        }

        if (balancing && r->now >= r->next_tick && !r->stopping) {
            rebalance_tick(r);
            r->next_tick = r->now + REBALANCE_MS;
        }
        bury_dead(r);                                /* nothing refers to them any more */
    }

    /* Shutdown: refuse further migrations, adopt anything already queued,
       then stop every live coroutine so its cco_finalize runs. */
    pthread_mutex_lock(&r->inbox_lock);
    r->inbox_closed = true;
    pthread_mutex_unlock(&r->inbox_lock);
    adopt_inbox(r);

#ifdef _WIN32
    if (r->lfd != BAD_SOCK) {                        /* its AcceptEx operations complete, cancelled */
        closesocket(r->lfd);
        r->lfd = BAD_SOCK;
    }
#else
    close(r->lfd);
#endif
    while (!dlink_empty(&r->live)) {
        struct conn* c = conn_of(r->live.next);
        cco_stop(c);                                 /* jump to cco_finalize on resume */
        resume(c);
    }
    bury_dead(r);
#ifdef _WIN32
    /* Closed sockets' operations, the cancelled reads of connections that were
       on their way to another reactor, and cancelled accepts still complete:
       wait for them (bounded), stopping any connection that couldn't leave. */
    for (int64_t end = now_ms() + 2000; (r->ndraining || r->nlimbo || r->naccept) && now_ms() < end; ) {
        reactor_poll(r, 50);
        while (!dlink_empty(&r->live)) {
            struct conn* c = conn_of(r->live.next);
            cco_stop(c);
            resume(c);
        }
        bury_dead(r);
    }
    free(r->acc);
#endif
    while (r->nctx_cache) free(r->ctx_cache[--r->nctx_cache]);
    free(r->heap);
    poll_close(r->ep);
    return NULL;
}

#ifndef SERVER_NO_MAIN                 /* only the demo's /stats uses it */
static int format_stats(char* buf, size_t cap, const struct reactor* self) {
    long total_req = 0, total_mig = 0; int total_act = 0, len = 0;
    for (int i = 0; i < g_nreactors; ++i) {
        total_act += atomic_load_explicit(&g_reactors[i].active, memory_order_relaxed);
        total_req += atomic_load_explicit(&g_reactors[i].requests, memory_order_relaxed);
        total_mig += atomic_load_explicit(&g_reactors[i].migrated_out, memory_order_relaxed);
    }
    len += snprintf(buf + len, cap - (size_t)len,
                    "served_by=reactor%d active_connections=%d total_requests=%ld migrations=%ld\n",
                    self->id, total_act, total_req, total_mig);
    for (int i = 0; i < g_nreactors && (size_t)len < cap; ++i) {
        const struct reactor* r = &g_reactors[i];
        len += snprintf(buf + len, cap - (size_t)len,
                        "reactor%d load=%3d%% active=%d requests=%ld migrated_in=%ld migrated_out=%ld\n", i,
                        atomic_load_explicit(&r->load_pm, memory_order_relaxed) / 10,
                        atomic_load_explicit(&r->active, memory_order_relaxed),
                        atomic_load_explicit(&r->requests, memory_order_relaxed),
                        atomic_load_explicit(&r->migrated_in, memory_order_relaxed),
                        atomic_load_explicit(&r->migrated_out, memory_order_relaxed));
    }
#ifdef IO_STATS
    if ((size_t)len < cap) len += snprintf(buf + len, cap - (size_t)len, "io");
    for (int k = 0; k < IO_NSTATS && (size_t)len < cap; ++k) {
        long sum = 0;
        for (int i = 0; i < g_nreactors; ++i)
            sum += atomic_load_explicit(&g_reactors[i].io[k], memory_order_relaxed);
        len += snprintf(buf + len, cap - (size_t)len, " %s=%ld", io_stat_names[k], sum);
    }
    if ((size_t)len < cap) len += snprintf(buf + len, cap - (size_t)len, "\n");
#endif
    return len;
}
#endif


#ifndef SERVER_NO_MAIN                 /* the demo routes: left out of the library build */
/* ======================================================================== */
/* Demo application                                                         */
/* ======================================================================== */

/* Minimal JSON string escaping for echoing user input back. */
static void json_escape(http_str s, char* out, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; i < s.len && j + 7 < cap; ++i) {
        unsigned char ch = (unsigned char)s.ptr[i];
        if (ch == '"' || ch == '\\') { out[j++] = '\\'; out[j++] = (char)ch; }
        else if (ch < 0x20) j += (size_t)snprintf(out + j, cap - j, "\\u%04x", ch);
        else out[j++] = (char)ch;
    }
    out[j] = '\0';
}

#define APP_FNV_OFFSET 0xcbf29ce484222325ULL
#define APP_FNV_PRIME  0x100000001b3ULL
static uint64_t fnv1a(uint64_t h, const char* p, size_t n) {
    for (size_t i = 0; i < n; ++i) h = (h ^ (unsigned char)p[i]) * APP_FNV_PRIME;
    return h;
}

/* GET / */
static void h_hello(http_ctx* x) {
    http_respond(x, 200, "text/plain", "Hello from STC coroutines!\n", 27);
}

/* GET /users/:id?verbose=1 - path parameter + query string -> JSON */
static void h_user(http_ctx* x) {
    char id[256], verbose[8] = "";
    json_escape(http_param(x, "id"), id, sizeof id);
    http_query(x, "verbose", verbose, sizeof verbose);
    http_str ua = http_header_get(x, "user-agent");
    char agent[256] = "";
    if (ua.ptr) json_escape(ua, agent, sizeof agent);
    if (strcmp(verbose, "1") == 0) {
        http_str m = http_method(x), p = http_path(x);
        char path[512];
        json_escape(p, path, sizeof path);
        http_respondf(x, 200, "application/json",
                      "{\"id\":\"%s\",\"method\":\"%.*s\",\"path\":\"%s\",\"user_agent\":\"%s\",\"reactor\":%d}\n",
                      id, (int)m.len, m.ptr, path, agent, x->c->r->id);
    }
else
        http_respondf(x, 200, "application/json", "{\"id\":\"%s\"}\n", id);
}

/* GET /static/<anything> - trailing wildcard parameter */
static void h_static(http_ctx* x) {
    http_str p = http_param(x, "path");
    http_respondf(x, 200, "text/plain", "you asked for static file '%.*s'\n", (int)p.len, p.ptr);
}

/* POST /upload - buffered body (limit 1 MiB): size and checksum */
static void h_upload(http_ctx* x) {
    http_str b = http_body(x);
    http_respondf(x, 200, "application/json", "{\"bytes\":%zu,\"fnv1a\":\"%016llx\"}\n",
                  b.len, (unsigned long long)fnv1a(APP_FNV_OFFSET, b.ptr, b.len));
}

/* POST /count - streaming consumer: same result as /upload, but for bodies of
   any size in constant memory. */
struct count_task { HTTP_TASK; uint64_t bytes, hash; };
static int s_count(void* p) {
    struct count_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        t->hash = APP_FNV_OFFSET;
        for (;;) {
            cco_await(http_body_ready(x));
            if (http_body_done(x)) break;
            http_str s = http_body_take(x);
            t->bytes += s.len;
            t->hash = fnv1a(t->hash, s.ptr, s.len);
        }
        http_respondf(x, 200, "application/json", "{\"bytes\":%llu,\"fnv1a\":\"%016llx\"}\n",
                      (unsigned long long)t->bytes, (unsigned long long)t->hash);
    }
    return cco_DONE;
}

/* GET /stream?n=N - streaming generator: N lines, chunked, paced by the client. */
struct numbers_task { HTTP_TASK; long i, n; };
static int s_numbers(void* p) {
    struct numbers_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        char buf[32];
        t->n = http_query(x, "n", buf, sizeof buf) ? atol(buf) : 10;
        http_start(x, 200, "text/plain");
        for (t->i = 1; t->i <= t->n; ++t->i)
            cco_await(http_sendf(x, "line %ld\n", t->i));
        http_end(x);
    }
    return cco_DONE;
}

/* POST /echo - full-duplex streaming: each body chunk is sent straight back.
   Memory use is constant, and a client that reads slowly stalls the upload. */
struct echo_task { HTTP_TASK; http_str chunk; };
static int s_echo(void* p) {
    struct echo_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        http_str ct = http_header_get(x, "content-type");
        char ctype[128] = "application/octet-stream";
        if (ct.ptr && ct.len < sizeof ctype) snprintf(ctype, sizeof ctype, "%.*s", (int)ct.len, ct.ptr);
        http_start(x, 200, ctype);
        for (;;) {
            cco_await(http_body_ready(x));
            if (http_body_done(x)) break;
            t->chunk = http_body_take(x);
            cco_await(http_send(x, t->chunk.ptr, t->chunk.len));
        }
        http_end(x);
    }
    return cco_DONE;
}

/* GET /events?n=5&ms=1000 - server-sent events paced by a handler timer. */
struct events_task { HTTP_TASK; http_timer tick; long i, n, ms; };
static int s_events(void* p) {
    struct events_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        char buf[32];
        t->n = http_query(x, "n", buf, sizeof buf) ? atol(buf) : 5;
        t->ms = http_query(x, "ms", buf, sizeof buf) ? atol(buf) : 1000;
        http_set_header(x, "Cache-Control", "no-cache");
        http_start(x, 200, "text/event-stream");
        for (t->i = 1; t->i <= t->n; ++t->i) {
            cco_await(http_sendf(x, "id: %ld\ndata: tick %ld\n\n", t->i, t->i));
            if (t->i < t->n)
                http_sleep(x, &t->tick, t->ms);
        }
        http_end(x);
    }
    return cco_DONE;
}

/* WebSocket /ws/echo - every message is sent back as-is (text or binary). */
struct wsecho_task { HTTP_TASK; ws_message m; };
static int ws_echo(void* p) {
    struct wsecho_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        for (;;) {
            cco_await(ws_recv_ready(x));
            if (ws_closed(x)) break;
            t->m = ws_recv(x);
            cco_await(ws_send(x, t->m.opcode, t->m.data, t->m.len));
        }
    }
    return cco_DONE;
}

/* WebSocket /ws/clock - pushes a tick every second while also answering
   messages: waits on a message OR a timer at the same time. "stop" closes. */
struct clock_task { HTTP_TASK; http_timer tick; long n; ws_message m; };
static int ws_clock(void* p) {
    struct clock_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        http_timer_start(x, &t->tick, 1000);
        for (;;) {
            cco_await(ws_recv_ready(x) || http_timer_done(x, &t->tick));
            if (ws_closed(x)) break;
            if (ws_has_message(x)) {
                t->m = ws_recv(x);
                if (t->m.len == 4 && memcmp(t->m.data, "stop", 4) == 0) {
                    ws_close(x, 1000, "bye");
                    break;
                }
                cco_await(ws_sendf(x, "you said: %.*s", (int)t->m.len, t->m.data));
            }
            if (http_timer_expired(x, &t->tick)) {
                cco_await(ws_sendf(x, "tick %ld", ++t->n));
                http_timer_start(x, &t->tick, 1000);
            }
        }
    }
    return cco_DONE;
}

/* ---- Chat rooms: pub/sub between connections on any thread ---- */

static void room_topic(http_ctx* x, char* buf, size_t cap) {
    http_str room = http_param(x, "room");
    snprintf(buf, cap, "room:%.*s", (int)room.len, room.ptr);
}

/* WebSocket /ws/chat/:room - every message is published to the room, and
   everything published to the room is forwarded to this client. Waits for
   its own client and for room traffic at the same time. */
struct chat_task { HTTP_TASK; char topic[80]; ws_message m; ps_message pm; unsigned lost; };
static int ws_chat(void* p) {
    struct chat_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        room_topic(x, t->topic, sizeof t->topic);
        if (!ps_subscribe(x, t->topic)) { ws_close(x, 1011, "subscribe failed"); cco_return; }
        ps_publish(t->topic, WS_TEXT, "* someone joined", 16);
        for (;;) {
            cco_await(ws_recv_ready(x) || ps_ready(x));
            if (ws_closed(x)) break;
            if (ws_has_message(x)) {
                t->m = ws_recv(x);
                ps_publish(t->topic, t->m.opcode, t->m.data, t->m.len);  /* to everyone, us included */
            }
            while (ps_ready(x)) {
                t->pm = ps_recv(x);
                cco_await(ws_send(x, t->pm.opcode, t->pm.data, t->pm.len));
            }
            t->lost = ps_lagged(x);             /* in the task: it's used across the await */
            if (t->lost) cco_await(ws_sendf(x, "* %u messages skipped (you fell behind)", t->lost));
        }
        cco_finalize:
        if (t->topic[0]) ps_publish(t->topic, WS_TEXT, "* someone left", 14);
    }
    return cco_DONE;
}

/* GET /rooms/:room/events - the same room as server-sent events. */
struct feed_task { HTTP_TASK; char topic[80]; ps_message pm; };
static int s_room_feed(void* p) {
    struct feed_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        room_topic(x, t->topic, sizeof t->topic);
        if (!ps_subscribe(x, t->topic)) { http_respond(x, 503, "text/plain", "busy\n", 5); cco_return; }
        http_set_header(x, "Cache-Control", "no-cache");
        http_start(x, 200, "text/event-stream");
        cco_await(http_sendf(x, ": subscribed to %s\n\n", t->topic));
        for (;;) {                              /* ends when the client disconnects */
            cco_await(ps_ready(x));
            t->pm = ps_recv(x);
            cco_await(http_sendf(x, "data: %.*s\n\n", (int)(t->pm.len > 900 ? 900 : t->pm.len), t->pm.data));
        }
    }
    return cco_DONE;
}

/* POST /rooms/:room - publish the request body to the room from plain HTTP. */
static void h_room_post(http_ctx* x) {
    char topic[80];
    room_topic(x, topic, sizeof topic);
    http_str b = http_body(x);
    int n = ps_publish(topic, WS_TEXT, b.ptr, b.len);
    http_respondf(x, 200, "application/json", "{\"delivered\":%d}\n", n);
}

/* GET /chat - browser chat page (open it in two tabs). */
static void h_chat_page(http_ctx* x) {
    static const char page[] =
        "<!doctype html><meta charset=utf-8><title>Chat</title>"
        "<body style='font-family:system-ui;max-width:40em;margin:2em auto'>"
        "<h3>Room <input id=room value=lobby size=10> <button id=join>Join</button></h3>"
        "<pre id=log style='height:20em;overflow:auto;background:#f4f4f4;padding:.5em'></pre>"
        "<input id=msg size=40 placeholder='say something'> <button id=send>Send</button>"
        "<p style='color:#666'>Also try: <code>curl -d hello localhost:PORT/rooms/lobby</code></p><script>"
        "const $=id=>document.getElementById(id),log=t=>{$('log').textContent+=t+'\\n';$('log').scrollTop=1e9};let ws;"
        "function join(){if(ws)ws.close();$('log').textContent='';"
        "ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/chat/'+encodeURIComponent($('room').value));"
        "ws.onopen=()=>log('[joined '+$('room').value+']');ws.onmessage=e=>log(e.data);ws.onclose=e=>log('[closed '+e.code+']');}"
        "$('join').onclick=join;$('send').onclick=()=>{ws.send($('msg').value);$('msg').value='';};"
        "$('msg').onkeydown=e=>{if(e.key==='Enter')$('send').click()};join();"
        "</script>";
    http_respond(x, 200, "text/html; charset=utf-8", page, sizeof page - 1);
}

/* GET /ws-test - a small browser page for trying the WebSocket endpoints. */
static void h_ws_test(http_ctx* x) {
    static const char page[] =
        "<!doctype html><meta charset=utf-8><title>WebSocket test</title>"
        "<body style='font-family:system-ui;max-width:40em;margin:2em auto'>"
        "<h3>/ws/clock</h3><p>Ticks every second. Type a message, or <b>stop</b> to close.</p>"
        "<input id=msg size=30> <button id=send>Send</button><pre id=log></pre><script>"
        "const log=t=>document.getElementById('log').textContent+=t+'\\n';"
        "const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/clock');"
        "ws.onopen=()=>log('connected');ws.onmessage=e=>log('< '+e.data);"
        "ws.onclose=e=>log('closed '+e.code+' '+e.reason);"
        "document.getElementById('send').onclick=()=>{const m=document.getElementById('msg');ws.send(m.value);log('> '+m.value);m.value='';};"
        "</script>";
    http_respond(x, 200, "text/html; charset=utf-8", page, sizeof page - 1);
}

/* GET /whoami - what the server believes about this request (useful behind a proxy). */
static void h_whoami(http_ctx* x) {
    char peer[INET6_ADDRSTRLEN], host[256] = "";
    ip_to_str(&x->c->peer, peer, sizeof peer);
    http_str h = http_header_get(x, "host");
    if (h.ptr) json_escape(h, host, sizeof host);
    http_respondf(x, 200, "application/json",
        "{\"client_ip\":\"%s\",\"scheme\":\"%s\",\"peer\":\"%s\",\"peer_trusted\":%s,\"host\":\"%s\",\"http\":\"%d.%d\"}\n",
        http_client_ip(x), http_scheme(x), peer, ip_trusted(&x->c->peer) ? "true" : "false",
        host, x->version_major, x->version_minor);
}

/* GET /stats */
static void h_stats(http_ctx* x) {
    char buf[4096];
    int n = format_stats(buf, sizeof buf, x->c->r);
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;   /* truncated */
    http_respond(x, 200, "text/plain", buf, (size_t)n);
}

/* GET /work - burns WORK_US of CPU to simulate an expensive request. */
static void h_work(http_ctx* x) {
    int64_t end = now_ns() + WORK_US * 1000;
    unsigned long v = 0;
    while (now_ns() < end) v = v * 6364136223846793005UL + 1442695040888963407UL;
    http_respondf(x, 200, "text/plain", "worked %dus on reactor%d (%lx)\n", WORK_US, x->c->r->id, v & 0xff);
}

static const http_route app_routes[] = {
    {"GET",  "/",             .handle = h_hello},
    {"GET",  "/users/:id",    .handle = h_user},
    {"GET",  "/static/*path", .handle = h_static},
    {"POST", "/upload",       .handle = h_upload, .body_limit = 1u << 20},
    {"POST", "/count",        .stream = s_count,   .task_size = sizeof(struct count_task)},
    {"POST", "/echo",         .stream = s_echo,    .task_size = sizeof(struct echo_task)},
    {"GET",  "/stream",       .stream = s_numbers, .task_size = sizeof(struct numbers_task)},
    {"GET",  "/events",       .stream = s_events,  .task_size = sizeof(struct events_task)},
    {"GET",  "/ws/echo",      .websocket = ws_echo,  .task_size = sizeof(struct wsecho_task)},
    {"GET",  "/ws/clock",     .websocket = ws_clock, .task_size = sizeof(struct clock_task)},
    {"GET",  "/ws-test",      .handle = h_ws_test},
    {"GET",  "/ws/chat/:room",       .websocket = ws_chat, .task_size = sizeof(struct chat_task)},
    {"GET",  "/rooms/:room/events",  .stream = s_room_feed, .task_size = sizeof(struct feed_task)},
    {"POST", "/rooms/:room",         .handle = h_room_post, .body_limit = 64 * 1024},
    {"GET",  "/chat",                .handle = h_chat_page},
    {"GET",  "/whoami",       .handle = h_whoami},
    {"GET",  "/stats",        .handle = h_stats},
    {"GET",  "/work",         .handle = h_work},
    {0},
};
#endif /* SERVER_NO_MAIN */

/* ======================================================================== */
/* main                                                                     */
/* ======================================================================== */

static bool add_trusted(const char* list) {
    const char* p = list;
    while (*p) {
        const char* comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        if (n) {
            if (g_ntrusted == MAX_TRUSTED || !cidr_parse(p, n, &g_trusted[g_ntrusted])) {
                fprintf(stderr, "bad --trust-proxy entry: %.*s\n", (int)n, p);
                return false;
            }
            ++g_ntrusted;
        }
        p += n + (comma ? 1 : 0);
    }
    return true;
}

static void usage(const char* prog) {
    fprintf(stderr,
        "usage: %s [options] [port] [threads]\n"
        "  --bind=ADDR          listen address (default 0.0.0.0; 127.0.0.1 behind a local proxy)\n"
        "  --keepalive=MS       idle keep-alive between requests (default %d, min %d)\n"
        "  --trust-proxy=LIST   proxies allowed to set X-Forwarded-* / send PROXY headers,\n"
        "                       e.g. 127.0.0.1,::1,10.0.0.0/8\n"
        "  --proxy-protocol     expect a PROXY v1/v2 header on every connection\n",
        prog, DEFAULT_KEEPALIVE_MS, TIMEOUT_MS);
}

int http_server_main(int argc, char* argv[], const http_route* routes) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { fprintf(stderr, "WSAStartup failed\n"); return 1; }
    iocp_init();
#endif
    static const struct option opts[] = {
        {"bind",           required_argument, 0, 'b'},
        {"keepalive",      required_argument, 0, 'k'},
        {"trust-proxy",    required_argument, 0, 't'},
        {"proxy-protocol", no_argument,       0, 'p'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };
    for (int ch; (ch = getopt_long(argc, argv, "", opts, NULL)) != -1; ) {
        switch (ch) {
        case 'b': g_bind = optarg; break;
        case 'k': g_keepalive_ms = atoi(optarg); break;
        case 't': if (!add_trusted(optarg)) return 2; break;
        case 'p': g_proxy_protocol = true; break;
        default:  usage(argv[0]); return ch == 'h' ? 0 : 2;
        }
    }
    if (g_keepalive_ms < TIMEOUT_MS) g_keepalive_ms = TIMEOUT_MS;   /* checked at that granularity */
    /* PROXY protocol without --trust-proxy: trust a local proxy only. Exactly
       the addresses it connects from, not all of 127/8: anything in the
       trusted set may also vouch for X-Forwarded-For entries. */
    if (g_proxy_protocol && g_ntrusted == 0) add_trusted("127.0.0.1,::1");

    int port = optind < argc ? atoi(argv[optind]) : 8080;
    int ncpu = online_cpus();
    int nthreads = optind + 1 < argc ? atoi(argv[optind + 1]) : (ncpu > 0 ? ncpu : 1);
    if (nthreads < 1) nthreads = 1;

    stop_signals_init();        /* before starting threads, so they inherit the signal mask */

    llhttp_settings_init(&g_parser_settings);
    g_parser_settings.on_url = on_url;
    g_parser_settings.on_header_field = on_header_field;
    g_parser_settings.on_header_value = on_header_value;
    g_parser_settings.on_headers_complete = on_headers_complete;
    g_parser_settings.on_body = on_body;
    g_parser_settings.on_message_complete = on_message_complete;
    g_routes = routes;

    g_nreactors = nthreads;
    g_reactors = calloc((size_t)nthreads, sizeof *g_reactors);
    if (!g_reactors) { perror("calloc"); return 1; }

    /* Open all listeners before starting threads, so a bind error fails fast. */
    for (int i = 0; i < nthreads; ++i) {
        struct reactor* r = &g_reactors[i];
        r->id = i;
        r->port = port;
        if (reactor_open(r) < 0) { net_error("reactor setup (socket/bind/listen)"); return 1; }
    }

    for (int i = 0; i < nthreads; ++i) {
        struct reactor* r = &g_reactors[i];
        if (pthread_create(&r->thread, NULL, reactor_run, r) != 0) {
            perror("pthread_create");
            return 1;
        }
        if (nthreads <= ncpu) pin_thread(r->thread, i);   /* reactor i on CPU i */
    }

    printf("listening on %s port %d with %d reactor thread(s)%s%s, %d trusted prox%s\n",
           g_bind, port, nthreads, nthreads > 1 ? ", rebalancing on" : "",
           g_proxy_protocol ? ", PROXY protocol" : "", g_ntrusted, g_ntrusted == 1 ? "y" : "ies");
    fflush(stdout);

    stop_signals_wait();

    int active = 0;
    for (int i = 0; i < nthreads; ++i)
        active += atomic_load(&g_reactors[i].active);
    printf("\nshutting down, closing %d connection(s)...\n", active);

    for (int i = 0; i < nthreads; ++i)
        reactor_notify(&g_reactors[i], NOTE_STOP);
    for (int i = 0; i < nthreads; ++i)
        pthread_join(g_reactors[i].thread, NULL);
    for (int i = 0; i < nthreads; ++i) {             /* close after join: others wrote to them */
        struct reactor* r = &g_reactors[i];
#ifndef _WIN32
        sock_close(r->wakefd);
        sock_close(r->inboxfd);
        sock_close(r->psfd);
#endif
        pthread_mutex_destroy(&r->inbox_lock);
        /* wake-ups posted after a reactor stopped: just drop their references */
        for (int k = 0; k < r->nwq; ++k) ps_sub_unref(r->wq[k]);
        free(r->wq);
        free(r->wq_spare);
        pthread_mutex_destroy(&r->wq_lock);
    }

    long mig = 0;
    for (int i = 0; i < nthreads; ++i) mig += atomic_load(&g_reactors[i].migrated_out);
    printf("bye (%ld migration(s) performed)\n", mig);
#ifdef _WIN32
    WSACleanup();                                    /* (each reactor closed its own port) */
#endif
    free(g_reactors);
    return 0;
}

#ifndef SERVER_NO_MAIN
int main(int argc, char* argv[]) { return http_server_main(argc, argv, app_routes); }
#endif
