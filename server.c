/*
 * server.c - multi-core HTTP/1.1 server on STC stackless coroutines, with
 *            full HTTP/1.1 parsing (llhttp), streaming request and response
 *            bodies, a router with path parameters, and load-based
 *            rebalancing of connections between cores.
 *
 * Copyright (c) 2026 Manuel Capel. SPDX-License-Identifier: MIT
 *
 * Linux (epoll, SO_REUSEPORT, eventfd) and Windows 10 1703+ (I/O completion
 * ports, built with MinGW-w64; see src/platform.c and src/eventloop.c).
 *
 * This file holds the overview, the includes and the tunable limits; the code
 * is in src/, which it includes in order below, so the whole server is still
 * one compilation unit built from this one file:
 *   src/platform.c    OS layer: sockets, wake-ups, signals, threads
 *   src/runtime.c     reactors, connections, requests; deadlines, timer heap
 *   src/http.c        parsing, request accessors, responses, formatting, router
 *   src/websocket.c   WebSocket handshake, framing, handler API
 *   src/pubsub.c      publish/subscribe between connections
 *   src/proxy.c       client addresses behind a proxy, PROXY protocol
 *   src/connection.c  the connection coroutine
 *   src/reactor.c     scheduling, accepting, deadlines, migration, rebalancing
 *   src/eventloop.c   listener, IOCP (Windows) / epoll (Linux) event loops
 *   src/demo.c        the demo routes
 *   src/main.c        command line, http_server_main()
 *
 * Built as is, this is a demo program (the routes in src/demo.c). Built with
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

#include "src/platform.c"

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

/* The rest of the server, in order (each file depends on the ones before it). */
#include "src/runtime.c"
#include "src/http.c"
#include "src/websocket.c"
#include "src/pubsub.c"
#include "src/proxy.c"
#include "src/connection.c"
#include "src/reactor.c"
#include "src/eventloop.c"
#include "src/demo.c"
#include "src/main.c"
