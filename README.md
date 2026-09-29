# cerveur

[![CI](https://github.com/mancap314/cerveur/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mancap314/cerveur/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A multi-core HTTP/1.1 server in C, built from a single source file
(`server.c`, which includes the parts in `src/`). It parses HTTP with
[llhttp](https://github.com/nodejs/llhttp) (Node.js's parser) and runs every
connection as a stackless coroutine from [STC](https://github.com/stclib/STC),
one event loop per CPU core, moving busy connections between cores when one
of them runs hot.

It runs on Linux (epoll) and on Windows 10 1703 or later (I/O completion
ports). It can be built as a stand-alone demo program or as a library for
your own C or C++ program.

## Features

- **HTTP/1.1**: keep-alive, pipelining, chunked request and response bodies,
  `Expect: 100-continue`, `413`/`431`/`400` for oversized or malformed
  requests, lingering close so error responses reach clients that are still
  uploading.
- **Router** with `:name` path parameters and a trailing `*name` wildcard;
  `404`, and `405` with an `Allow` header; `HEAD` served by `GET` routes.
- **Three kinds of handlers**: buffered (the whole body is read first),
  streaming (a coroutine that reads the body chunk by chunk and writes the
  response as it goes, with backpressure in both directions), and WebSocket.
- **WebSockets** (RFC 6455): fragmentation, UTF-8 validation, ping/pong,
  close handshake, keepalive pings, and detection of peers that stop reading.
- **Server-sent events** with keepalive comments.
- **Timers** a handler can wait on, alone or together with other events.
- **Publish/subscribe between connections** on any thread (chat rooms, live
  feeds), with per-subscriber mailboxes that never block the publisher.
- **Load-based rebalancing**: every 250 ms each core measures its CPU load and,
  if it is clearly the busiest, hands its heaviest connections to the least
  loaded one, mid-request if need be.
- **Reverse-proxy aware**: the real client address from `X-Forwarded-For` (only
  from trusted proxies) or the PROXY protocol v1/v2, and
  `X-Forwarded-Proto`. TLS, HTTP/2 and HTTP/3 are left to the proxy by design;
  example configs for Caddy, nginx and HAProxy are included.
- **Graceful shutdown** on SIGINT/SIGTERM (Ctrl+C / Ctrl+Break on Windows).

## How it works

**One reactor per core.** The server starts one thread per CPU (or as many as
you ask for), each pinned to its core with its own event loop. On Linux every
reactor has its own `SO_REUSEPORT` listener and epoll set, so the kernel
spreads new connections. On Windows every reactor has an I/O completion port;
reactor 0 accepts with `AcceptEx` and deals connections out round-robin.

**One coroutine per connection.** A connection is an STC stackless coroutine:
a plain struct plus a `switch`-based resume point. An idle connection costs
about 17 KB (its 16 KB input buffer and ~660 bytes of state); a request in
progress adds a 44 KB context (header space and response buffer), recycled
between requests. The coroutine reads the request head, routes it, runs the
handler, flushes the response, and loops for keep-alive. It is only resumed
when its socket is ready, its timer fires or pub/sub mail arrives, so there
is no thread per connection and no locking on the request path.

**Handlers are coroutines too.** A streaming or WebSocket handler awaits
events with `cco_await`: a body chunk (`http_body_ready`), room in the output
buffer (`http_send`), a WebSocket message (`ws_recv_ready`), a timer
(`http_timer_done`) or pub/sub mail (`ps_ready`), or any combination of them.
While it waits, the connection does the I/O it is waiting for. A handler that
writes faster than the client reads is simply resumed less often.

**Migration is a pointer handoff.** Because a suspended connection, including
its handler, is just a struct, moving it to another core means passing a
pointer through that core's inbox. On Windows the socket must first be moved to
the other reactor's completion port, which is only possible with no I/O
pending, so the connection's posted read is cancelled first.

**I/O.** On Linux: level-triggered epoll and non-blocking `recv`/`send`. On
Windows: overlapped `WSARecv`/`WSASend` straight into the connection's buffers,
with sockets in "skip completion on success" mode so that a read that finds
data already waiting costs one call, like `recv`. Small writes between two
flushes are merged into one chunk. A connection's input buffer grows from
16 KB to 64 KB while it receives bulk data, and shrinks back when it goes idle.

**Formatting.** `http_sendf`, `http_respondf`, `ws_sendf` and the response
headers use a small built-in formatter for the common conversions (`%d %u %x
%s %c` with widths and length modifiers), falling back to `vsnprintf` for
anything else: printf was the main cost of handlers that format their output.

## Building

The server needs two dependencies, downloaded next to `server.c` by
`deploy/fetch_deps.sh` (or by hand):

    mkdir -p stc && curl -sSLo stc/coroutine.h \
        https://raw.githubusercontent.com/stclib/stcsingle/main/stc/coroutine.h
    git clone --depth 1 --branch release https://github.com/nodejs/llhttp.git

**Linux** (gcc or clang):

    gcc -std=gnu11 -O2 -Wall -pthread -Illhttp/include -o server server.c \
        llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c

**Windows** (MinGW-w64 gcc with posix threads, for example from Git Bash):

    gcc -std=gnu11 -O3 -Wall -pthread -Illhttp/include -o server.exe server.c \
        llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c -lws2_32

Useful compile-time options:

| Option | Effect |
|---|---|
| `-DSERVER_NO_MAIN` | Build as a library: leaves out the demo routes and `main()` (see below). |
| `-DOUT_CAP=131072` | Larger response buffer per active request: about 10% less CPU for large bodies, at the cost of memory for every open WebSocket or SSE stream (default 32768). |
| `-DIO_STATS` | Count system calls per request (reads, writes, wasted calls, accepts), shown by `GET /stats` and by `bench.py`. |
| `-DTIMEOUT_MS=…`, `-DWS_PING_MS=…`, … | Shorter timers, used by the test build (`deploy/build_test_server.sh`). |

## Running the demo

    ./server [options] [port] [threads]          # defaults: 8080, one thread per CPU

| Option | Meaning |
|---|---|
| `--bind=ADDR` | Listen address (default `0.0.0.0`; `::` for dual stack; `127.0.0.1` behind a proxy). |
| `--keepalive=MS` | Idle keep-alive between requests (default 75000). |
| `--trust-proxy=LIST` | Comma-separated addresses/CIDRs of your proxies, e.g. `127.0.0.1,::1,10.0.0.0/8`; only these may set `X-Forwarded-*` or send PROXY headers. |
| `--proxy-protocol` | Every connection starts with a PROXY v1/v2 header. |

The demo routes show every feature:

    open http://localhost:8080/chat in two browser tabs    # pub/sub chat over WebSockets
    open http://localhost:8080/ws-test                     # WebSocket echo and clock
    curl -d 'hello room' localhost:8080/rooms/lobby        # publish into the chat over HTTP
    curl -N 'localhost:8080/events?n=5'                    # server-sent events, one per second
    curl 'localhost:8080/users/42?verbose=1'               # path parameter and query string
    curl -N 'localhost:8080/stream?n=5'                    # streamed response
    curl --data-binary @bigfile localhost:8080/echo | cmp - bigfile   # full-duplex streaming
    curl localhost:8080/stats                              # per-core load, requests, migrations

On Windows, `localhost` tries `::1` first and a refused IPv6 connection takes
about 2 s to fall back to IPv4: start the server with `--bind=::` or use
`127.0.0.1`.

## Using it from your own program (C or C++)

Build `server.c` with `-DSERVER_NO_MAIN`, include `server.h` (plain C API,
`extern "C"` for C++), and start the server with your route table:

```c
#include "server.h"

static void hello(http_ctx* x) {
    http_str name = http_param(x, "name");
    http_respondf(x, 200, "text/plain", "Hello, %.*s!\n", (int)name.len, name.ptr);
}

static const http_route routes[] = {
    {"GET", "/hello/:name", hello},     /* method, pattern, handler, ... */
    {0},
};

int main(int argc, char** argv) { return http_server_main(argc, argv, routes); }
```

    gcc -c -O2 -pthread -Illhttp/include -DSERVER_NO_MAIN server.c llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c
    g++ -std=c++17 -O2 -pthread -Illhttp/include example.cpp *.o -o example    # Windows: add -lws2_32

`http_server_main` takes the same command-line options as the demo.
`example.cpp` shows a buffered handler (a plain function or a capture-less
lambda), a streaming handler with a timer, and a WebSocket handler in C++. The
demo handlers in `src/demo.c` cover the rest of the API.

Streaming and WebSocket handlers are coroutines, so local variables do not
survive a `cco_await`: keep that state in the task struct (which starts with
`HTTP_TASK`). In C++, also avoid initialized declarations between `cco_async`
and the awaits, since the coroutine macros jump over them. `server.h` supplies
a C++-compatible `cco_async`; on Windows, include `<windows.h>` (if you need
it) before `server.h`.

## Running behind a reverse proxy

The proxy handles TLS, HTTP/2 (and HTTP/3 with Caddy) and compression; the
server speaks HTTP/1.1 on loopback. Pick one config:

| File          | Proxy   | How the client address reaches the server        | Start the server with |
|---------------|---------|--------------------------------------------------|-----------------------|
| `Caddyfile`   | Caddy   | `X-Forwarded-For` / `-Proto`                     | `./server --bind=127.0.0.1 --trust-proxy=127.0.0.1 8080` |
| `nginx.conf`  | nginx   | `X-Forwarded-For` / `-Proto`                     | `./server --bind=127.0.0.1 --trust-proxy=127.0.0.1 8080` |
| `haproxy.cfg` | HAProxy | PROXY protocol v2 (incl. "client used TLS" flag) | `./server --bind=127.0.0.1 --proxy-protocol 8080` |

Things that must line up (marked `[!]` in the configs):

- The proxy's upstream idle timeout must be shorter than the server's
  `--keepalive` (default 75 s), or the proxy may reuse a connection the server
  is closing. Caddy's default (2 min) is longer, so its config sets 60 s.
- `--bind=127.0.0.1` so clients can't bypass the proxy; `--trust-proxy` lists
  only the proxy's own address (never a range your clients could come from).
- nginx: `proxy_http_version 1.1`, the Upgrade/Connection headers for
  WebSockets, and a larger `client_max_body_size`.

No proxy timeout tuning is needed for WebSockets or server-sent events: the
server pings quiet WebSockets and sends SSE comment lines after 20 s of silence,
and SSE responses carry `X-Accel-Buffering: no` so nginx streams them.

In handlers, use `http_client_ip(x)` and `http_scheme(x)`; `GET /whoami` shows
what the server sees.

## Benchmarks

Measured with `bench.py` on a laptop: Intel Core i3-1115G4 (2 cores,
4 threads), Windows 11, over loopback. The server ran with 2 reactor threads
pinned to CPUs 0–1, and the load generator ([oha](https://github.com/hatoo/oha))
on CPUs 2–3. Medians of 5 runs of 4 s, with other programs using about half of
the machine at the time.

| Scenario | Requests/s | Latency p50 / p99 | Server CPU per request | Server CPU busy |
|---|---|---|---|---|
| `GET /`, 64 keep-alive connections | 83,700 | 0.58 / 4.6 ms | 12 µs | 45% |
| `GET /`, 32 connections, a new TCP connection per request | 5,400 | 5.0 / 28 ms | 81 µs | 20% |
| `GET /stream?n=2000` (2000 formatted lines, ~19 KB), 16 connections | 11,600 (219 MB/s) | 1.1 / 6.1 ms | 134 µs | 74% |
| `POST /echo` with 64 KB bodies, 16 connections | 21,300 (1.4 GB/s) | 0.55 / 4.5 ms | 63 µs | 66% |

In the first two scenarios the server's cores were less than half busy: the
load generator on the other two cores was the limit, so the server's own
ceiling there is higher than these figures. Server-sent events scheduled every
10 ms arrive every ~16 ms on Windows, which is the system timer's resolution.

**Compared with Axum.** The same benchmark against a minimal
[Axum](https://github.com/tokio-rs/axum) 0.8 server (Tokio, 2 worker threads,
same endpoints, same pinning), alternating the two servers over 6 rounds:

| Scenario | Server CPU per request, Axum relative to cerveur | Requests/s, Axum relative to cerveur |
|---|---|---|
| Keep-alive `GET /` | +83% ± 5 | −8.5% ± 3.7 |
| New connection per request | +80% ± 9 | +8.8% ± 4.8 |
| 64 KB echo | −11% ± 1.4 | +11.7% ± 4.8 |
| 2000-line stream, Axum building the body in one buffer | −6% ± 0.9 | −2.5% ± 2.9 |
| 2000-line stream, Axum streaming one item per line | +1509% | −95% |

cerveur uses about half the CPU of Axum per small request and per new
connection; Axum moves large bodies about 10% more cheaply (building cerveur
with `-DOUT_CAP=131072` closes most of that gap). Axum does far more (HTTP/2,
TLS, middleware), so this compares the core HTTP/1.1 path only.

**Caveats.** One laptop, loopback only, Windows only: the Linux build has not
been benchmarked, and a real network changes the cost of sending. Run-to-run
noise on this machine reached 10–30%, so compare builds by alternating them
and looking at paired differences rather than single runs.

**Running the benchmark yourself:**

    python bench.py --oha path/to/oha --save before.json
    python bench.py --oha path/to/oha --compare before.json
    python bench.py --server path/to/other/server --only hello,echo

`bench.py` pins the server and oha to separate CPUs (`--server-cpus`,
`--client-cpus`) and reports throughput, latency, the server's CPU time per
request (user and kernel) and how busy its cores were. Any server that takes
`--bind=ADDR port threads` and serves the same endpoints can be measured; with
a `-DIO_STATS` build it also shows system calls per request.

## Testing

The test suites run against a running server (they need Python 3 and
`pip install websockets`, and exit with status 1 if a check fails):

    deploy/run_tests.sh ./server       # starts it, runs the three suites, stops it

    ./server 8080 &                    # or by hand:
    python3 test_http.py 8080      # HTTP/1.1: routing, bodies, streaming, pipelining, limits (29 checks)
    python3 test_ws.py 8080        # WebSocket protocol, timers, idle timeouts (35 checks)
    python3 test_ps.py 8080        # pub/sub: rooms, fan-out, ordering, slow subscribers (14 checks)

`deploy/run_tests.sh` also fails if the server dies, if a sanitizer reports
anything, or (on Linux) if it doesn't shut down cleanly. On Windows, run it
from Git Bash with `PYTHON=python`.

The proxy tests use a build with shortened timers and real proxies (Linux):

    ./deploy/build_test_server.sh      # server_t with shortened timers
    ./deploy/start_test_stack.sh       # 3 servers + nginx, Caddy, HAProxy on 8443-8445
    python3 test_proxy.py              # 45 tests

On Windows, `deploy/build_test_server.sh` works from Git Bash, but
`start_test_stack.sh` is Linux-only; the proxy-independent parts of
`test_proxy.py` can be run against three `server_t` instances started by hand.

**Sanitizers.** Build with Clang and `-fsanitize=address,undefined` (or
`-fsanitize=thread`) and run `deploy/run_tests.sh` on the result.

**Fuzzing.** `fuzz/` has four targets for the code that parses untrusted input:
requests (`fuzz_http.c`: parser callbacks, router, bodies, query decoding,
`X-Forwarded-For`), WebSocket frames (`fuzz_ws.c`), PROXY protocol headers and
address parsing (`fuzz_proxy.c`), and the formatter checked against the C
library's `vsnprintf` (`fuzz_fmt.c`). With Clang they build with libFuzzer:

    clang -g -O1 -fsanitize=fuzzer,address,undefined -Illhttp/include fuzz/fuzz_http.c \
        llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c -pthread -o fuzz_http
    ./fuzz_http -max_total_time=300 corpus/

With any other compiler, add `-DFUZZ_STANDALONE` (and `-lws2_32` on Windows)
for a simple built-in driver that mutates the targets' example inputs
(`FUZZ_SECONDS=60 ./fuzz_http`, or `./fuzz_http crash-file` to replay one).

**Continuous integration.** `.github/workflows/ci.yml` builds and tests on
Linux (gcc and clang, warnings as errors), runs the suites under
AddressSanitizer + UndefinedBehaviorSanitizer and ThreadSanitizer, fuzzes each
target for a minute, runs the proxy tests behind real nginx, Caddy and HAProxy,
and builds and tests on Windows (MinGW-w64).

## Files

| File | Contents |
|---|---|
| `server.c` | What you compile: overview, includes and tunable limits; includes the files in `src/` in order. |
| `src/` | The server's code by topic: `platform.c`, `runtime.c`, `http.c`, `websocket.c`, `pubsub.c`, `proxy.c`, `connection.c`, `reactor.c`, `eventloop.c`, `demo.c` (demo routes), `main.c`. Not compiled on their own. |
| `server.h` | Public API for handlers, and `http_server_main()` for library builds. |
| `example.cpp` | Using the server from C++. |
| `bench.py` | Benchmark driver (oha-based). |
| `test_http.py`, `test_ws.py`, `test_ps.py`, `test_proxy.py` | Test suites. |
| `fuzz/` | Fuzz targets (libFuzzer, or a built-in driver). |
| `Caddyfile`, `nginx.conf`, `haproxy.cfg` | Reverse-proxy configurations. |
| `deploy/` | Scripts: fetch the dependencies, run the test suites, test build, local proxy stack. |
| `.github/workflows/ci.yml` | Continuous integration (GitHub Actions). |

## License

MIT, see [LICENSE](LICENSE). The dependencies are MIT-licensed as well:
[llhttp](https://github.com/nodejs/llhttp) and [STC](https://github.com/stclib/STC).
