# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may
change the API).

## [0.1.0] - 2026-09-29

First release.

### Server
- Multi-core HTTP/1.1 server: one reactor thread per core, one STC stackless
  coroutine per connection, llhttp for parsing.
- Keep-alive, pipelining, chunked request and response bodies,
  `Expect: 100-continue`, `413`/`431`/`400` for oversized or malformed
  requests, lingering close.
- Router with `:name` parameters and a trailing `*name` wildcard; `404`, `405`
  with `Allow`; `HEAD` served by `GET` routes.
- Buffered, streaming and WebSocket handlers; timers; server-sent events with
  keepalive comments.
- WebSockets (RFC 6455): fragmentation, UTF-8 validation, ping/pong, close
  handshake, keepalive pings, detection of peers that stop reading.
- Publish/subscribe between connections across threads.
- Load-based rebalancing: busy connections move between cores, mid-request if
  need be.
- Reverse-proxy support: client address from `X-Forwarded-For` (trusted
  proxies only) or the PROXY protocol v1/v2, and `X-Forwarded-Proto`; example
  configurations for Caddy, nginx and HAProxy.
- Graceful shutdown on SIGINT/SIGTERM (Ctrl+C / Ctrl+Break on Windows).

### Platforms
- Linux: epoll, one `SO_REUSEPORT` listener per reactor.
- Windows 10 1703+ (MinGW-w64): I/O completion ports, overlapped reads and
  writes straight into the connection's buffers, `AcceptEx`.

### Using it
- Stand-alone demo program, or a library for C and C++ programs
  (`-DSERVER_NO_MAIN`, `server.h`, `http_server_main()`); `example.cpp`.

### Performance
- Built-in formatter for the common `printf` conversions, used by the
  `*printf` handler APIs and response headers.
- Input buffer that grows from 16 KB to 64 KB for bulk transfers and shrinks
  back when the connection goes idle.
- `-DOUT_CAP` to enlarge the response buffer for large-body workloads;
  `-DIO_STATS` for per-request system call counts.
- `bench.py`: benchmark driver (oha) reporting throughput, latency and server
  CPU per request.

### Quality
- Test suites for HTTP, WebSockets, pub/sub and proxy deployments;
  `deploy/run_tests.sh`.
- Fuzz targets for request parsing, WebSocket frames, PROXY headers and the
  formatter (libFuzzer, or a built-in driver).
- Continuous integration on Linux (gcc, clang, AddressSanitizer +
  UndefinedBehaviorSanitizer, ThreadSanitizer, fuzzing, proxy tests) and
  Windows.

[0.1.0]: https://github.com/mancap314/cerveur/releases/tag/v0.1.0
