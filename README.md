# Running the STC server behind a reverse proxy

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

## Windows

The server also builds natively on Windows 10 (1703+) with MinGW-w64 gcc (no
extra dependencies); build instructions are at the top of `server.c`, and
`deploy/build_test_server.sh` works from Git Bash. Differences from Linux:

- The event loop uses an I/O completion port per reactor instead of epoll:
  reads and writes are overlapped `WSARecv`/`WSASend` straight into the
  connection's buffers, and the connection coroutines run unchanged on top.
- There is no `SO_REUSEPORT`, so there is one listening socket: reactor 0
  accepts (`AcceptEx`) and deals new connections out round-robin to all
  reactors. Moving a connection to another reactor first cancels its posted
  read, since a socket can only change completion ports with no I/O pending.
- `localhost` resolves to `::1` first, and a refused IPv6 connect takes ~2 s to
  fall back to IPv4. Start the server with `--bind=::` (dual stack) or point
  clients at `127.0.0.1`.
- Stop it with Ctrl+C / Ctrl+Break (there is no SIGTERM).
- `deploy/start_test_stack.sh` is Linux-only (`setsid`, `pkill`, `/dev/tcp`).

## Benchmarking

`bench.py` drives the server with [oha](https://github.com/hatoo/oha), pinning
server and load generator to separate CPUs, and reports the median of several
runs per scenario (keep-alive, new connection per request, streamed and echoed
bodies, SSE delivery gaps):

    python bench.py --oha path/to/oha --save before.json
    python bench.py --oha path/to/oha --compare before.json

Build the server with `-DIO_STATS` to also get syscalls per request (`recv`,
`send`, wasted calls, epoll interest changes, `accept`), shown by `/stats` and
by `bench.py`. Run-to-run noise on a laptop can reach 10-15%, so alternate the
builds you compare and look at paired differences rather than single runs.

## Testing locally

    ./deploy/build_test_server.sh      # server_t with shortened timers
    ./deploy/start_test_stack.sh       # 3 servers + nginx, Caddy, HAProxy on 8443-8445
    python3 test_proxy.py              # 45 tests (needs: pip install websockets)
