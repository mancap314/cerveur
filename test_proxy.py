# Proxy-readiness tests. Expects deploy/start_test_stack.sh to be running:
#   8080 server A (trusts 127.0.0.1, 10/8; --keepalive=6000)   8443 nginx  -> A
#   8081 server B (--proxy-protocol)                           8444 Caddy  -> A
#   8082 server C (trusts nobody)                              8445 HAProxy -> B (PROXY v2 + TLS TLV)
# The server is built with TIMEOUT_MS=2000 WS_PING_MS=3000 WS_PONG_MS=2000
# WS_STALL_MS=6000 SSE_KEEPALIVE_MS=3000 (see deploy/build_test_server.sh). "Outside" clients connect from 127.0.0.2.
import socket, ssl, json, time, struct, os, subprocess, threading, asyncio, warnings, logging
warnings.filterwarnings("ignore"); logging.disable(logging.CRITICAL)
import websockets
from websockets.sync.client import connect as ws_connect
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS {name}")
    else: failed += 1; print(f"  FAIL {name}  {str(detail)[:300]}")
OUTSIDE = ("127.0.0.2", 0)
def conn(port, src=OUTSIDE):
    s = socket.create_connection(("127.0.0.1", port), timeout=10, source_address=src); return s
def read_response(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: raise EOFError("closed")
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
    while len(rest) < n: rest += s.recv(65536)
    return head, rest[:n]
def whoami(port, headers="", prefix=b"", src=OUTSIDE):
    s = conn(port, src); s.sendall(prefix + f"GET /whoami HTTP/1.1\r\nHost: x\r\n{headers}\r\n".encode())
    return json.loads(read_response(s)[1])
def closed_by_server(s, within):
    s.settimeout(within)
    try: return s.recv(4096) == b""
    except (socket.timeout, TimeoutError): return False
    except (ConnectionResetError, ConnectionAbortedError): return True   # (the latter on Windows)
def curl(*args): return subprocess.run(["curl", "-sk", "--interface", "127.0.0.2", *args], capture_output=True, text=True, timeout=30)

print("X-Forwarded-For / -Proto (direct)")
w = whoami(8082, "X-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: https\r\n")
check("untrusted peer: forwarded headers ignored", w["client_ip"] == "127.0.0.2" and w["scheme"] == "http", w)
w = whoami(8082, "X-Forwarded-For: 6.6.6.6\r\n", src=("127.0.0.1", 0))
check("server C trusts nobody, even loopback", w["client_ip"] == "127.0.0.1", w)
T = ("127.0.0.1", 0)   # server A trusts 127.0.0.1: act as its proxy
w = whoami(8080, "X-Forwarded-For: 9.9.9.9, 1.2.3.4, 10.0.0.5\r\n", src=T)
check("right-to-left past trusted hops: 1.2.3.4 (the spoofed 9.9.9.9 is ignored)", w["client_ip"] == "1.2.3.4", w)
w = whoami(8080, "X-Forwarded-For: 9.9.9.9\r\nX-Forwarded-For: 1.2.3.4\r\n", src=T)
check("repeated X-Forwarded-For headers are combined", w["client_ip"] == "1.2.3.4", w)
w = whoami(8080, "X-Forwarded-For: [2001:db8::7]:443\r\n", src=T)
check("IPv6 with brackets and port", w["client_ip"] == "2001:db8::7", w)
w = whoami(8080, "X-Forwarded-For: 1.2.3.4, unknown, 10.0.0.5\r\n", src=T)
check("junk entry stops the walk at the last good hop", w["client_ip"] == "10.0.0.5", w)
w = whoami(8080, "X-Forwarded-Proto: https\r\n", src=T)
check("X-Forwarded-Proto from a trusted proxy", w["scheme"] == "https", w)

print("PROXY protocol (direct to server B)")
def v2(src4=None, src6=None, tls=False, local=False):
    body = b""
    if src6: fam, body = 0x21, socket.inet_pton(socket.AF_INET6, src6) + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack(">HH", 5555, 443)
    elif src4: fam, body = 0x11, socket.inet_aton(src4) + socket.inet_aton("127.0.0.1") + struct.pack(">HH", 5555, 443)
    else: fam = 0x00
    if tls: body += bytes([0x20]) + struct.pack(">H", 5) + bytes([0x01]) + struct.pack(">I", 0)
    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes([0x20 if local else 0x21, fam]) + struct.pack(">H", len(body)) + body
check("v1 TCP4", whoami(8081, prefix=b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\n", src=T)["client_ip"] == "203.0.113.9")
check("v1 TCP6", whoami(8081, prefix=b"PROXY TCP6 2001:db8::1 ::1 5555 443\r\n", src=T)["client_ip"] == "2001:db8::1")
check("v1 UNKNOWN keeps the peer", whoami(8081, prefix=b"PROXY UNKNOWN\r\n", src=T)["client_ip"] == "127.0.0.1")
w = whoami(8081, prefix=v2(src4="198.51.100.4", tls=True), src=T)
check("v2 TCP4 + TLS flag -> client and https", w["client_ip"] == "198.51.100.4" and w["scheme"] == "https", w)
check("v2 TCP6", whoami(8081, prefix=v2(src6="2001:db8::42"), src=T)["client_ip"] == "2001:db8::42")
check("v2 LOCAL keeps the peer", whoami(8081, prefix=v2(local=True), src=T)["client_ip"] == "127.0.0.1")
s = conn(8081, T)
for b in v2(src4="192.0.2.77") + b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n": s.send(bytes([b])); time.sleep(0.001)
check("header and request dribbled byte by byte", json.loads(read_response(s)[1])["client_ip"] == "192.0.2.77")
s = conn(8081, T); s.sendall(b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
check("missing PROXY header -> connection closed", closed_by_server(s, 3))
s = conn(8081, T); s.sendall(b"PROXY TCP4 not-an-ip 127.0.0.1 1 2\r\n")
check("malformed PROXY header -> connection closed", closed_by_server(s, 3))
s = conn(8081, OUTSIDE); s.sendall(b"PROXY TCP4 6.6.6.6 127.0.0.1 1 2\r\nGET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
check("PROXY header from an untrusted peer -> connection closed", closed_by_server(s, 3))

print("keep-alive and header timeouts (TIMEOUT 2s, --keepalive=6000)")
s = conn(8080); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); read_response(s)
time.sleep(4.5); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
try: ok = read_response(s)[1].startswith(b"Hello")
except Exception: ok = False
check("idle 4.5s between requests (> 2s header timeout): connection still usable", ok)
t0 = time.time(); gone = closed_by_server(s, 12)
check(f"...closed after the keep-alive period ({time.time()-t0:.1f}s idle)", gone and 5 <= time.time() - t0 <= 10)
s = conn(8080); t0 = time.time(); gone = closed_by_server(s, 12)
check(f"fresh connection that sends nothing: header timeout, not keep-alive ({time.time()-t0:.1f}s)", gone and time.time() - t0 < 5)

print("WebSocket keepalive pings (ping after 3s quiet, pong within 2s)")
def raw_ws(port):
    s = conn(port); s.sendall(b"GET /ws/echo HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    return s
def read_frame(s, timeout):
    s.settimeout(timeout); h = s.recv(2)
    if len(h) < 2: return None
    n = h[1] & 0x7F; p = s.recv(n) if n else b""
    return h[0] & 0x0F, p
def pong(s):
    key = os.urandom(4); s.sendall(bytes([0x8A, 0x80]) + key)
s = raw_ws(8080); t0 = time.time(); f = read_frame(s, 10)
check(f"quiet WebSocket gets a ping ({time.time()-t0:.1f}s)", f and f[0] == 9 and 2.5 < time.time() - t0 < 7, f)
pong(s); f2 = read_frame(s, 10)
check("answering keeps it open: next ping arrives", f2 and f2[0] == 9, f2)
t0 = time.time()
try:
    f3 = read_frame(s, 10); rest = s.recv(10)
except Exception: f3, rest = None, None
check(f"not answering: server closes it ({time.time()-t0:.1f}s)", (f3 is None or f3[0] == 8) and time.time() - t0 < 8, f3)

print("WebSocket backlog vs liveness (ping 3s, pong 2s, stall limit 6s)")
def flood(room, secs, stop_evt=None):
    """Publish 1 KB messages to a room over HTTP keep-alive; returns delivered counts."""
    s = conn(8080, T); counts = []; end = time.time() + secs; body = b"y" * 1000
    while time.time() < end and not (stop_evt and stop_evt.is_set()):
        s.sendall(b"POST /rooms/%s HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n" % room.encode() + body)
        counts.append(json.loads(read_response(s)[1])["delivered"])
    return counts
def ws_sub(room, rcvbuf):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.bind(OUTSIDE); s.connect(("127.0.0.1", 8080))
    s.sendall(f"GET /ws/chat/{room} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    return s, buf.split(b"\r\n\r\n", 1)[1]
# 1) slow but steady reader. A 3 MB burst ends up queued in the kernel for
#    it; the server's own buffer and the mailbox empty,
#    and its keepalive pings sit behind that kernel backlog while the reader
#    works through it at 160 KB/s (answering pings as it reaches them). It
#    must not be disconnected: the pong can't come before the data ahead of it.
s, pending = ws_sub("slowroom", 16384)
ps = conn(8080, T); body = b"y" * 60000         # ~3 MB: fits in the kernel's send buffer,
for _ in range(50):                             # so the server's own buffer and mailbox empty
    ps.sendall(b"POST /rooms/slowroom HTTP/1.1\r\nHost: x\r\nContent-Length: 60000\r\n\r\n" + body)
    read_response(ps)
t0 = time.time(); got = 0; closed = False; pings = 0; buf = pending
s.settimeout(5)
while time.time() - t0 < 16:
    try: d = s.recv(32768)
    except (socket.timeout, TimeoutError): d = b"x"
    except OSError: closed = True; break
    if not d: closed = True; break
    buf += d; got += len(d)
    while len(buf) >= 2:                      # answer pings, like a real client
        n = buf[1] & 0x7F; off = 2 + (2 if n == 126 else 8 if n == 127 else 0)
        if len(buf) < off: break
        if n == 126: n = struct.unpack(">H", buf[2:4])[0]
        elif n == 127: n = struct.unpack(">Q", buf[2:10])[0]
        if len(buf) < off + n: break
        if buf[0] & 0x0F == 8: closed = True
        if buf[0] & 0x0F == 9:
            pings += 1; key = os.urandom(4); s.sendall(bytes([0x8A, 0x80]) + key)
        buf = buf[off + n:]
    time.sleep(0.2)
# The kernel keeps delivering queued data even after the server closes a
# socket, so the reader can't tell by itself: ask the server whether it is
# still subscribed.
ps = conn(8080, T)          # (the publishing connection has hit its keep-alive limit by now)
ps.sendall(b"POST /rooms/slowroom HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nprobe")
still = json.loads(read_response(ps)[1])["delivered"]
check(f"slow reader working through a kernel backlog for 16s stays connected (read {got//1024} KB, subscribers: {still})",
      not closed and got > 1_000_000 and still == 1, (closed, got, pings, still))
s.close()
# 2) dead reader: never reads, so no progress at all. Large messages fill the
#    kernel buffers within a second; after that the server must close it within
#    the stall limit (6s) plus check granularity (2 x 2s).
s, _ = ws_sub("deadroom", 16384)
t0 = time.time(); gone_at = None
ps = conn(8080, T); body = b"z" * 60000
while time.time() - t0 < 25:
    ps.sendall(b"POST /rooms/deadroom HTTP/1.1\r\nHost: x\r\nContent-Length: 60000\r\n\r\n" + body)
    if json.loads(read_response(ps)[1])["delivered"] == 0: gone_at = time.time() - t0; break
    time.sleep(0.01)
check(f"reader that never reads is disconnected once stalled ({gone_at and round(gone_at, 1)}s, limit 6s + checks)",
      gone_at is not None and gone_at < 12, gone_at)
s.close()

print("SSE keepalive comments")
s = conn(8080); s.sendall(b"GET /rooms/quiet/events HTTP/1.1\r\nHost: x\r\n\r\n"); buf = b""; t0 = time.time()
s.settimeout(10)
while b": keepalive" not in buf and time.time() - t0 < 10: buf += s.recv(4096)
check(f"idle subscribed SSE stream gets ': keepalive' ({time.time()-t0:.1f}s)", b": keepalive" in buf and b"X-Accel-Buffering: no" in buf, buf[:200])

for name, port in (("nginx", 8443), ("Caddy", 8444), ("HAProxy + PROXY v2", 8445)):
    print(f"through {name} (TLS on port {port})")
    r = curl("--http2", "-H", "X-Forwarded-For: 6.6.6.6", "-w", "\n%{http_version}", f"https://localhost:{port}/whoami")
    body, ver = r.stdout.rsplit("\n", 1); w = json.loads(body)
    check(f"HTTP/2 + TLS; real client 127.0.0.2, scheme https, spoof ignored", ver == "2" and w["client_ip"] == "127.0.0.2" and w["scheme"] == "https", (ver, w))
    urls = [f"https://localhost:{port}/users/{i}" for i in range(20)]
    r = curl("--http2", "--parallel", "--parallel-max", "20", "-w", "%{http_code} %{http_version}\n", "-o", "/dev/null", *sum([[u, "-o", "/dev/null"] for u in urls[1:]], []), urls[0])
    codes = r.stdout.split()
    check("20 multiplexed HTTP/2 requests", codes.count("200") == 20 and set(codes[1::2]) == {"2"}, r.stdout[:120])
    data = os.urandom(3_000_000); open("/tmp/up.bin", "wb").write(data)
    r = curl("--http2", "--data-binary", "@/tmp/up.bin", f"https://localhost:{port}/count")
    check("3 MB upload streamed through to the server", '"bytes":3000000' in r.stdout, r.stdout[:100])
    t0 = time.time()
    p = subprocess.Popen(["curl", "-skN", "--interface", "127.0.0.2", f"https://localhost:{port}/events?n=3&ms=800"], stdout=subprocess.PIPE)
    first = p.stdout.readline(); t_first = time.time() - t0; rest = p.stdout.read(); p.wait()
    check(f"SSE not buffered: first event after {t_first:.2f}s, all 3 events", t_first < 0.5 and (first + rest).count(b"data: tick") == 3)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with ws_connect(f"wss://localhost:{port}/ws/echo", ssl=ctx, open_timeout=10, ping_interval=None,
                        source_address=OUTSIDE) as ws:
            ws.send("over tls"); a = ws.recv(timeout=5)
            time.sleep(8)                              # quiet longer than nginx's (test) 6s read timeout
            ws.send("still here"); b = ws.recv(timeout=5)
        check("WSS echo, then 8s of silence survived (server pings keep the proxy happy)", a == "over tls" and b == "still here")
    except Exception as e:
        check("WSS echo, then 8s of silence survived (server pings keep the proxy happy)", False, repr(e))
    s = socket.create_connection(("127.0.0.1", port), source_address=OUTSIDE)
    s = ctx.wrap_socket(s, server_hostname="localhost"); s.settimeout(15)
    s.sendall(b"GET /rooms/quietproxy/events HTTP/1.1\r\nHost: localhost\r\n\r\n"); buf = b""; t0 = time.time()
    try:
        while time.time() - t0 < 9:
            d = s.recv(4096)
            if not d: break
            buf += d
    except Exception: pass
    alive = time.time() - t0 >= 8.9
    check(f"idle SSE feed survives 9s through the proxy (keepalives: {buf.count(b': keepalive')})", alive and buf.count(b": keepalive") >= 2, (time.time()-t0, buf[-120:]))

print("upstream keep-alive pool (proxies idle 4s < server keep-alive 6s)")
errors = 0
for rnd in range(3):
    for port in (8443, 8444):
        r = curl("-o", "/dev/null", "-w", "%{http_code}", f"https://localhost:{port}/")
        if r.stdout != "200": errors += 1
    time.sleep(5)
check("requests after 5s pauses (pooled connections expire at the proxy first): no errors", errors == 0, errors)
print(f"\n{passed} passed, {failed} failed")
