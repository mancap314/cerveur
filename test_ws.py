import socket, sys, os, time, struct, threading, re, base64, hashlib
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed
PORT = int(sys.argv[1]); BASE = f"ws://localhost:{PORT}"
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS {name}")
    else: failed += 1; print(f"  FAIL {name}  {detail}")

# ---------- raw WebSocket helpers ----------
def frame(op, payload=b"", fin=True, mask=True, rsv=0):
    b0 = (0x80 if fin else 0) | rsv | op
    n = len(payload)
    hdr = bytes([b0]) + (bytes([(0x80 if mask else 0) | n]) if n < 126 else
                         bytes([(0x80 if mask else 0) | 126]) + struct.pack(">H", n) if n < 65536 else
                         bytes([(0x80 if mask else 0) | 127]) + struct.pack(">Q", n))
    if not mask: return hdr + payload
    key = os.urandom(4)
    return hdr + key + bytes(b ^ key[i & 3] for i, b in enumerate(payload))
class Raw:
    def __init__(s, path="/ws/echo", extra=b"", key=b"dGhlIHNhbXBsZSBub25jZQ=="):
        s.s = socket.create_connection(("localhost", PORT)); s.s.settimeout(5); s.buf = b""
        s.s.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n" + extra + b"\r\n")
        while b"\r\n\r\n" not in s.buf: s.buf += s.s.recv(4096)
        s.head, s.buf = s.buf.split(b"\r\n\r\n", 1)
    def need(s, n):
        while len(s.buf) < n:
            d = s.s.recv(1 << 20)
            if not d: raise EOFError
            s.buf += d
    def read(s):
        s.need(2); op = s.buf[0] & 0xF; n = s.buf[1] & 0x7F; off = 2
        if n == 126: s.need(4); n = struct.unpack(">H", s.buf[2:4])[0]; off = 4
        elif n == 127: s.need(10); n = struct.unpack(">Q", s.buf[2:10])[0]; off = 10
        s.need(off + n); p = s.buf[off:off+n]; s.buf = s.buf[off+n:]
        return op, p
    def close_code(s):
        try:
            while True:
                op, p = s.read()
                if op == 8: return struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 1005
        except Exception as e: return f"no close frame ({e!r})"
    def eof(s):
        try:
            s.s.settimeout(3)
            while True:
                if not s.s.recv(4096): return True
        except Exception: return False

print("handshake")
r = Raw()
check("101 with RFC 6455 example accept key", r.head.startswith(b"HTTP/1.1 101") and b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in r.head, r.head)
s = socket.create_connection(("localhost", PORT)); s.sendall(b"GET /ws/echo HTTP/1.1\r\nHost: x\r\n\r\n"); h = s.recv(4096)
check("plain GET on a WebSocket route -> 426 + Upgrade header", h.startswith(b"HTTP/1.1 426") and b"Upgrade: websocket" in h, h[:80])
s = socket.create_connection(("localhost", PORT))
s.sendall(b"GET /ws/echo HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n")
h = s.recv(4096); check("unsupported version -> 426 + Sec-WebSocket-Version: 13", h.startswith(b"HTTP/1.1 426") and b"Sec-WebSocket-Version: 13" in h, h[:120])

print("messaging (websockets client library)")
with connect(f"{BASE}/ws/echo", max_size=None) as ws:
    ws.send("hello"); check("text echo", ws.recv() == "hello")
    ws.send("héllo ✓ 日本"); check("UTF-8 text echo", ws.recv() == "héllo ✓ 日本")
    data = os.urandom(500_000); ws.send(data); check("500 KB binary echo (larger than the output buffer)", ws.recv() == data)
    data = os.urandom(1 << 20); ws.send(data); check("1 MiB binary echo (the limit)", ws.recv() == data)
    for i in range(1000): ws.send(f"m{i}")
    got = [ws.recv() for _ in range(1000)]; check("1000 messages, in order", got == [f"m{i}" for i in range(1000)])
    pong = ws.ping(b"are you there"); check("ping -> pong", pong.wait(3))
    ws.close(4000, "custom"); check("client close 4000 echoed", ws.close_code == 4000, ws.close_code)
with connect(f"{BASE}/ws/echo", max_size=None) as ws:
    ws.send(os.urandom((1 << 20) + 1))
    try: ws.recv(); code = None
    except ConnectionClosed as e: code = e.rcvd.code if e.rcvd else None
    check("message over 1 MiB -> close 1009", code == 1009, code)

print("protocol violations (raw frames)")
def violation(name, frames, expect):
    r = Raw(); r.s.sendall(b"".join(frames)); code = r.close_code(); check(f"{name} -> {expect}", code == expect, code)
violation("unmasked client frame", [frame(1, b"hi", mask=False)], 1002)
violation("RSV bit without extension", [frame(1, b"hi", rsv=0x40)], 1002)
violation("continuation without a start", [frame(0, b"x")], 1002)
violation("new message inside a fragmented one", [frame(1, b"a", fin=False), frame(1, b"b")], 1002)
violation("control frame over 125 bytes", [frame(9, b"x" * 126)], 1002)
violation("fragmented control frame", [frame(9, b"x", fin=False)], 1002)
violation("unknown opcode", [frame(3, b"x")], 1002)
violation("invalid UTF-8 in text", [frame(1, b"\xff\xfe")], 1007)
violation("UTF-8 surrogate in text", [frame(1, b"\xed\xa0\x80")], 1007)
violation("close with 1-byte payload", [frame(8, b"\x03")], 1002)
violation("close with reserved code 1005", [frame(8, struct.pack(">H", 1005))], 1002)
violation("close with code 999", [frame(8, struct.pack(">H", 999))], 1002)
violation("fragmented message over 1 MiB", [frame(2, b"x" * 600_000, fin=False), frame(0, b"x" * 600_000)], 1009)
r = Raw(); r.s.sendall(frame(1, "é".encode()[:1], fin=False) + frame(9, b"mid") + frame(0, "é".encode()[1:] + b"!"))
a, b = r.read(), r.read()
check("fragments + interleaved ping: pong first, then reassembled text (UTF-8 split across frames)", a == (10, b"mid") and b == (1, "é!".encode()), (a, b))
r = Raw(); r.s.sendall(frame(1, b"")); check("empty text message", r.read() == (1, b""))
r = Raw(); r.s.sendall(frame(8, struct.pack(">H", 1000) + b"done"))
check("close handshake: code echoed, then TCP closed", r.close_code() == 1000 and r.eof())

print("timers")
with connect(f"{BASE}/ws/clock") as ws:
    t0 = time.time(); m1 = ws.recv(); t1 = time.time() - t0
    ws.send("hi"); m2 = ws.recv()
    m3 = ws.recv(); t3 = time.time() - t0
    check(f"clock: tick every second ({t1:.2f}s, {t3:.2f}s)", m1 == "tick 1" and 0.9 < t1 < 1.3 and m3 == "tick 2" and 1.9 < t3 < 2.3, (m1, m3))
    check("clock: answers messages while waiting on its timer", m2 == "you said: hi", m2)
    ws.send("stop")
    try: ws.recv(); code = None
    except ConnectionClosed as e: code = (e.rcvd.code, e.rcvd.reason) if e.rcvd else None
    check("clock: 'stop' -> close 1000 'bye'", code == (1000, "bye"), code)

def sse(path):
    s = socket.create_connection(("localhost", PORT)); s.settimeout(30)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()); buf = b""; t0 = time.time()
    while not buf.endswith(b"0\r\n\r\n"):
        d = s.recv(65536)
        if not d: break
        buf += d
    return buf, time.time() - t0
body, dt = sse("/events?n=3&ms=300")
check(f"SSE: 3 events 300 ms apart ({dt:.2f}s)", body.count(b"data: tick") == 3 and b"text/event-stream" in body and 0.55 < dt < 0.9)
res = []
def one(): res.append(sse("/events?n=3&ms=500"))
ts = [threading.Thread(target=one) for _ in range(200)]; t0 = time.time(); [t.start() for t in ts]; [t.join() for t in ts]
check(f"200 concurrent sleeping handlers finish together ({time.time()-t0:.2f}s)", all(b.count(b"data: tick") == 3 for b, _ in res) and time.time() - t0 < 2.5)
def active():
    s = socket.create_connection(("localhost", PORT)); s.sendall(b"GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    d = b""
    while True:
        x = s.recv(4096)
        if not x: break
        d += x
    return int(re.search(rb"active_connections=(\d+)", d).group(1)) - 1
base = active()
ss = []
for _ in range(20):
    s = socket.create_connection(("localhost", PORT)); s.sendall(b"GET /events?n=100&ms=5000 HTTP/1.1\r\nHost: x\r\n\r\n"); ss.append(s)
time.sleep(0.5); during = active()
for s in ss: s.close()
time.sleep(0.5); after = active()
check(f"clients leaving mid-sleep are noticed at once ({base} -> {during} -> {after})", during == base + 20 and after == base)
print("idle timeouts (slow: ~12 s)")
with connect(f"{BASE}/ws/echo") as ws:
    lived = []
    def sse_long(): lived.append(sse("/events?n=2&ms=11000"))
    t = threading.Thread(target=sse_long); t.start()
    time.sleep(12); ws.send("still here?"); ok = ws.recv() == "still here?"; t.join()
    check("WebSocket idle 12 s (> 10 s HTTP timeout) stays open", ok)
    check(f"handler sleeping 11 s isn't killed by the 10 s idle timeout ({lived[0][1]:.1f}s)", lived[0][0].count(b"data: tick") == 2)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
