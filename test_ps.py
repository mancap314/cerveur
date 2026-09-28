import sys, time, threading, socket, re, json, warnings
warnings.filterwarnings("ignore")
from websockets.sync.client import connect
PORT = int(sys.argv[1]); WS = f"ws://localhost:{PORT}"
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS {name}")
    else: failed += 1; print(f"  FAIL {name}  {str(detail)[:300]}")
def chat(room): return connect(f"{WS}/ws/chat/{room}", max_size=None, max_queue=None, open_timeout=20, close_timeout=5)
def recv_until(ws, pred, timeout=10):
    end = time.time() + timeout; got = []
    while time.time() < end:
        try: m = ws.recv(timeout=max(0.01, end - time.time()))
        except TimeoutError: break
        got.append(m)
        if pred(m): return got
    return got
def post(room, body):
    s = socket.create_connection(("localhost", PORT)); s.settimeout(10)
    s.sendall(f"POST /rooms/{room} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body.encode())
    d = b""
    while True:
        x = s.recv(4096)
        if not x: break
        d += x
    return json.loads(d.split(b"\r\n\r\n", 1)[1])["delivered"]
def drain_joins(ws, n):   # wait until n join notices seen
    seen = 0
    while seen < n:
        if ws.recv(timeout=10) == "* someone joined": seen += 1

print("rooms")
a = chat("lobby"); drain_joins(a, 1)
b = chat("lobby"); drain_joins(b, 1); drain_joins(a, 1)
check("join notice reaches existing members", True)
a.send("hi from a")
ga = recv_until(a, lambda m: m == "hi from a"); gb = recv_until(b, lambda m: m == "hi from a")
check("message reaches every member, sender included", ga[-1:] == ["hi from a"] and gb[-1:] == ["hi from a"], (ga, gb))
other = chat("elsewhere"); drain_joins(other, 1)
a.send("lobby only"); recv_until(b, lambda m: m == "lobby only")
check("rooms are isolated", recv_until(other, lambda m: True, timeout=0.5) == [])
n = post("lobby", "hello over http")
check(f"HTTP POST publishes into the room (delivered={n})", n == 2 and recv_until(a, lambda m: m == "hello over http")[-1:] == ["hello over http"])
s = socket.create_connection(("localhost", PORT)); s.settimeout(10)
s.sendall(b"GET /rooms/lobby/events HTTP/1.1\r\nHost: x\r\n\r\n"); buf = b""
while b"subscribed" not in buf: buf += s.recv(4096)
b.send("to ws and sse")
while b"to ws and sse" not in buf: buf += s.recv(4096)
check("SSE feed of the same room receives WebSocket messages", b"data: to ws and sse" in buf)
s.close(); other.close(); a.close()
got = recv_until(b, lambda m: m == "* someone left")
check("leave notice", got[-1:] == ["* someone left"], got)
b.close(); time.sleep(0.3)
check("subscriptions end with the connection (nobody left to deliver to)", post("lobby", "anyone?") == 0)

print("fan-out across reactors")
N = 200; subs = [chat("fan") for _ in range(N)]
time.sleep(1.0)
def count_subs():
    return post("fan", "__probe__")
check(f"{N} subscribers registered", count_subs() == N)
results = [None] * N
def reader(i):
    ws = subs[i]; seq = []
    try:
        while len(seq) < 100:
            m = ws.recv(timeout=20)
            if m.startswith("msg "): seq.append(int(m[4:]))
    except Exception as e: seq.append(repr(e))
    results[i] = seq
ts = [threading.Thread(target=reader, args=(i,)) for i in range(N)]; [t.start() for t in ts]
t0 = time.time()
for k in range(100): post("fan", f"msg {k}")
[t.join() for t in ts]; dt = time.time() - t0
check(f"100 messages x {N} subscribers: all delivered, in order ({dt:.2f}s)", all(r == list(range(100)) for r in results),
      [r for r in results if r != list(range(100))][:2])
for ws in subs: ws.close()

print("concurrent publishers")
P, K = 10, 100; clients = [chat("multi") for _ in range(P)]; time.sleep(0.5)
recv = [dict() for _ in range(P)]; skipped = [0] * P
def rd(i):
    ws = clients[i]; total = 0
    try:
        while total + skipped[i] < P * K:
            m = ws.recv(timeout=20)
            mm = re.fullmatch(r"c(\d+)-(\d+)", m)
            if mm: recv[i].setdefault(int(mm[1]), []).append(int(mm[2])); total += 1
            elif "skipped" in m: skipped[i] += int(m.split()[1])
    except Exception as e: recv[i]["err"] = repr(e)
def wr(i):
    for k in range(K): clients[i].send(f"c{i}-{k}")
rts = [threading.Thread(target=rd, args=(i,)) for i in range(P)]; wts = [threading.Thread(target=wr, args=(i,)) for i in range(P)]
[t.start() for t in rts]; [t.start() for t in wts]; [t.join() for t in wts]; [t.join() for t in rts]
ok = all(all(r.get(j) == list(range(K)) for j in range(P)) for r in recv)
check(f"{P} publishers x {K} messages burst: everyone gets all {P*K}, each sender's order kept (skipped: {sum(skipped)})", ok and sum(skipped) == 0,
      [r.get("err") for r in recv])
for ws in clients: ws.close()

print("slow subscriber")
import os, struct
class RawWS:                                    # a client that can genuinely stop reading
    def __init__(s, path):
        s.s = socket.create_connection(("localhost", PORT)); s.s.settimeout(30); s.buf = b""
        s.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)   # small, but not crippling
        s.s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
        while b"\r\n\r\n" not in s.buf: s.buf += s.s.recv(4096)
        s.buf = s.buf.split(b"\r\n\r\n", 1)[1]
    def need(s, n):
        while len(s.buf) < n:
            d = s.s.recv(1 << 20)
            if not d: raise EOFError("server closed the connection")
            s.buf += d
    def recv(s):
        while True:
            s.need(2); op = s.buf[0] & 0x0F; n = s.buf[1] & 0x7F; off = 2
            if n == 126: s.need(4); n = struct.unpack(">H", s.buf[2:4])[0]; off = 4
            elif n == 127: s.need(10); n = struct.unpack(">Q", s.buf[2:10])[0]; off = 10
            s.need(off + n); p = s.buf[off:off+n]; s.buf = s.buf[off+n:]
            if op == 9:                            # answer pings, like any real client
                key = os.urandom(4)
                s.s.sendall(bytes([0x8A, 0x80 | len(p)]) + key + bytes(b ^ key[i & 3] for i, b in enumerate(p)))
                continue
            return p.decode(errors="replace")
    def send(s, text):
        p = text.encode(); key = os.urandom(4)
        s.s.sendall(bytes([0x81, 0x80 | len(p)]) + key + bytes(b ^ key[i & 3] for i, b in enumerate(p)))
slow = RawWS("/ws/chat/flood"); fast = chat("flood"); pub = chat("flood"); time.sleep(0.5)
M = 20000; payload = "x" * 1000
fast_seq = []; fast_skip = [0]
def fast_reader():
    try:
        while len(fast_seq) + fast_skip[0] < M:
            m = fast.recv(timeout=30)
            if m.startswith("f "): fast_seq.append(int(m[2:7]))
            elif "skipped" in m: fast_skip[0] += int(m.split()[1])
    except Exception as e: fast_seq.append(repr(e))
def pub_reader():
    n = 0
    try:
        while n < M:
            m = pub.recv(timeout=30)
            if m.startswith("f "): n += 1
            elif "skipped" in m: n += int(m.split()[1])
    except Exception: pass
ft = threading.Thread(target=fast_reader); pt = threading.Thread(target=pub_reader); ft.start(); pt.start()
t0 = time.time()
for k in range(M): pub.send(f"f {k:05d} {payload}")
pub_time = time.time() - t0
ft.join(); pt.join()
increasing = all(isinstance(a, int) and a < b for a, b in zip(fast_seq, fast_seq[1:]))
check(f"20 MB burst ({pub_time:.1f}s): fast reader gets {len(fast_seq)} in order + {fast_skip[0]} reported skipped = {M}",
      increasing and len(fast_seq) + fast_skip[0] == M, fast_seq[-1:])
check("a stalled reader doesn't slow the burst down (publisher never blocks)", pub_time < 15)
# now the stalled client starts reading: messages it got + what it was told it missed = M
got = skipped = 0; seq = []
while got + skipped < M:
    m = slow.recv()
    if m.startswith("f "): got += 1; seq.append(int(m[2:7]))
    elif "skipped" in m: skipped += int(m.split()[1])
ordered = all(a < b for a, b in zip(seq, seq[1:]))
check(f"stalled reader: {got} delivered in order + {skipped} reported skipped = {M}", skipped > 0 and ordered and got + skipped == M)
slow.send("still alive")
while True:
    if slow.recv() == "still alive": break
check("stalled subscriber still works afterwards", True)
fast.close(); pub.close()
print(f"\n{passed} passed, {failed} failed")
