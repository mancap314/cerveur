import socket, sys, time, os, hashlib, random, threading, subprocess
PORT = int(sys.argv[1])
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS {name}")
    else: failed += 1; print(f"  FAIL {name}  {detail}")

def fnv(b):
    h = 0xcbf29ce484222325
    for x in b: h = ((h ^ x) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

class Conn:
    def __init__(s): s.s = socket.create_connection(("localhost", PORT)); s.s.settimeout(10); s.buf = b""
    def send(s, b): s.s.sendall(b)
    def _more(s):
        d = s.s.recv(1 << 20)
        if not d: raise EOFError
        s.buf += d
    def response(s, head_request=False):
        while b"\r\n\r\n" not in s.buf: s._more()
        head, s.buf = s.buf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n"); status = int(lines[0].split()[1])
        h = {}
        for l in lines[1:]:
            k, v = l.split(":", 1); h[k.strip().lower()] = v.strip()
        body = b""
        if head_request or status in (100, 204, 304): return status, h, body
        if "content-length" in h:
            n = int(h["content-length"])
            while len(s.buf) < n: s._more()
            body, s.buf = s.buf[:n], s.buf[n:]
        elif h.get("transfer-encoding") == "chunked":
            while True:
                while b"\r\n" not in s.buf: s._more()
                line, s.buf = s.buf.split(b"\r\n", 1); n = int(line, 16)
                while len(s.buf) < n + 2: s._more()
                body += s.buf[:n]; assert s.buf[n:n+2] == b"\r\n"; s.buf = s.buf[n+2:]
                if n == 0: break
        else:  # close-delimited
            try:
                while True: s._more()
            except EOFError: pass
            body, s.buf = s.buf, b""
        return status, h, body
    def closed(s):
        try:
            s.s.settimeout(3)
            return s.s.recv(1) == b""
        except Exception: return False

def req(method, path, body=None, headers="", chunked=False):
    c = Conn(); r = f"{method} {path} HTTP/1.1\r\nHost: x\r\n{headers}"
    if body is not None and not chunked: r += f"Content-Length: {len(body)}\r\n"
    if chunked: r += "Transfer-Encoding: chunked\r\n"
    c.send(r.encode() + b"\r\n")
    if body is not None:
        if chunked:
            for i in range(0, len(body), 7001): part = body[i:i+7001]; c.send(b"%x\r\n" % len(part) + part + b"\r\n")
            c.send(b"0\r\n\r\n")
        else: c.send(body)
    return c, c.response(method == "HEAD")

print("routing and parameters")
_, (st, h, b) = req("GET", "/"); check("GET / -> 200 hello", st == 200 and b == b"Hello from STC coroutines!\n")
check("Date header present", "date" in h and h["date"].endswith("GMT"))
_, (st, h, b) = req("HEAD", "/"); check("HEAD / -> 200, Content-Length 27, no body", st == 200 and h.get("content-length") == "27" and b == b"")
_, (st, h, b) = req("GET", "/users/42?verbose=1", headers="User-Agent: tester\r\n")
check("path param + query + header -> JSON", st == 200 and b'"id":"42"' in b and b'"user_agent":"tester"' in b and b'"method":"GET"' in b, b)
_, (st, h, b) = req("GET", "/users/caf%C3%A9%20%22x%22"); check("percent-decoded + JSON-escaped param", b == '{"id":"café \\"x\\""}\n'.encode(), b)
_, (st, h, b) = req("GET", "/users/"); check("empty :id -> 404", st == 404)
_, (st, h, b) = req("GET", "/static/css/site.css"); check("wildcard param", st == 200 and b"'css/site.css'" in b, b)
_, (st, h, b) = req("GET", "/nope"); check("unknown path -> 404", st == 404)
_, (st, h, b) = req("DELETE", "/users/1"); check("wrong method -> 405 + Allow: GET", st == 405 and h.get("allow") == "GET", h)

print("buffered bodies")
data = os.urandom(300_000)
_, (st, h, b) = req("POST", "/upload", data); check("Content-Length upload 300 KB hash", st == 200 and fnv(data).encode() in b, b)
_, (st, h, b) = req("POST", "/upload", data, chunked=True); check("chunked upload 300 KB hash", st == 200 and fnv(data).encode() in b, b)
c, (st, h, b) = req("POST", "/upload", body=None, headers="Content-Length: 5000000\r\n")
check("oversized Content-Length -> 413 before sending body", st == 413 and h.get("connection") == "close")
def oversized_chunked():
    c = Conn(); c.send(b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
    def pump():
        try:
            for _ in range(400): c.s.sendall(b"%x\r\n" % 16000 + os.urandom(16000) + b"\r\n")
        except OSError: pass
    t = threading.Thread(target=pump); t.start()
    try: st = c.response()[0]
    except Exception as e: st = repr(e)
    t.join(); return st
sts = [oversized_chunked() for _ in range(10)]
check("oversized chunked body -> 413 reaches the client (10 tries, lingering close)", sts == [413] * 10, sts)

print("streaming bodies")
data = os.urandom(20_000_000)
_, (st, h, b) = req("POST", "/count", data); check("stream-count 20 MB (Content-Length)", st == 200 and fnv(data).encode() in b and b'"bytes":20000000' in b, b)
_, (st, h, b) = req("POST", "/count", data, chunked=True); check("stream-count 20 MB (chunked)", st == 200 and fnv(data).encode() in b, b)
# full-duplex echo: send and receive concurrently
c = Conn(); echo_in = os.urandom(8_000_000)
c.send(f"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-test\r\nContent-Length: {len(echo_in)}\r\n\r\n".encode())
t = threading.Thread(target=lambda: c.s.sendall(echo_in)); t.start()
st, h, b = c.response(); t.join()
check("echo 8 MB round trip (full duplex, chunked response)", st == 200 and b == echo_in and h.get("transfer-encoding") == "chunked" and h.get("content-type") == "application/x-test")
_, (st, h, b) = req("GET", "/stream?n=100000")
lines = b.split(b"\n")
check("generator /stream?n=100000", st == 200 and lines[0] == b"line 1" and lines[-2] == b"line 100000" and len(lines) == 100001)

print("protocol details")
c = Conn()
c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nPOST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /users/7 HTTP/1.1\r\nHost: x\r\n\r\nGET /stream?n=3 HTTP/1.1\r\nHost: x\r\n\r\n")
r = [c.response() for _ in range(4)]
check("pipelined GET, POST, GET, streamed GET on one connection",
      [x[0] for x in r] == [200]*4 and r[1][2] == f'{{"bytes":5,"fnv1a":"{fnv(b"hello")}"}}\n'.encode() and r[2][2] == b'{"id":"7"}\n' and r[3][2] == b"line 1\nline 2\nline 3\n", r)
c = Conn()
for ch in b"GET /users/dribble HTTP/1.1\r\nHost: x\r\n\r\n": c.send(bytes([ch])); time.sleep(0.002)
st, h, b = c.response(); check("request dribbled 1 byte at a time", b == b'{"id":"dribble"}\n')
c = Conn(); c.send(b"POST /nope HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n" + b"z" * 100000 + b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
st1, _, _ = c.response(); st2, _, b2 = c.response()
check("unread body drained, connection reused", st1 == 404 and st2 == 200 and b2.startswith(b"Hello"))
c = Conn(); c.send(b"POST /count HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\nExpect: 100-continue\r\n\r\n")
st, h, b = c.response(); c.send(b"hello world"); st2, h2, b2 = c.response()
check("Expect: 100-continue -> 100, then final response", st == 100 and st2 == 200 and b'"bytes":11' in b2)
c = Conn(); c.send(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 9999999\r\nExpect: 100-continue\r\n\r\n")
st, h, b = c.response(); check("Expect: 100-continue with oversized body -> 413 without 100", st == 413 and c.closed())
c = Conn(); c.send(b"GET /stream?n=2 HTTP/1.0\r\n\r\n"); st, h, b = c.response()
check("HTTP/1.0 streamed response is close-delimited", st == 200 and "transfer-encoding" not in h and b == b"line 1\nline 2\n")
c = Conn(); c.send(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"); st, h, b = c.response()
c.send(b"GET / HTTP/1.0\r\n\r\n"); st2, h2, _ = c.response()
check("HTTP/1.0 keep-alive honored, then closed", h.get("connection") == "keep-alive" and h2.get("connection") == "close" and c.closed())
c = Conn(); c.send(b"GARBAGE\r\n\r\n"); st, h, b = c.response(); check("malformed request -> 400 + close", st == 400 and c.closed())
c = Conn(); c.send(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 9000 + b"\r\n\r\n"); st, h, b = c.response()
check("oversized headers -> 431", st == 431)
c = Conn(); c.send(b"POST /count HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZZ\r\n")
st, h, b = c.response(); check("malformed chunk framing in streamed body -> 400", st == 400)

print("real client (curl)")
import tempfile
big = os.urandom(30_000_000)
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    f.write(big)
try:
    r = subprocess.run(["curl", "-s", "--data-binary", "@" + f.name, "-H", "Content-Type: application/octet-stream",
                        f"http://127.0.0.1:{PORT}/echo"], capture_output=True, timeout=120)
    check("curl: 30 MB echo byte-identical (curl uses Expect: 100-continue)", r.stdout == big,
          f"got {len(r.stdout)} bytes")
    r = subprocess.run(["curl", "-s", "-T", f.name, "-X", "POST", f"http://127.0.0.1:{PORT}/count"],
                       capture_output=True, timeout=120)
    check("curl: 30 MB chunked upload to streaming consumer", fnv(big).encode() in r.stdout, r.stdout)
finally:
    os.unlink(f.name)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
