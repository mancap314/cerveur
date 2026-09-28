"""Benchmark the server with oha (https://github.com/hatoo/oha) plus an SSE
latency probe. Server and load generator are pinned to disjoint CPUs so they
don't compete; each scenario runs several times and the median is reported.

    python bench.py                              # ./server(.exe), oha on PATH
    python bench.py --oha path/to/oha --save base.json
    python bench.py --compare base.json          # show the change vs a saved run
    python bench.py --only hello,newconn         # a subset of the scenarios

Each scenario also reports the server's CPU time per request, split into user
and kernel (cpu_user_us, cpu_kern_us), and how busy its CPUs were (cpu_util,
1.0 = saturated, so the server is the bottleneck). A server built with
-DIO_STATS also reports syscalls per request (read from /stats before and
after each run).

Scenarios:
    hello        GET /, 64 keep-alive connections: per-request overhead
    newconn      GET /, 32 connections, a new TCP connection per request: accept path
    stream       GET /stream?n=2000 (~24 KB in 2000 chunks), 16 connections: many sends
    echo         POST 64 KB to /echo, 16 connections: large reads and writes
    sse-gap      20 SSE streams ticking every 10 ms: delivery delay of small writes
                 (Nagle + delayed ACK show up here as gaps far above 10 ms)
"""
import argparse, json, os, shutil, socket, statistics, subprocess, sys, tempfile, threading, time

WIN = sys.platform == "win32"


def set_affinity(p, cpus):
    if WIN:
        import ctypes
        mask = sum(1 << c for c in cpus)
        if not ctypes.windll.kernel32.SetProcessAffinityMask(int(p._handle), mask):
            raise OSError("SetProcessAffinityMask failed")
    else:
        os.sched_setaffinity(p.pid, cpus)


def process_cpu(p):
    """(user, kernel) CPU seconds used so far by process p."""
    if WIN:
        import ctypes
        from ctypes import wintypes
        t = [wintypes.FILETIME() for _ in range(4)]
        if not ctypes.windll.kernel32.GetProcessTimes(int(p._handle), *[ctypes.byref(x) for x in t]):
            raise OSError("GetProcessTimes failed")
        secs = lambda f: ((f.dwHighDateTime << 32) | f.dwLowDateTime) / 1e7
        return secs(t[3]), secs(t[2])
    fields = open(f"/proc/{p.pid}/stat").read().rsplit(")", 1)[1].split()
    tck = os.sysconf("SC_CLK_TCK")
    return int(fields[11]) / tck, int(fields[12]) / tck


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server didn't start on port {port}")


def oha(args, url, cpus, extra=()):
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [args.oha, "-z", f"{args.duration}s", "--no-tui", "--output-format", "json", "-o", out, *extra, url]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    set_affinity(p, cpus)
    _, err = p.communicate(timeout=args.duration + 60)
    if p.returncode != 0:
        raise RuntimeError(f"oha failed: {err.decode(errors='replace')}")
    d = json.load(open(out))
    os.unlink(out)
    s, lat = d["summary"], d["latencyPercentiles"]
    errors = sum(d.get("errorDistribution", {}).values()) - d.get("errorDistribution", {}).get("aborted due to deadline", 0)
    return {"rps": s["requestsPerSec"], "p50_ms": lat["p50"] * 1e3, "p99_ms": lat["p99"] * 1e3,
            "mbps": s["sizePerSec"] / 1e6, "errors": errors,
            "_requests": sum(d.get("statusCodeDistribution", {}).values())}


def sse_gap(port, clients=20, n=100, ms=10):
    """Inter-arrival gaps of SSE events that the server emits every `ms` ms."""
    gaps, lock = [], threading.Lock()

    def one():
        s = socket.create_connection(("127.0.0.1", port))
        s.settimeout(30)
        s.sendall(f"GET /events?n={n}&ms={ms} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        buf, seen, last, mine = b"", 0, None, []
        while True:
            d = s.recv(65536)
            if not d:
                break
            now = time.perf_counter()
            buf += d
            k = buf.count(b"data: tick")
            if k > seen:
                if last is not None:
                    mine.append((now - last) * 1e3)
                mine.extend([0.0] * (k - seen - 1))     # several events in one read
                seen, last = k, now
            if buf.endswith(b"0\r\n\r\n"):
                break
        s.close()
        with lock:
            gaps.extend(mine)

    ts = [threading.Thread(target=one) for _ in range(clients)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    gaps.sort()
    return {"gap_p50_ms": gaps[len(gaps) // 2], "gap_p99_ms": gaps[int(len(gaps) * 0.99)], "gap_max_ms": gaps[-1]}


def server_stats(port):
    """Request count, plus I/O counters for servers built with -DIO_STATS
    (empty for other servers, which have no /stats)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    out = b""
    while d := s.recv(65536):
        out += d
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 200"):
        return {}
    text = body.decode()
    io = {}
    for line in text.splitlines():
        if line.startswith("served_by="):
            io["requests"] = int(line.split("total_requests=")[1].split()[0])
        elif line.startswith("io "):
            io.update((k, int(v)) for k, v in (kv.split("=") for kv in line.split()[1:]))
    return io


def run_measured(args, srv, ncpu, fn):
    """Run one scenario; add server CPU per request (user/kernel, in us), the
    server's CPU utilisation (1.0 = all its cores busy) and, for -DIO_STATS
    builds, syscalls per request."""
    before, cpu0, t0 = server_stats(args.port), process_cpu(srv), time.perf_counter()
    r = fn()
    wall, cpu1, after = time.perf_counter() - t0, process_cpu(srv), server_stats(args.port)
    oha_n = r.pop("_requests", None)
    if "requests" in after:
        n = max(after["requests"] - before["requests"] - 1, 1)     # minus our own /stats request
    else:                                   # another server (no /stats): count what oha saw
        n = max(oha_n or 1, 1)
    r["cpu_user_us"] = (cpu1[0] - cpu0[0]) / n * 1e6
    r["cpu_kern_us"] = (cpu1[1] - cpu0[1]) / n * 1e6
    r["cpu_util"] = (cpu1[0] - cpu0[0] + cpu1[1] - cpu0[1]) / wall / ncpu
    r.update({f"io_{k}": (after[k] - before[k]) / n for k in after if k != "requests"})
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="server.exe" if WIN else "./server")
    ap.add_argument("--oha", default=shutil.which("oha") or "oha")
    ap.add_argument("--server-cpus", default="0,1")
    ap.add_argument("--client-cpus", default="2,3")
    ap.add_argument("--duration", type=int, default=5, help="seconds per oha run")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--port", type=int, default=18200)
    ap.add_argument("--only", help="comma-separated scenario names")
    ap.add_argument("--save", help="write results to this JSON file")
    ap.add_argument("--compare", help="JSON file from an earlier --save")
    args = ap.parse_args()
    scpus = [int(c) for c in args.server_cpus.split(",")]
    ccpus = [int(c) for c in args.client_cpus.split(",")]

    body = tempfile.NamedTemporaryFile(delete=False)
    body.write(os.urandom(65536))
    body.close()
    base = f"http://127.0.0.1:{args.port}"
    scenarios = {
        "hello":   lambda: oha(args, f"{base}/", ccpus, ["-c", "64"]),
        "newconn": lambda: oha(args, f"{base}/", ccpus, ["-c", "32", "--disable-keepalive"]),
        "stream":  lambda: oha(args, f"{base}/stream?n=2000", ccpus, ["-c", "16"]),
        "echo":    lambda: oha(args, f"{base}/echo", ccpus, ["-c", "16", "-m", "POST", "-D", body.name]),
        "sse-gap": lambda: sse_gap(args.port),
    }
    names = args.only.split(",") if args.only else list(scenarios)

    server = os.path.abspath(args.server) if os.path.exists(args.server) else args.server
    srv = subprocess.Popen([server, "--bind=127.0.0.1", str(args.port), str(len(scpus))],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = {}
    try:
        set_affinity(srv, scpus)
        wait_port(args.port)
        print(f"server: {args.server} on CPUs {scpus} ({len(scpus)} reactors), client on CPUs {ccpus}, "
              f"{args.runs} x {args.duration}s runs, median shown")
        for name in names:
            runs = [run_measured(args, srv, len(scpus), scenarios[name]) for _ in range(args.runs)]
            results[name] = {k: statistics.median(r[k] for r in runs) for k in runs[0]}
            if srv.poll() is not None:
                raise RuntimeError("server exited")
    finally:
        srv.kill()
        os.unlink(body.name)

    old = json.load(open(args.compare)) if args.compare else {}

    def fmt(name, k, v):
        s = f"{k}={v:,.0f}" if k == "rps" else f"{k}={v:.2f}" if isinstance(v, float) else f"{k}={v}"
        if name in old and k in old[name] and old[name][k] and k != "errors":
            s += f" ({(v / old[name][k] - 1) * 100:+.0f}%)"
        return s

    for name, r in results.items():
        print(f"  {name:8} " + "  ".join(fmt(name, k, v) for k, v in r.items() if not k.startswith("io_")))
    if any(k.startswith("io_") for r in results.values() for k in r):
        print("syscalls and events per request (-DIO_STATS build):")
        for name, r in results.items():
            print(f"  {name:8} " + "  ".join(fmt(name, k, v)[3:] for k, v in r.items() if k.startswith("io_")))
    if args.save:
        json.dump(results, open(args.save, "w"), indent=2)


if __name__ == "__main__":
    main()
