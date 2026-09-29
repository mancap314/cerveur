#!/bin/bash
# Run the HTTP, WebSocket and pub/sub suites against a server binary:
#   deploy/run_tests.sh ./server [port]          (Windows: ./server.exe)
# Starts it on [::]:port with 2 reactors, runs the suites, then stops it.
# Fails if a suite fails, the server dies, a sanitizer reports anything, or
# (Linux) it doesn't shut down cleanly on SIGTERM. Needs Python 3 with the
# websockets package ($PYTHON, default python3).
set -u
cd "$(dirname "$0")/.." || exit 1
SERVER=$1
PORT=${2:-18080}
PY=${PYTHON:-python3}
LOG=server-test.log

"$SERVER" --bind=:: "$PORT" 2 > "$LOG" 2>&1 &
PID=$!
for _ in $(seq 100); do
    (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break
    sleep 0.1
done

status=0
for t in test_http.py test_ws.py test_ps.py; do
    echo "=== $t"
    "$PY" "$t" "$PORT" || status=1
done

if ! kill -0 "$PID" 2>/dev/null; then
    echo "!!! the server died during the tests"
    status=1
else
    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)               # no SIGTERM for native Windows programs
        kill "$PID"; wait "$PID" 2>/dev/null ;;
    *)
        kill -TERM "$PID"
        if ! wait "$PID"; then echo "!!! the server didn't shut down cleanly"; status=1; fi ;;
    esac
fi
if grep -qE 'Sanitizer|runtime error:' "$LOG"; then
    echo "!!! sanitizer report:"
    status=1
fi
echo "=== server output"
cat "$LOG"
rm -f "$LOG"
exit $status
