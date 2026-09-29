#!/bin/bash
# Build ./server_t with shortened timers for test_proxy.py (extra gcc flags, e.g.
# -fsanitize=thread, can be passed as arguments). On Windows (Git Bash/MSYS2 with
# MinGW-w64 gcc) this builds server_t.exe.
cd "$(dirname "$0")/.." || exit 1
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) PLATFORM=(-lws2_32) ;;
  *)                    PLATFORM=() ;;
esac
gcc -std=gnu11 -O2 -Wall -pthread -Illhttp/include \
  -DTIMEOUT_MS=2000 -DWS_PING_MS=3000 -DWS_PONG_MS=2000 -DWS_STALL_MS=6000 -DSSE_KEEPALIVE_MS=3000 \
  "$@" -o server_t server.c llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c "${PLATFORM[@]}"
