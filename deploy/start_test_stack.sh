#!/bin/bash
# Start 3 test servers and nginx/Caddy/HAProxy using the shipped configs, with
# test ports, the self-signed cert, and shortened timeouts substituted in.
set -e
D=$(cd "$(dirname "$0")" && pwd); S=$(dirname "$D"); T=/tmp/stack; mkdir -p $T
if [ ! -f $D/test.crt ]; then          # self-signed certificate for local testing only
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout $D/test.key -out $D/test.crt 2>/dev/null
fi
pkill -9 -x server_t 2>/dev/null || true; pkill -9 -x nginx 2>/dev/null || true
pkill -9 -x caddy 2>/dev/null || true; pkill -9 -x haproxy 2>/dev/null || true; sleep 0.3
cd $S
setsid ./server_t --bind=127.0.0.1 --trust-proxy=127.0.0.1,10.0.0.0/8 --keepalive=6000 8080 2 > $T/a.log 2>&1 < /dev/null &
setsid ./server_t --bind=127.0.0.1 --proxy-protocol 8081 2 > $T/b.log 2>&1 < /dev/null &
setsid ./server_t 8082 1 > $T/c.log 2>&1 < /dev/null &
# nginx: port 8443, test cert, upstream idle 4s (< server's 6s), and a short
# proxy_read_timeout to prove that pings/keepalives beat it.
sed -e "s|listen 443 ssl http2;|listen 8443 ssl http2;|" \
    -e "s|/etc/ssl/certs/example.com.crt|$D/test.crt|; s|/etc/ssl/private/example.com.key|$D/test.key|" \
    -e "s|keepalive_timeout 60s;|keepalive_timeout 4s;|" \
    -e "s|proxy_request_buffering off;|proxy_request_buffering off; proxy_read_timeout 6s;|" \
    $D/nginx.conf > $T/nginx.conf
nginx -c $T/nginx.conf -g "pid $T/nginx.pid; error_log $T/nginx_err.log;"
# Caddy: localhost:8444 with the test cert, upstream idle 4s.
{ echo "{"; echo "  auto_https disable_redirects"; echo "  admin off"; echo "}"
  sed -e "s|^example.com {|localhost:8444 {\n    tls $D/test.crt $D/test.key|" \
      -e "s|keepalive 60s |keepalive 4s |" $D/Caddyfile; } > $T/Caddyfile
setsid caddy run --config $T/Caddyfile --adapter caddyfile > $T/caddy.log 2>&1 < /dev/null &
# HAProxy: port 8445, test cert, backend = server B (PROXY protocol).
cat $D/test.crt $D/test.key > $T/test.pem
sed -e "s|bind :443 ssl crt /etc/haproxy/certs/example.com.pem|bind :8445 ssl crt $T/test.pem|" \
    -e "s|server app1 127.0.0.1:8080|server app1 127.0.0.1:8081|" -e "s|maxconn 20000|maxconn 4000|" $D/haproxy.cfg > $T/haproxy.cfg
haproxy -D -f $T/haproxy.cfg -p $T/haproxy.pid
sleep 1.5
for p in 8080 8081 8082 8443 8444 8445; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo "port $p up" || echo "port $p DOWN"; done
