// example.cpp - using the server from C++.
// Copyright (c) 2026 Manuel Capel. SPDX-License-Identifier: MIT
//
// Build (Linux; on Windows add -lws2_32, e.g. from Git Bash with MinGW-w64):
//   gcc -c -O2 -pthread -Illhttp/include -DSERVER_NO_MAIN server.c llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c
//   g++ -std=c++17 -O2 -pthread -Illhttp/include example.cpp server.o api.o http.o llhttp.o -o example
// Run:   ./example 8080     then: curl localhost:8080/hello/you
//                                  curl -N 'localhost:8080/count?n=5'
#include "server.h"

#include <string>

// Buffered handler: a plain function, or a lambda without captures.
static void hello(http_ctx* x) {
    http_str name = http_param(x, "name");
    std::string body = "Hello, " + std::string(name.ptr, name.len) + "!\n";
    http_respond(x, 200, "text/plain", body.data(), body.size());
}

// Streaming handler: an STC coroutine. State that must survive a cco_await
// lives in the task struct (it starts with HTTP_TASK), and the body has no
// initialized declarations between cco_async and the awaits (C++ doesn't
// allow jumping over them).
struct count_task { HTTP_TASK; long i, n; http_timer tick; };

static int count(void* p) {
    count_task* t = static_cast<count_task*>(p);
    http_ctx* x = t->x;
    cco_async (t) {
        char buf[32];
        t->n = http_query(x, "n", buf, sizeof buf) ? std::stol(buf) : 3;
        http_start(x, 200, "text/plain");
        for (t->i = 1; t->i <= t->n; ++t->i) {
            cco_await(http_sendf(x, "%ld\n", t->i));
            http_sleep(x, &t->tick, 500);           // one number every half second
        }
        http_end(x);
    }
    return cco_DONE;
}

// WebSocket handler: echo every message back.
struct echo_task { HTTP_TASK; ws_message m; };

static int ws_echo(void* p) {
    echo_task* t = static_cast<echo_task*>(p);
    http_ctx* x = t->x;
    cco_async (t) {
        for (;;) {
            cco_await(ws_recv_ready(x));
            if (ws_closed(x)) break;
            t->m = ws_recv(x);
            cco_await(ws_send(x, t->m.opcode, t->m.data, t->m.len));
        }
    }
    return cco_DONE;
}

static const http_route routes[] = {
    // method, pattern, handle, stream, websocket, task_size, body_limit
    {"GET", "/hello/:name", hello},
    {"GET", "/", [](http_ctx* x) { http_respondf(x, 200, "text/plain", "try /hello/you\n"); }},
    {"GET", "/count", nullptr, count, nullptr, sizeof(count_task)},
    {"GET", "/ws/echo", nullptr, nullptr, ws_echo, sizeof(echo_task)},
    {},
};

int main(int argc, char* argv[]) {
    return http_server_main(argc, argv, routes);
}
