/*
 * src/demo.c - the demo application's routes (left out of library builds).
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
#ifndef SERVER_NO_MAIN                 /* the demo routes: left out of the library build */
/* ======================================================================== */
/* Demo application                                                         */
/* ======================================================================== */

/* Minimal JSON string escaping for echoing user input back. */
static void json_escape(http_str s, char* out, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; i < s.len && j + 7 < cap; ++i) {
        unsigned char ch = (unsigned char)s.ptr[i];
        if (ch == '"' || ch == '\\') { out[j++] = '\\'; out[j++] = (char)ch; }
        else if (ch < 0x20) j += (size_t)snprintf(out + j, cap - j, "\\u%04x", ch);
        else out[j++] = (char)ch;
    }
    out[j] = '\0';
}

#define APP_FNV_OFFSET 0xcbf29ce484222325ULL
#define APP_FNV_PRIME  0x100000001b3ULL
static uint64_t fnv1a(uint64_t h, const char* p, size_t n) {
    for (size_t i = 0; i < n; ++i) h = (h ^ (unsigned char)p[i]) * APP_FNV_PRIME;
    return h;
}

/* GET / */
static void h_hello(http_ctx* x) {
    http_respond(x, 200, "text/plain", "Hello from STC coroutines!\n", 27);
}

/* GET /users/:id?verbose=1 - path parameter + query string -> JSON */
static void h_user(http_ctx* x) {
    char id[256], verbose[8] = "";
    json_escape(http_param(x, "id"), id, sizeof id);
    http_query(x, "verbose", verbose, sizeof verbose);
    http_str ua = http_header_get(x, "user-agent");
    char agent[256] = "";
    if (ua.ptr) json_escape(ua, agent, sizeof agent);
    if (strcmp(verbose, "1") == 0) {
        http_str m = http_method(x), p = http_path(x);
        char path[512];
        json_escape(p, path, sizeof path);
        http_respondf(x, 200, "application/json",
                      "{\"id\":\"%s\",\"method\":\"%.*s\",\"path\":\"%s\",\"user_agent\":\"%s\",\"reactor\":%d}\n",
                      id, (int)m.len, m.ptr, path, agent, x->c->r->id);
    }
else
        http_respondf(x, 200, "application/json", "{\"id\":\"%s\"}\n", id);
}

/* GET /static/<anything> - trailing wildcard parameter */
static void h_static(http_ctx* x) {
    http_str p = http_param(x, "path");
    http_respondf(x, 200, "text/plain", "you asked for static file '%.*s'\n", (int)p.len, p.ptr);
}

/* POST /upload - buffered body (limit 1 MiB): size and checksum */
static void h_upload(http_ctx* x) {
    http_str b = http_body(x);
    http_respondf(x, 200, "application/json", "{\"bytes\":%zu,\"fnv1a\":\"%016llx\"}\n",
                  b.len, (unsigned long long)fnv1a(APP_FNV_OFFSET, b.ptr, b.len));
}

/* POST /count - streaming consumer: same result as /upload, but for bodies of
   any size in constant memory. */
struct count_task { HTTP_TASK; uint64_t bytes, hash; };
static int s_count(void* p) {
    struct count_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        t->hash = APP_FNV_OFFSET;
        for (;;) {
            cco_await(http_body_ready(x));
            if (http_body_done(x)) break;
            http_str s = http_body_take(x);
            t->bytes += s.len;
            t->hash = fnv1a(t->hash, s.ptr, s.len);
        }
        http_respondf(x, 200, "application/json", "{\"bytes\":%llu,\"fnv1a\":\"%016llx\"}\n",
                      (unsigned long long)t->bytes, (unsigned long long)t->hash);
    }
    return cco_DONE;
}

/* GET /stream?n=N - streaming generator: N lines, chunked, paced by the client. */
struct numbers_task { HTTP_TASK; long i, n; };
static int s_numbers(void* p) {
    struct numbers_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        char buf[32];
        t->n = http_query(x, "n", buf, sizeof buf) ? atol(buf) : 10;
        http_start(x, 200, "text/plain");
        for (t->i = 1; t->i <= t->n; ++t->i)
            cco_await(http_sendf(x, "line %ld\n", t->i));
        http_end(x);
    }
    return cco_DONE;
}

/* POST /echo - full-duplex streaming: each body chunk is sent straight back.
   Memory use is constant, and a client that reads slowly stalls the upload. */
struct echo_task { HTTP_TASK; http_str chunk; };
static int s_echo(void* p) {
    struct echo_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        http_str ct = http_header_get(x, "content-type");
        char ctype[128] = "application/octet-stream";
        if (ct.ptr && ct.len < sizeof ctype) snprintf(ctype, sizeof ctype, "%.*s", (int)ct.len, ct.ptr);
        http_start(x, 200, ctype);
        for (;;) {
            cco_await(http_body_ready(x));
            if (http_body_done(x)) break;
            t->chunk = http_body_take(x);
            cco_await(http_send(x, t->chunk.ptr, t->chunk.len));
        }
        http_end(x);
    }
    return cco_DONE;
}

/* GET /events?n=5&ms=1000 - server-sent events paced by a handler timer. */
struct events_task { HTTP_TASK; http_timer tick; long i, n, ms; };
static int s_events(void* p) {
    struct events_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        char buf[32];
        t->n = http_query(x, "n", buf, sizeof buf) ? atol(buf) : 5;
        t->ms = http_query(x, "ms", buf, sizeof buf) ? atol(buf) : 1000;
        http_set_header(x, "Cache-Control", "no-cache");
        http_start(x, 200, "text/event-stream");
        for (t->i = 1; t->i <= t->n; ++t->i) {
            cco_await(http_sendf(x, "id: %ld\ndata: tick %ld\n\n", t->i, t->i));
            if (t->i < t->n)
                http_sleep(x, &t->tick, t->ms);
        }
        http_end(x);
    }
    return cco_DONE;
}

/* WebSocket /ws/echo - every message is sent back as-is (text or binary). */
struct wsecho_task { HTTP_TASK; ws_message m; };
static int ws_echo(void* p) {
    struct wsecho_task* t = p;
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

/* WebSocket /ws/clock - pushes a tick every second while also answering
   messages: waits on a message OR a timer at the same time. "stop" closes. */
struct clock_task { HTTP_TASK; http_timer tick; long n; ws_message m; };
static int ws_clock(void* p) {
    struct clock_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        http_timer_start(x, &t->tick, 1000);
        for (;;) {
            cco_await(ws_recv_ready(x) || http_timer_done(x, &t->tick));
            if (ws_closed(x)) break;
            if (ws_has_message(x)) {
                t->m = ws_recv(x);
                if (t->m.len == 4 && memcmp(t->m.data, "stop", 4) == 0) {
                    ws_close(x, 1000, "bye");
                    break;
                }
                cco_await(ws_sendf(x, "you said: %.*s", (int)t->m.len, t->m.data));
            }
            if (http_timer_expired(x, &t->tick)) {
                cco_await(ws_sendf(x, "tick %ld", ++t->n));
                http_timer_start(x, &t->tick, 1000);
            }
        }
    }
    return cco_DONE;
}

/* ---- Chat rooms: pub/sub between connections on any thread ---- */

static void room_topic(http_ctx* x, char* buf, size_t cap) {
    http_str room = http_param(x, "room");
    snprintf(buf, cap, "room:%.*s", (int)room.len, room.ptr);
}

/* WebSocket /ws/chat/:room - every message is published to the room, and
   everything published to the room is forwarded to this client. Waits for
   its own client and for room traffic at the same time. */
struct chat_task { HTTP_TASK; char topic[80]; ws_message m; ps_message pm; unsigned lost; };
static int ws_chat(void* p) {
    struct chat_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        room_topic(x, t->topic, sizeof t->topic);
        if (!ps_subscribe(x, t->topic)) { ws_close(x, 1011, "subscribe failed"); cco_return; }
        ps_publish(t->topic, WS_TEXT, "* someone joined", 16);
        for (;;) {
            cco_await(ws_recv_ready(x) || ps_ready(x));
            if (ws_closed(x)) break;
            if (ws_has_message(x)) {
                t->m = ws_recv(x);
                ps_publish(t->topic, t->m.opcode, t->m.data, t->m.len);  /* to everyone, us included */
            }
            while (ps_ready(x)) {
                t->pm = ps_recv(x);
                cco_await(ws_send(x, t->pm.opcode, t->pm.data, t->pm.len));
            }
            t->lost = ps_lagged(x);             /* in the task: it's used across the await */
            if (t->lost) cco_await(ws_sendf(x, "* %u messages skipped (you fell behind)", t->lost));
        }
        cco_finalize:
        if (t->topic[0]) ps_publish(t->topic, WS_TEXT, "* someone left", 14);
    }
    return cco_DONE;
}

/* GET /rooms/:room/events - the same room as server-sent events. */
struct feed_task { HTTP_TASK; char topic[80]; ps_message pm; };
static int s_room_feed(void* p) {
    struct feed_task* t = p;
    http_ctx* x = t->x;
    cco_async (t) {
        room_topic(x, t->topic, sizeof t->topic);
        if (!ps_subscribe(x, t->topic)) { http_respond(x, 503, "text/plain", "busy\n", 5); cco_return; }
        http_set_header(x, "Cache-Control", "no-cache");
        http_start(x, 200, "text/event-stream");
        cco_await(http_sendf(x, ": subscribed to %s\n\n", t->topic));
        for (;;) {                              /* ends when the client disconnects */
            cco_await(ps_ready(x));
            t->pm = ps_recv(x);
            cco_await(http_sendf(x, "data: %.*s\n\n", (int)(t->pm.len > 900 ? 900 : t->pm.len), t->pm.data));
        }
    }
    return cco_DONE;
}

/* POST /rooms/:room - publish the request body to the room from plain HTTP. */
static void h_room_post(http_ctx* x) {
    char topic[80];
    room_topic(x, topic, sizeof topic);
    http_str b = http_body(x);
    int n = ps_publish(topic, WS_TEXT, b.ptr, b.len);
    http_respondf(x, 200, "application/json", "{\"delivered\":%d}\n", n);
}

/* GET /chat - browser chat page (open it in two tabs). */
static void h_chat_page(http_ctx* x) {
    static const char page[] =
        "<!doctype html><meta charset=utf-8><title>Chat</title>"
        "<body style='font-family:system-ui;max-width:40em;margin:2em auto'>"
        "<h3>Room <input id=room value=lobby size=10> <button id=join>Join</button></h3>"
        "<pre id=log style='height:20em;overflow:auto;background:#f4f4f4;padding:.5em'></pre>"
        "<input id=msg size=40 placeholder='say something'> <button id=send>Send</button>"
        "<p style='color:#666'>Also try: <code>curl -d hello localhost:PORT/rooms/lobby</code></p><script>"
        "const $=id=>document.getElementById(id),log=t=>{$('log').textContent+=t+'\\n';$('log').scrollTop=1e9};let ws;"
        "function join(){if(ws)ws.close();$('log').textContent='';"
        "ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/chat/'+encodeURIComponent($('room').value));"
        "ws.onopen=()=>log('[joined '+$('room').value+']');ws.onmessage=e=>log(e.data);ws.onclose=e=>log('[closed '+e.code+']');}"
        "$('join').onclick=join;$('send').onclick=()=>{ws.send($('msg').value);$('msg').value='';};"
        "$('msg').onkeydown=e=>{if(e.key==='Enter')$('send').click()};join();"
        "</script>";
    http_respond(x, 200, "text/html; charset=utf-8", page, sizeof page - 1);
}

/* GET /ws-test - a small browser page for trying the WebSocket endpoints. */
static void h_ws_test(http_ctx* x) {
    static const char page[] =
        "<!doctype html><meta charset=utf-8><title>WebSocket test</title>"
        "<body style='font-family:system-ui;max-width:40em;margin:2em auto'>"
        "<h3>/ws/clock</h3><p>Ticks every second. Type a message, or <b>stop</b> to close.</p>"
        "<input id=msg size=30> <button id=send>Send</button><pre id=log></pre><script>"
        "const log=t=>document.getElementById('log').textContent+=t+'\\n';"
        "const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/clock');"
        "ws.onopen=()=>log('connected');ws.onmessage=e=>log('< '+e.data);"
        "ws.onclose=e=>log('closed '+e.code+' '+e.reason);"
        "document.getElementById('send').onclick=()=>{const m=document.getElementById('msg');ws.send(m.value);log('> '+m.value);m.value='';};"
        "</script>";
    http_respond(x, 200, "text/html; charset=utf-8", page, sizeof page - 1);
}

/* GET /whoami - what the server believes about this request (useful behind a proxy). */
static void h_whoami(http_ctx* x) {
    char peer[INET6_ADDRSTRLEN], host[256] = "";
    ip_to_str(&x->c->peer, peer, sizeof peer);
    http_str h = http_header_get(x, "host");
    if (h.ptr) json_escape(h, host, sizeof host);
    http_respondf(x, 200, "application/json",
        "{\"client_ip\":\"%s\",\"scheme\":\"%s\",\"peer\":\"%s\",\"peer_trusted\":%s,\"host\":\"%s\",\"http\":\"%d.%d\"}\n",
        http_client_ip(x), http_scheme(x), peer, ip_trusted(&x->c->peer) ? "true" : "false",
        host, x->version_major, x->version_minor);
}

/* GET /stats */
static void h_stats(http_ctx* x) {
    char buf[4096];
    int n = format_stats(buf, sizeof buf, x->c->r);
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;   /* truncated */
    http_respond(x, 200, "text/plain", buf, (size_t)n);
}

/* GET /work - burns WORK_US of CPU to simulate an expensive request. */
static void h_work(http_ctx* x) {
    int64_t end = now_ns() + WORK_US * 1000;
    unsigned long v = 0;
    while (now_ns() < end) v = v * 6364136223846793005UL + 1442695040888963407UL;
    http_respondf(x, 200, "text/plain", "worked %dus on reactor%d (%lx)\n", WORK_US, x->c->r->id, v & 0xff);
}

static const http_route app_routes[] = {
    {"GET",  "/",             .handle = h_hello},
    {"GET",  "/users/:id",    .handle = h_user},
    {"GET",  "/static/*path", .handle = h_static},
    {"POST", "/upload",       .handle = h_upload, .body_limit = 1u << 20},
    {"POST", "/count",        .stream = s_count,   .task_size = sizeof(struct count_task)},
    {"POST", "/echo",         .stream = s_echo,    .task_size = sizeof(struct echo_task)},
    {"GET",  "/stream",       .stream = s_numbers, .task_size = sizeof(struct numbers_task)},
    {"GET",  "/events",       .stream = s_events,  .task_size = sizeof(struct events_task)},
    {"GET",  "/ws/echo",      .websocket = ws_echo,  .task_size = sizeof(struct wsecho_task)},
    {"GET",  "/ws/clock",     .websocket = ws_clock, .task_size = sizeof(struct clock_task)},
    {"GET",  "/ws-test",      .handle = h_ws_test},
    {"GET",  "/ws/chat/:room",       .websocket = ws_chat, .task_size = sizeof(struct chat_task)},
    {"GET",  "/rooms/:room/events",  .stream = s_room_feed, .task_size = sizeof(struct feed_task)},
    {"POST", "/rooms/:room",         .handle = h_room_post, .body_limit = 64 * 1024},
    {"GET",  "/chat",                .handle = h_chat_page},
    {"GET",  "/whoami",       .handle = h_whoami},
    {"GET",  "/stats",        .handle = h_stats},
    {"GET",  "/work",         .handle = h_work},
    {0},
};
#endif /* SERVER_NO_MAIN */
