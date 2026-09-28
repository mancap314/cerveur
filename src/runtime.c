/*
 * src/runtime.c - core structures: reactors, connections, requests; deadlines, timer heap.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* Runtime structures                                                       */
/* ======================================================================== */

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static int64_t now_ms(void) { return now_ns() / 1000000; }
static int64_t thread_cpu_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* Intrusive doubly-linked list. */
typedef struct dlink { struct dlink *prev, *next; } dlink;
static void dlink_init(dlink* n) { n->prev = n->next = n; }
static bool dlink_empty(const dlink* l) { return l->next == l; }
static void dlink_remove(dlink* n) {
    n->prev->next = n->next;
    n->next->prev = n->prev;
    dlink_init(n);
}
static void dlink_insert_after(dlink* pos, dlink* n) {
    n->prev = pos;
    n->next = pos->next;
    pos->next->prev = n;
    pos->next = n;
}
static void dlink_push_back(dlink* l, dlink* n) { dlink_insert_after(l->prev, n); }

struct conn;
struct ps_sub;

/* An IPv4 or IPv6 address (IPv4 stored as IPv4-mapped IPv6). */
typedef struct { uint8_t b[16]; } ipaddr;
typedef struct { ipaddr net; int bits; } cidr;

/* Settings from the command line. */
static const char* g_bind = "0.0.0.0";
static int     g_keepalive_ms = DEFAULT_KEEPALIVE_MS;
static bool    g_proxy_protocol;
static cidr    g_trusted[MAX_TRUSTED];
static int     g_ntrusted;

/* I/O counters for benchmarking, compiled in with -DIO_STATS and shown by
   GET /stats: how many syscalls each request costs, and how many were wasted. */
enum {
    IO_RECV, IO_RECV_EMPTY,     /* recv() calls, and those that found nothing
                                   (Windows: WSARecv, and those that had to wait) */
    IO_SEND, IO_SEND_FULL,      /* send() calls, and those that found the socket full
                                   (Windows: WSASend, and those that had to wait) */
    IO_SEND_SHORT,              /* send() calls that took only part of what was offered */
    IO_MOD, IO_MOD_ADD,         /* interest changes, and those adding events */
    IO_WAIT, IO_EVENTS,         /* epoll_wait() calls, and connection events delivered */
    IO_ACCEPT, IO_ACCEPT_EMPTY, /* accept() calls, and those that found nothing */
    IO_NSTATS
};
#ifdef IO_STATS                 /* single writer, so no atomic read-modify-write */
static const char* const io_stat_names[IO_NSTATS] = {
    "recv", "recv_empty", "send", "send_full", "send_short", "mod", "mod_add",
    "wait", "events", "accept", "accept_empty",
};
#define IOSTAT(r, k, n) atomic_store_explicit(&(r)->io[k], \
            atomic_load_explicit(&(r)->io[k], memory_order_relaxed) + (n), memory_order_relaxed)
#else
#define IOSTAT(r, k, n) ((void)0)
#endif

/* Per-thread reactor. Atomics are the only fields other threads read; the
   inbox is the only field they write (under its lock). */
struct reactor {
    int id, port;
    sock_t lfd, wakefd, inboxfd;
    poll_t ep;
    pthread_t thread;
    int64_t now;               /* cached monotonic ms, refreshed after each epoll_wait */
    dlink live;                /* live connections, earliest deadline first */
    bool stopping;

    pthread_mutex_t inbox_lock;/* migration inbox: other reactors push, we drain */
    struct conn* inbox;
    bool inbox_closed;
    unsigned next_home;        /* Windows acceptor: round-robin cursor over reactors */

    int64_t next_tick, tick_wall_ns, tick_cpu_ns;

    sock_t psfd;               /* wake-up handle: subscribers here have mail */
    pthread_mutex_t wq_lock;   /* pub/sub wake queue: any thread pushes, we drain */
    struct ps_sub** wq;
    int nwq, wq_cap;
    struct ps_sub** wq_spare;  /* swapped with wq while draining */
    int wq_spare_cap;

    struct conn** heap;        /* handler timers: min-heap ordered by conn->wake_at */
    int nheap, heap_cap;

    struct conn* graveyard;    /* finished connections, freed after the current batch */

    http_ctx* ctx_cache[CTX_CACHE];
    int nctx_cache;
    time_t date_sec;
    char date[40];             /* cached IMF-fixdate for the Date header */

    _Atomic int  load_pm;      /* CPU load over the last window, per mille of one core */
    _Atomic int  active;
    _Atomic long requests, migrated_in, migrated_out;
    _Atomic long io[IO_NSTATS];/* -DIO_STATS counters; only this reactor writes them */
#ifdef _WIN32
    struct accept_op* acc;     /* reactor 0: its AcceptEx operations */
    int lfamily;               /* ... and the listener's address family */
    int naccept;               /* AcceptEx operations in flight */
    int ndraining;             /* closed connections waiting for their last completion */
    int nlimbo;                /* connections migrating away, waiting for a cancelled read */
#endif
};

static struct reactor* g_reactors;
static int g_nreactors;
static const http_route* g_routes;
static llhttp_settings_t g_parser_settings;

/* Wake a reactor: stop, adopt its inbox, or deliver pub/sub mail. */
enum { NOTE_STOP, NOTE_INBOX, NOTE_PS };
#ifdef _WIN32
enum { KEY_IO = 1, KEY_ACCEPT, KEY_STOP, KEY_INBOX, KEY_PS, KEY_KICK };   /* completion keys */
static void reactor_notify(struct reactor* r, int what) {
    PostQueuedCompletionStatus(r->ep, 0, what == NOTE_STOP ? KEY_STOP : what == NOTE_INBOX ? KEY_INBOX : KEY_PS, NULL);
}
#else
static void reactor_notify(struct reactor* r, int what) {
    notify_signal(what == NOTE_STOP ? r->wakefd : what == NOTE_INBOX ? r->inboxfd : r->psfd);
}
#endif

#ifndef _WIN32
/* epoll data.ptr tags for the non-connection fds */
static char LISTENER_TAG, WAKE_TAG, INBOX_TAG, PS_TAG;
#endif

static __thread struct reactor* tls_reactor;    /* the reactor running on this thread */

enum { BODY_DISCARD, BODY_BUFFER, BODY_STREAM };

/* Per-request state. Allocated when a request's first byte arrives and
   recycled through the reactor's cache afterwards, so idle keep-alive
   connections only cost their socket buffer. */
struct http_ctx {
    struct conn* c;
    const http_route* route;

    /* request head (all strings point into arena) */
    http_str method, target, path, query;
    int version_major, version_minor;
    http_header headers[MAX_HEADERS];
    int nheaders;
    struct { http_str name, value; } params[MAX_PARAMS];
    int nparams;
    int64_t content_length;    /* -1 if absent */
    bool chunked, expect_continue, is_head, keep_alive;
    bool head_done, msg_done;
    int hstate;                /* 0 none, 1 in header field, 2 in header value */

    /* request body */
    int body_mode;
    char* body;                /* buffered body (heap) */
    size_t body_len, body_cap, body_limit, discarded;
    http_str chunk;            /* streaming: current chunk, points into conn->in */
    bool want_body;            /* streaming handler is awaiting http_body_ready() */

    /* response */
    int err;                   /* nonzero: respond with this status and stop */
    bool head_sent, ended, chunked_out, close, want_write, sent_continue;
    int open_chunk;            /* offset of the reserved chunk-size field in out, or -1 */
    char* ext;                 /* large buffered response body (heap) */
    size_t ext_len, ext_off;
    int xhdr_len;
    char xhdr[1024];           /* extra response headers from http_set_header() */

    /* proxy awareness */
    char client_ip[INET6_ADDRSTRLEN];   /* resolved http_client_ip(), cached */
    bool sse;                  /* response is text/event-stream */
    bool sse_keepalive_due;    /* reactor asks for a keepalive comment */

    /* WebSocket */
    bool ws;                   /* connection has been upgraded */
    bool ws_ping_due;          /* reactor asks for a keepalive ping */
    bool ws_ping_out;          /* ping sent, waiting to hear anything back */
    int64_t ws_ping_at;
    bool want_ws;              /* handler is awaiting ws_recv_ready() */
    bool ws_in_frame, ws_frame_fin, ws_in_msg, ws_msg_ready, ws_msg_held;
    bool ws_close_received, ws_close_queued, ws_close_pending, ws_close_sent, ws_failed;
    bool ws_pong_pending;
    int ws_msg_op, ws_close_code, ws_pong_len, ws_close_len;
    uint64_t ws_frame_left, ws_mask_pos;
    uint8_t ws_mask[4];
    char* ws_msg;              /* message being assembled (heap, up to WS_MAX_MSG) */
    size_t ws_msg_len, ws_msg_cap;
    char ws_pong[125], ws_closebuf[125];

    /* buffers (not zeroed on reuse) */
    int arena_len;
    char arena[HDR_ARENA];
    int out_off, out_len;
    char out[OUT_CAP];
};

/* Connection task. Everything that must survive a suspension point lives
   here or in its http_ctx, which is also what makes migration a pointer handoff. */
cco_task_struct (conn) {
    conn_base base;            /* must be first */
    struct reactor* r;         /* current owner; changes on migration */
    dlink link;                /* position in r->live (deadline order) */
    struct conn* inbox_next;   /* link while queued in a reactor's inbox */
    int64_t deadline;
    int64_t win_ns;            /* coroutine run time in the current window */
    int64_t settled_at;        /* ms when it last migrated (cooldown reference) */
    int64_t last_io;           /* ms of the last byte in or out */
    int64_t last_rx, last_tx;  /* ms of the last byte received / sent */
    uint64_t tx_total;         /* bytes handed to the kernel */
    uint64_t acked_last;       /* tx_total minus the kernel's send queue at the last check:
                                  bytes the peer has actually taken (WebSocket liveness) */
    int64_t kq_moved_at;       /* ms the peer was last seen taking our data */
    ipaddr peer;               /* the TCP peer (often the proxy) */
    ipaddr client;             /* the client: the peer, or from a PROXY header */
    bool client_tls;           /* PROXY v2 says the client connection used TLS */
    bool served;               /* completed a request: now idling as keep-alive */
    char client_str[INET6_ADDRSTRLEN];
    int64_t wake_at;           /* handler timer, valid while heap_idx >= 0 */
    int heap_idx;              /* position in r->heap, or -1 */
    bool timer_moved;          /* timer detached during migration, re-add on arrival */
    bool fresh;                /* in an inbox, just accepted and not started yet */
    bool timed_out, eof, paused, progress, woken, rdhup, linger;
    bool dead;                 /* finished; freed at the end of the loop iteration */
    struct conn* dead_next;
    size_t lingered;           /* bytes discarded during a lingering close */
    sock_t fd;
    uint32_t ready;            /* epoll events delivered by the reactor */
    uint32_t interest;         /* events currently registered with epoll */
    bool tx_full;              /* socket buffer full: don't send() until EPOLLOUT (Linux) */
#ifdef _WIN32
    struct io_op {             /* one overlapped read or write (see "I/O completion ports") */
        OVERLAPPED ov;         /* first: a completion hands back &ov */
        struct conn* c;
        int state;             /* IO_IDLE, IO_PENDING, or IO_DONE (completed, result not taken yet) */
        DWORD bytes;
        bool failed, cancelled;
        bool probe;            /* read: zero-byte, only to learn that data or a close arrived */
        size_t out_n;          /* write: how much of it came from x->out (the rest from x->ext) */
    } rd, wr;
    bool skip;                 /* immediate successes queue no completion (io_set_modes) */
    bool probe_seen;           /* a probe found data or a close: don't probe again until it reads */
    bool kick_pending;         /* `kick` is queued: run it again next round (resume) */
    OVERLAPPED kick;
    bool migrating;            /* moving to migrate_to once its cancelled read completes */
    bool shrink_wanted;        /* shrinking `in` once its cancelled read completes */
    bool buried;               /* dead: freed when its last operation completes */
    struct reactor* migrate_to;
#endif
    http_ctx* x;               /* current request, or NULL between requests */
    struct http_task* task;    /* current streaming/WebSocket handler, or NULL */
    http_stream_fn task_fn;    /* ... and its function */
    struct ps_sub* sub;        /* pub/sub subscription of the current handler, or NULL */
    llhttp_t parser;
    int in_off, in_len;        /* unparsed input is in[in_off .. in_len) */
    int in_cap;                /* size of in: IN_CAP, or IN_BIG_CAP while grown (in_grow) */
    char* in;                  /* in_small, or a heap buffer while receiving bulk data */
    char in_small[IN_CAP];     /* last: not zeroed on accept */
};

#define conn_of(lnk) c_container_of(lnk, struct conn, link)

enum { IO_IDLE, IO_PENDING, IO_DONE };

/* Windows: the kernel owns part of `in` while a read is posted or its result
   hasn't been taken, and part of the output buffers while a write is. */
#ifdef _WIN32
static bool in_busy(const struct conn* c) { return c->rd.state != IO_IDLE && !c->rd.probe; }
static bool out_busy(const struct conn* c) { return c->wr.state == IO_PENDING; }
static bool io_busy(const struct conn* c) {
    return c->rd.state == IO_PENDING || c->wr.state == IO_PENDING || c->kick_pending;
}
#else
static bool in_busy(const struct conn* c) { (void)c; return false; }
static bool out_busy(const struct conn* c) { (void)c; return false; }
static bool io_busy(const struct conn* c) { (void)c; return false; }
#endif

/* ---- Deadlines ---- */

/* All deadlines armed here are now + TIMEOUT_MS, so appending keeps the list sorted. */
static void arm_deadline(struct conn* c) {
    c->deadline = c->r->now + TIMEOUT_MS;
    dlink_remove(&c->link);
    dlink_push_back(&c->r->live, &c->link);
}

/* Re-arm the deadline because bytes moved (or a request started). */
static void touch(struct conn* c) {
    c->last_io = c->r->now;
    arm_deadline(c);
}

/* A migrated connection keeps its original deadline, which may be earlier than
   ones already queued here, so walk back from the tail to its sorted place. */
static void insert_by_deadline(struct reactor* r, struct conn* c) {
    dlink* pos = r->live.prev;
    while (pos != &r->live && conn_of(pos)->deadline > c->deadline)
        pos = pos->prev;
    dlink_insert_after(pos, &c->link);
}

/* What the connection waits for. On Linux this is its epoll registration
   (EPOLLRDHUP goes with EPOLLIN: a streaming handler that stops reading then
   just drops EPOLLIN). On Windows io_arm() acts on it after the coroutine
   yields: EPOLLIN or EPOLLRDHUP keep a read posted. */
static void set_interest(struct conn* c, uint32_t events) {
    if ((events & EPOLLIN) && !c->rdhup) events |= EPOLLRDHUP;
#ifdef _WIN32
    c->interest = events;
#else
    if (c->interest == events) return;
    IOSTAT(c->r, IO_MOD, 1);
    IOSTAT(c->r, IO_MOD_ADD, (events & ~c->interest) != 0);
    struct epoll_event ev = {.events = events, .data.ptr = c};
    epoll_ctl(c->r->ep, EPOLL_CTL_MOD, c->fd, &ev);
    c->interest = events;
#endif
}

/* ---- Handler timers: per-reactor binary min-heap on conn->wake_at ---- */

static void heap_swap(struct reactor* r, int i, int j) {
    struct conn* t = r->heap[i];
    r->heap[i] = r->heap[j];
    r->heap[j] = t;
    r->heap[i]->heap_idx = i;
    r->heap[j]->heap_idx = j;
}
static void heap_up(struct reactor* r, int i) {
    while (i > 0) {
        int p = (i - 1) / 2;
        if (r->heap[p]->wake_at <= r->heap[i]->wake_at) break;
        heap_swap(r, i, p);
        i = p;
    }
}
static void heap_down(struct reactor* r, int i) {
    for (;;) {
        int l = 2 * i + 1, rt = l + 1, m = i;
        if (l < r->nheap && r->heap[l]->wake_at < r->heap[m]->wake_at) m = l;
        if (rt < r->nheap && r->heap[rt]->wake_at < r->heap[m]->wake_at) m = rt;
        if (m == i) return;
        heap_swap(r, i, m);
        i = m;
    }
}
static bool heap_push(struct reactor* r, struct conn* c) {
    if (r->nheap == r->heap_cap) {
        int cap = r->heap_cap ? r->heap_cap * 2 : 64;
        struct conn** h = realloc(r->heap, (size_t)cap * sizeof *h);
        if (!h) return false;
        r->heap = h;
        r->heap_cap = cap;
    }
    r->heap[r->nheap] = c;
    c->heap_idx = r->nheap++;
    heap_up(r, c->heap_idx);
    return true;
}
static void heap_remove(struct reactor* r, struct conn* c) {
    int i = c->heap_idx;
    if (i < 0) return;
    int last = --r->nheap;
    if (i != last) {
        r->heap[i] = r->heap[last];
        r->heap[i]->heap_idx = i;
        heap_down(r, i);
        heap_up(r, i);
    }
    c->heap_idx = -1;
}
/* Wake the connection at `when` (keeping an earlier wake-up if one is set). */
static void timer_arm(struct conn* c, int64_t when) {
    if (c->heap_idx >= 0) {
        if (c->wake_at <= when) return;
        heap_remove(c->r, c);
    }
    c->wake_at = when;
    heap_push(c->r, c);
}

/* ---- Request contexts ---- */

static http_ctx* ctx_acquire(struct conn* c) {
    struct reactor* r = c->r;
    http_ctx* x = r->nctx_cache ? r->ctx_cache[--r->nctx_cache] : malloc(sizeof *x);
    if (!x) return NULL;
    memset(x, 0, offsetof(http_ctx, arena));
    x->c = c;
    x->content_length = -1;
    x->open_chunk = -1;
    x->arena_len = x->out_off = x->out_len = 0;
    return x;
}

static void ctx_release(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return;
    free(x->body);
    free(x->ext);
    free(x->ws_msg);
    struct reactor* r = c->r;
    if (r->nctx_cache < CTX_CACHE) r->ctx_cache[r->nctx_cache++] = x;
    else free(x);
    c->x = NULL;
}
