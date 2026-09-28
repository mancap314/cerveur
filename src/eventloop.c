/*
 * src/eventloop.c - the event loop: listener, I/O completion ports (Windows) or epoll (Linux).
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ------------------------------------------------------------------ */
/* Reactor setup and event loop                                       */
/* ------------------------------------------------------------------ */
/* A non-blocking listening socket on g_bind:port, or BAD_SOCK. */
static sock_t listen_open(int port) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof addr);
    socklen_t addrlen;
    struct sockaddr_in* a4 = (struct sockaddr_in*)&addr;
    struct sockaddr_in6* a6 = (struct sockaddr_in6*)&addr;
    if (inet_pton(AF_INET, g_bind, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons((uint16_t)port);
        addrlen = sizeof *a4;
    } else if (inet_pton(AF_INET6, g_bind, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons((uint16_t)port);
        addrlen = sizeof *a6;
    } else {
        errno = EINVAL;
        return BAD_SOCK;
    }
    int one = 1, zero = 0;
#ifdef _WIN32
    sock_t s = socket(addr.ss_family, SOCK_STREAM, 0);
    if (s == BAD_SOCK) return BAD_SOCK;
    /* Windows' SO_REUSEADDR would let another process steal the port. */
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof one);
    /* Accepted sockets inherit TCP_NODELAY from the listener on Windows. */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
    if (sock_nonblock(s) != 0) goto fail;
#else
    sock_t s = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s == BAD_SOCK) return BAD_SOCK;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) < 0) goto fail;
#endif
    if (addr.ss_family == AF_INET6)             /* "::" also accepts IPv4 */
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&zero, sizeof zero);
    if (bind(s, (struct sockaddr*)&addr, addrlen) < 0) goto fail;
    if (listen(s, SOMAXCONN) < 0) goto fail;
    return s;
fail:
    sock_close(s);
    return BAD_SOCK;
}

#ifdef _WIN32
/* ------------------------------------------------------------------ */
/* Windows: I/O completion ports                                       */
/* ------------------------------------------------------------------ */
/* Each reactor has its own completion port. A connection's reads and writes
   are overlapped WSARecv/WSASend into its own buffers (rd_post, flush); their
   completions set the same event bits epoll would (io_done), and the
   connection coroutine runs unchanged. Sockets are put in "skip completion on
   success" mode, so an operation that completes at once (data already
   waiting, room in the send buffer) costs one call and no completion packet.
   Wake-ups (stop, inbox, pub/sub mail) are posted packets. Reactor 0 accepts
   for everyone with AcceptEx. */

#define ACCEPT_OPS  16                          /* AcceptEx operations kept posted */
#define ACCEPT_ADDR (sizeof(SOCKADDR_STORAGE) + 16)
#define STATUS_CANCELLED_ ((LONG)0xC0000120)    /* CancelIoEx'd operation */

struct accept_op { OVERLAPPED ov; sock_t s; char addr[2 * ACCEPT_ADDR]; };

static LPFN_ACCEPTEX g_AcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS g_GetAcceptExSockaddrs;

typedef struct { HANDLE port; PVOID key; } completion_info;         /* FILE_COMPLETION_INFORMATION */
typedef struct { union { LONG status; PVOID ptr; }; ULONG_PTR info; } io_status;
typedef LONG (NTAPI* set_info_fn)(HANDLE, io_status*, PVOID, ULONG, int);
static set_info_fn g_NtSetInformationFile;
static bool g_skip_ok;                          /* all TCP providers are IFS: skip mode is safe */

/* Skipping completions on success is only safe when no layered service
   provider sits between Winsock and the kernel. */
static bool tcp_providers_are_ifs(void) {
    DWORD len = 0;
    WSAEnumProtocolsW(NULL, NULL, &len);
    WSAPROTOCOL_INFOW* p = len ? malloc(len) : NULL;
    int n = p ? WSAEnumProtocolsW(NULL, p, &len) : -1;
    bool ok = n > 0;
    for (int i = 0; i < n; ++i)
        if (p[i].iProtocol == IPPROTO_TCP && !(p[i].dwServiceFlags1 & XP1_IFS_HANDLES)) ok = false;
    free(p);
    return ok;
}

static void iocp_init(void) {
    g_NtSetInformationFile = (set_info_fn)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    g_skip_ok = tcp_providers_are_ifs();
}

static void io_set_modes(struct conn* c) {
    c->skip = g_skip_ok && SetFileCompletionNotificationModes((HANDLE)c->fd,
                  FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);
}

/* Move a socket (with no I/O pending) to another reactor's completion port.
   The move resets the skip-on-success mode, so it is set again. */
static bool io_rebind(struct conn* c, struct reactor* to) {
    if (!g_NtSetInformationFile) return false;
    completion_info ci = {to->ep, (PVOID)(ULONG_PTR)KEY_IO};
    io_status st;
    if (g_NtSetInformationFile((HANDLE)c->fd, &st, &ci, sizeof ci, 61 /* FileReplaceCompletionInformation */) < 0)
        return false;
    io_set_modes(c);
    return true;
}

/* After the coroutine yields: if it waits for input, keep a read posted into
   `in`; if it only watches for the peer hanging up, keep a probe posted.
   Returns true if that completed at once, so the coroutine should run again. */
static bool io_arm(struct conn* c) {
    if (c->rd.state != IO_IDLE || c->migrating || c->shrink_wanted || !(c->interest & (EPOLLIN | EPOLLRDHUP)))
        return false;
    if (!(c->interest & EPOLLIN)) {     /* not reading: a handler may hold a pointer into `in` */
        if (c->probe_seen) return false;
        rd_post(c, true);
        if (c->rd.state != IO_DONE) return false;
        uint32_t bits = probe_result(c);
        c->ready |= bits;
        return bits != 0;
    }
    if (c->in_off > 0) {                /* reading: nothing points into `in` */
        memmove(c->in, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
        c->in_len -= c->in_off;
        c->in_off = 0;
    }
    if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
    if (c->in_len == c->in_cap) return false;
    rd_post(c, false);
    if (c->rd.state != IO_DONE) return false;
    c->ready |= rd_bits(c);
    return true;
}

/* A connection's read or write completed. */
static void io_done(struct reactor* r, OVERLAPPED_ENTRY* e) {
    struct io_op* op = (struct io_op*)e->lpOverlapped;
    struct conn* c = op->c;
    LONG st = (LONG)e->lpOverlapped->Internal;
    op->state = IO_DONE;
    op->bytes = e->dwNumberOfBytesTransferred;
    op->cancelled = st == STATUS_CANCELLED_;
    op->failed = st < 0 && !op->cancelled;
    IOSTAT(r, IO_EVENTS, 1);
    if (c->dead) {                      /* closed: it was only waiting for this */
        if (c->buried && !io_busy(c)) {
            conn_free_buffers(c);
            free(c);
            r->ndraining--;
        }
        return;
    }
    bool is_rd = op == &c->rd;
    if (is_rd && op->cancelled) op->state = IO_IDLE;     /* nothing arrived */
    if (c->migrating) {                 /* its read is out of the way: move it */
        migrate_finish(r, c);
        return;
    }
    if (is_rd && c->shrink_wanted) {
        c->shrink_wanted = false;
        if (op->state == IO_IDLE) {     /* cancelled as asked: shrink, then read again */
            in_shrink(c);
            if (io_arm(c)) resume_timed(c);
            return;
        }
    }
    if (is_rd && op->state == IO_IDLE) return;
    if (is_rd && op->probe) {           /* data or a close arrived while it wasn't reading */
        uint32_t bits = probe_result(c);
        if (!bits) {                    /* spurious: watch again */
            if (io_arm(c)) resume_timed(c);
            return;
        }
        c->ready |= bits;
        resume_timed(c);
        return;
    }
    c->ready |= is_rd ? rd_bits(c) : op->failed ? EPOLLOUT | EPOLLERR | EPOLLHUP : EPOLLOUT;
    resume_timed(c);
}

/* A connection's kick (io_kick) came round: run it. */
static void kick_done(struct reactor* r, OVERLAPPED* ov) {
    struct conn* c = c_container_of(ov, struct conn, kick);
    c->kick_pending = false;
    if (c->dead) {                      /* closed meanwhile: it was only waiting for this */
        if (c->buried && !io_busy(c)) {
            conn_free_buffers(c);
            free(c);
            r->ndraining--;
        }
        return;
    }
    resume_timed(c);
}

static void accept_post(struct reactor* r, struct accept_op* op) {
    memset(&op->ov, 0, sizeof op->ov);
    op->s = WSASocketW(r->lfamily, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (op->s == BAD_SOCK) return;
    DWORD got = 0;
    if (!g_AcceptEx(r->lfd, op->s, op->addr, 0, ACCEPT_ADDR, ACCEPT_ADDR, &got, &op->ov)
        && WSAGetLastError() != ERROR_IO_PENDING) {
        closesocket(op->s);
        op->s = BAD_SOCK;
        return;
    }
    r->naccept++;
}

/* An AcceptEx completed: set up the connection, deal it out, post another. */
static void accept_done(struct reactor* r, OVERLAPPED_ENTRY* e) {
    struct accept_op* op = (struct accept_op*)e->lpOverlapped;
    sock_t fd = op->s;
    op->s = BAD_SOCK;
    r->naccept--;
    IOSTAT(r, IO_ACCEPT, 1);
    struct conn* c = NULL;
    if ((LONG)e->lpOverlapped->Internal >= 0 && !r->stopping
        && setsockopt(fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char*)&r->lfd, sizeof r->lfd) == 0
        && sock_nonblock(fd) == 0) {
        struct sockaddr *la, *ra;
        INT lal, ral;
        g_GetAcceptExSockaddrs(op->addr, 0, ACCEPT_ADDR, ACCEPT_ADDR, &la, &lal, &ra, &ral);
        c = conn_new(r, fd, ra);
    }
    if (!c) {
        IOSTAT(r, IO_ACCEPT_EMPTY, 1);
        closesocket(fd);
    } else {
        /* Reactor 0 alone accepts, so it deals connections out round-robin. */
        struct reactor* home = &g_reactors[r->next_home++ % (unsigned)g_nreactors];
        if (home == r || !hand_off_new(home, c)) conn_start(r, c);
    }
    if (!r->stopping && r->lfd != BAD_SOCK) accept_post(r, op);
}

/* Wait up to `timeout` ms (-1: no limit) and handle what completed. */
static void reactor_poll(struct reactor* r, int timeout) {
    OVERLAPPED_ENTRY ev[MAX_EVENTS];
    ULONG n = 0;
    if (!GetQueuedCompletionStatusEx(r->ep, ev, MAX_EVENTS, &n, timeout < 0 ? INFINITE : (DWORD)timeout, FALSE))
        n = 0;                          /* timed out */
    r->now = now_ms();
    IOSTAT(r, IO_WAIT, 1);
    for (ULONG i = 0; i < n; ++i) {
        switch (ev[i].lpCompletionKey) {
        case KEY_IO:     io_done(r, &ev[i]); break;
        case KEY_ACCEPT: accept_done(r, &ev[i]); break;
        case KEY_INBOX:  adopt_inbox(r); break;
        case KEY_PS:     ps_drain(r); break;         /* other threads posted mail */
        case KEY_KICK:   kick_done(r, ev[i].lpOverlapped); break;
        case KEY_STOP:   r->stopping = true; break;
        }
    }
}

static int reactor_open(struct reactor* r) {
    dlink_init(&r->live);
    pthread_mutex_init(&r->inbox_lock, NULL);
    pthread_mutex_init(&r->wq_lock, NULL);
    r->lfd = BAD_SOCK;
    r->ep = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!r->ep) return -1;
    if (r->id != 0) return 0;
    /* Reactor 0 accepts for everyone (there is no SO_REUSEPORT). */
    r->lfd = listen_open(r->port);
    if (r->lfd == BAD_SOCK) return -1;
    struct sockaddr_storage la;
    int lal = sizeof la;
    GUID g1 = WSAID_ACCEPTEX, g2 = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD got;
    if (getsockname(r->lfd, (struct sockaddr*)&la, &lal) != 0
        || WSAIoctl(r->lfd, SIO_GET_EXTENSION_FUNCTION_POINTER, &g1, sizeof g1,
                    &g_AcceptEx, sizeof g_AcceptEx, &got, NULL, NULL) != 0
        || WSAIoctl(r->lfd, SIO_GET_EXTENSION_FUNCTION_POINTER, &g2, sizeof g2,
                    &g_GetAcceptExSockaddrs, sizeof g_GetAcceptExSockaddrs, &got, NULL, NULL) != 0
        || !CreateIoCompletionPort((HANDLE)r->lfd, r->ep, KEY_ACCEPT, 0))
        return -1;
    r->lfamily = la.ss_family;
    r->acc = calloc(ACCEPT_OPS, sizeof *r->acc);
    if (!r->acc) return -1;
    for (int i = 0; i < ACCEPT_OPS; ++i) accept_post(r, &r->acc[i]);
    return r->naccept ? 0 : -1;
}

#else  /* Linux: epoll */

/* Wait up to `timeout` ms (-1: no limit) and handle what's ready. */
static void reactor_poll(struct reactor* r, int timeout) {
    struct epoll_event evs[MAX_EVENTS];
    int nev = epoll_wait(r->ep, evs, MAX_EVENTS, timeout);
    r->now = now_ms();
    IOSTAT(r, IO_WAIT, 1);

    for (int i = 0; i < nev; ++i) {
        void* tag = evs[i].data.ptr;
        if (tag == &LISTENER_TAG) { accept_all(r); continue; }
        if (tag == &INBOX_TAG)    { adopt_inbox(r); continue; }
        if (tag == &PS_TAG) {                    /* other threads posted mail */
            notify_drain(r->psfd);
            ps_drain(r);
            continue;
        }
        if (tag == &WAKE_TAG)     { r->stopping = true; continue; }
        struct conn* c = tag;
        if (c->dead) continue;                   /* finished earlier in this batch */
        IOSTAT(r, IO_EVENTS, 1);
        if (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) c->tx_full = false;
        c->ready |= evs[i].events;
        resume_timed(c);                         /* only ready connections run */
    }
}

static int reactor_open(struct reactor* r) {
    dlink_init(&r->live);
    pthread_mutex_init(&r->inbox_lock, NULL);
    pthread_mutex_init(&r->wq_lock, NULL);
    r->lfd = listen_open(r->port);
    if (r->lfd == BAD_SOCK) return -1;

    r->ep = epoll_create1(0);
    r->wakefd = notify_open();
    r->inboxfd = notify_open();
    r->psfd = notify_open();
    if (r->ep == BAD_POLL || r->wakefd == BAD_SOCK || r->inboxfd == BAD_SOCK || r->psfd == BAD_SOCK)
        return -1;
    struct epoll_event pev = {.events = EPOLLIN, .data.ptr = &PS_TAG};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->psfd, &pev);
    struct epoll_event lev = {.events = EPOLLIN, .data.ptr = &LISTENER_TAG};
    struct epoll_event wev = {.events = EPOLLIN, .data.ptr = &WAKE_TAG};
    struct epoll_event iev = {.events = EPOLLIN, .data.ptr = &INBOX_TAG};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->lfd, &lev);
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->wakefd, &wev);
    epoll_ctl(r->ep, EPOLL_CTL_ADD, r->inboxfd, &iev);
    return 0;
}
#endif

static void* reactor_run(void* arg) {
    struct reactor* r = arg;
    bool balancing = g_nreactors > 1;

    tls_reactor = r;
    r->now = now_ms();
    r->next_tick = r->now + REBALANCE_MS;
    r->tick_wall_ns = now_ns();
    r->tick_cpu_ns = thread_cpu_ns();

    while (!r->stopping) {
        /* Deliver pub/sub mail posted by this thread (it skips the eventfd).
           Bounded, in case handlers keep publishing to each other. */
        for (int round = 0; round < 4 && ps_drain(r) > 0; ++round) {}

        /* Sleep until the earliest of: an event, the next deadline, the next tick. */
        int64_t wake_at = balancing ? r->next_tick : INT64_MAX;
        if (!dlink_empty(&r->live) && conn_of(r->live.next)->deadline < wake_at)
            wake_at = conn_of(r->live.next)->deadline;
        if (r->nheap && r->heap[0]->wake_at < wake_at)
            wake_at = r->heap[0]->wake_at;
        int timeout = -1;
        if (wake_at != INT64_MAX) {
            int64_t ms = wake_at - now_ms();
            timeout = ms < 0 ? 0 : (int)ms;
        }
        if (ps_pending(r)) timeout = 0;              /* more mail: don't sleep */
        reactor_poll(r, timeout);

        /* Fire handler timers that are due. */
        while (r->nheap && r->heap[0]->wake_at <= r->now) {
            struct conn* c = r->heap[0];
            heap_remove(r, c);
            c->woken = true;
            resume_timed(c);
        }

        /* Expire overdue connections; they sit at the front of the list.
           conn_still_wanted() decides who lives on (keep-alive, WebSocket
           pings, sleeping or subscribed handlers). */
        while (!dlink_empty(&r->live) && conn_of(r->live.next)->deadline <= r->now) {
            struct conn* c = conn_of(r->live.next);
            if (conn_still_wanted(r, c)) {
                arm_deadline(c);                     /* moves it to the tail */
                if (!c->x) in_release_idle(c);       /* idle keep-alive: give back a grown buffer */
                if (c->x && (c->x->ws_ping_due || c->x->sse_keepalive_due)) {
                    c->woken = true;                 /* let it send the ping / comment */
                    resume_timed(c);
                }
                continue;
            }
            c->timed_out = true;
            resume(c);                               /* cco_return -> finalize -> unlinks */
        }

        if (balancing && r->now >= r->next_tick && !r->stopping) {
            rebalance_tick(r);
            r->next_tick = r->now + REBALANCE_MS;
        }
        bury_dead(r);                                /* nothing refers to them any more */
    }

    /* Shutdown: refuse further migrations, adopt anything already queued,
       then stop every live coroutine so its cco_finalize runs. */
    pthread_mutex_lock(&r->inbox_lock);
    r->inbox_closed = true;
    pthread_mutex_unlock(&r->inbox_lock);
    adopt_inbox(r);

#ifdef _WIN32
    if (r->lfd != BAD_SOCK) {                        /* its AcceptEx operations complete, cancelled */
        closesocket(r->lfd);
        r->lfd = BAD_SOCK;
    }
#else
    close(r->lfd);
#endif
    while (!dlink_empty(&r->live)) {
        struct conn* c = conn_of(r->live.next);
        cco_stop(c);                                 /* jump to cco_finalize on resume */
        resume(c);
    }
    bury_dead(r);
#ifdef _WIN32
    /* Closed sockets' operations, the cancelled reads of connections that were
       on their way to another reactor, and cancelled accepts still complete:
       wait for them (bounded), stopping any connection that couldn't leave. */
    for (int64_t end = now_ms() + 2000; (r->ndraining || r->nlimbo || r->naccept) && now_ms() < end; ) {
        reactor_poll(r, 50);
        while (!dlink_empty(&r->live)) {
            struct conn* c = conn_of(r->live.next);
            cco_stop(c);
            resume(c);
        }
        bury_dead(r);
    }
    free(r->acc);
#endif
    while (r->nctx_cache) free(r->ctx_cache[--r->nctx_cache]);
    free(r->heap);
    poll_close(r->ep);
    return NULL;
}

#ifndef SERVER_NO_MAIN                 /* only the demo's /stats uses it */
static int format_stats(char* buf, size_t cap, const struct reactor* self) {
    long total_req = 0, total_mig = 0; int total_act = 0, len = 0;
    for (int i = 0; i < g_nreactors; ++i) {
        total_act += atomic_load_explicit(&g_reactors[i].active, memory_order_relaxed);
        total_req += atomic_load_explicit(&g_reactors[i].requests, memory_order_relaxed);
        total_mig += atomic_load_explicit(&g_reactors[i].migrated_out, memory_order_relaxed);
    }
    len += snprintf(buf + len, cap - (size_t)len,
                    "served_by=reactor%d active_connections=%d total_requests=%ld migrations=%ld\n",
                    self->id, total_act, total_req, total_mig);
    for (int i = 0; i < g_nreactors && (size_t)len < cap; ++i) {
        const struct reactor* r = &g_reactors[i];
        len += snprintf(buf + len, cap - (size_t)len,
                        "reactor%d load=%3d%% active=%d requests=%ld migrated_in=%ld migrated_out=%ld\n", i,
                        atomic_load_explicit(&r->load_pm, memory_order_relaxed) / 10,
                        atomic_load_explicit(&r->active, memory_order_relaxed),
                        atomic_load_explicit(&r->requests, memory_order_relaxed),
                        atomic_load_explicit(&r->migrated_in, memory_order_relaxed),
                        atomic_load_explicit(&r->migrated_out, memory_order_relaxed));
    }
#ifdef IO_STATS
    if ((size_t)len < cap) len += snprintf(buf + len, cap - (size_t)len, "io");
    for (int k = 0; k < IO_NSTATS && (size_t)len < cap; ++k) {
        long sum = 0;
        for (int i = 0; i < g_nreactors; ++i)
            sum += atomic_load_explicit(&g_reactors[i].io[k], memory_order_relaxed);
        len += snprintf(buf + len, cap - (size_t)len, " %s=%ld", io_stat_names[k], sum);
    }
    if ((size_t)len < cap) len += snprintf(buf + len, cap - (size_t)len, "\n");
#endif
    return len;
}
#endif
