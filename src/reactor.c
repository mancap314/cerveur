/*
 * src/reactor.c - reactors: scheduling, accepting, deadlines, migration, rebalancing.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* Reactor: scheduling, migration, rebalancing                              */
/* ======================================================================== */

#ifdef _WIN32
static bool io_arm(struct conn* c);
static void io_set_modes(struct conn* c);
static bool io_rebind(struct conn* c, struct reactor* to);

/* Run it again on the next round, after the others. */
static void io_kick(struct conn* c) {
    if (c->kick_pending) return;
    c->kick_pending = true;
    memset(&c->kick, 0, sizeof c->kick);
    PostQueuedCompletionStatus(c->r->ep, 0, KEY_KICK, &c->kick);
}
#else
static bool io_arm(struct conn* c) { (void)c; return false; }
static void io_kick(struct conn* c) { (void)c; }
#endif

/* Resume a connection. Returns false once it has finished. A finished
   connection isn't freed yet: other connections resumed in the same batch
   (e.g. by pub/sub mail) may finish while their events are still pending in
   the batch, so frees wait until the batch is done. On Windows, io_arm() then
   posts the read it may be waiting for; if that completes at once (data was
   already there), it runs again, a few times, and then yields to the other
   connections with a kick rather than hogging the reactor. */
static bool resume(struct conn* c) {
    for (int again = 0;; ++again) {
        if (c->dead) return false;
        /* Called directly rather than with cco_resume(), which goes through
           STC's generic int (*)(struct cco_task*) pointer: calling conn_run
           through that type is undefined (UBSan's -fsanitize=function). */
        if (conn_run(c) == cco_DONE) {
            c->dead = true;
            c->dead_next = c->r->graveyard;
            c->r->graveyard = c;
            return false;
        }
        if (!io_arm(c)) return true;            /* waiting for a completion */
        if (again == 8) {                       /* ready again, but others go first */
            io_kick(c);
            return true;
        }
    }
}

static void bury_dead(struct reactor* r) {
    while (r->graveyard) {
        struct conn* c = r->graveyard;
        r->graveyard = c->dead_next;
#ifdef _WIN32
        if (io_busy(c)) {               /* its closed socket's operations are still completing */
            c->buried = true;
            r->ndraining++;
            continue;                   /* io_done() frees it */
        }
#endif
        conn_free_buffers(c);
        free(c);
    }
}

/* Resume and charge the coroutine's run time to the connection. */
static void resume_timed(struct conn* c) {
    int64_t t0 = now_ns();
    if (resume(c))
        c->win_ns += now_ns() - t0;
}

static void conn_start(struct reactor* r, struct conn* c);
#ifdef _WIN32
static bool hand_off_new(struct reactor* to, struct conn* c);
#endif

/* A connection for an accepted socket, not started yet (conn_start). */
static struct conn* conn_new(struct reactor* r, sock_t fd, const struct sockaddr* sa) {
    struct conn* c = malloc(sizeof *c);
    if (!c) return NULL;
    memset(c, 0, offsetof(struct conn, in_small));   /* the 16 KiB buffer needn't be zeroed */
    c->in = c->in_small;
    c->in_cap = IN_CAP;
    c->base.func = conn_run;
    c->r = r;
    c->fd = fd;
    c->settled_at = r->now - COOLDOWN_MS;       /* cooldown only applies after a migration */
    c->heap_idx = -1;
    c->last_io = c->last_rx = c->last_tx = c->kq_moved_at = r->now;
    ip_from_sockaddr(sa, &c->peer);
    c->client = c->peer;
    ip_to_str(&c->client, c->client_str, sizeof c->client_str);
    dlink_init(&c->link);
    llhttp_init(&c->parser, HTTP_REQUEST, &g_parser_settings);
    c->parser.data = c;
    /* Wait for the first EPOLLIN rather than reading right away: accept
       returns once the handshake completes, before the client's request
       has arrived, so an immediate recv() nearly always comes back empty. */
    c->interest = EPOLLIN | EPOLLRDHUP;     /* see set_interest() */
#ifdef _WIN32
    c->rd.c = c->wr.c = c;
#endif
    return c;
}

#ifndef _WIN32
static void accept_all(struct reactor* r) {
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;
    for (;;) {
        sock_t fd = sock_accept(r->lfd, (struct sockaddr*)&sa, &salen);
        salen = sizeof sa;
        IOSTAT(r, IO_ACCEPT, 1);
        if (fd == BAD_SOCK) { IOSTAT(r, IO_ACCEPT_EMPTY, 1); break; }
        struct conn* c = conn_new(r, fd, (struct sockaddr*)&sa);
        if (!c) { sock_close(fd); continue; }
        conn_start(r, c);
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Deadlines: keep-alive, pings and keepalive comments                 */
/* ------------------------------------------------------------------ */

/* A connection's deadline (TIMEOUT_MS after its last activity) has passed.
   Return true to keep it: its deadline is re-armed, and if a WebSocket ping
   or SSE keepalive was requested here it is resumed to send it. */
static bool conn_still_wanted(struct reactor* r, struct conn* c) {
    http_ctx* x = c->x;
    if (!x)                     /* between requests: keep-alive, but a fresh connection
                                   gets only the header timeout to start its first one */
        return c->served && r->now - c->last_io < g_keepalive_ms;
    bool out_pending = x->out_off < x->out_len || x->ext_off < x->ext_len;
    if (!x->ws && out_pending && r->now - c->last_tx >= TIMEOUT_MS)
        return false;                                       /* client stopped reading */
    if (x->ws) {
        /* Backlog includes what the kernel still holds for the peer: a ping
           queued behind megabytes can't be answered until they're read.
           Progress = bytes the peer has acknowledged (sent minus still
           queued), which only grows when it actually reads; the kernel
           enlarging its buffer doesn't count. */
        int kq = sock_outq(c->fd, c->tx_total);
        if (kq < 0) kq = 0;
        uint64_t acked = c->tx_total - (uint64_t)kq;
        if (acked != c->acked_last) {
            c->acked_last = acked;
            c->kq_moved_at = r->now;
        }
        if (out_pending || kq > 0) {
            if (r->now - c->kq_moved_at >= WS_STALL_MS) return false;   /* stopped reading */
            if (x->ws_ping_out) x->ws_ping_at = r->now;     /* its answer can't be due yet */
            return true;
        }
        if (x->ws_ping_out) {                               /* heard anything since the ping? */
            if (c->last_rx >= x->ws_ping_at) x->ws_ping_out = false;
            else return r->now - x->ws_ping_at < WS_PONG_MS;
        }
        if (r->now - c->last_rx >= WS_PING_MS) {            /* quiet: ping it */
            x->ws_ping_due = x->ws_ping_out = true;
            x->ws_ping_at = r->now;
        }
        return true;
    }
    if (c->heap_idx >= 0 || ps_listening(c)) {              /* handler sleeping / subscribed */
        if (x->sse && !out_pending && r->now - c->last_tx >= SSE_KEEPALIVE_MS)
            x->sse_keepalive_due = true;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Pub/sub wake-ups                                                    */
/* ------------------------------------------------------------------ */

/* Resume subscribers on this reactor that have mail. A wake-up for a
   subscription that has since migrated is forwarded to its new owner. */
static int ps_drain(struct reactor* r) {
    pthread_mutex_lock(&r->wq_lock);
    struct ps_sub** q = r->wq;
    int n = r->nwq, cap = r->wq_cap;
    r->wq = r->wq_spare;
    r->wq_cap = r->wq_spare_cap;
    r->nwq = 0;
    pthread_mutex_unlock(&r->wq_lock);

    for (int i = 0; i < n; ++i) {
        struct ps_sub* s = q[i];
        struct reactor* owner = atomic_load(&s->owner);
        if (!atomic_load(&s->alive)) { ps_sub_unref(s); continue; }
        if (owner != r) { ps_post_wake(owner, s); continue; }    /* it moved: forward */
        atomic_store(&s->wake_pending, false);   /* before the handler checks its mail */
        struct conn* c = s->conn;
        if (c && c->r == r) {                    /* (not yet adopted: adoption resumes it) */
            c->woken = true;
            resume_timed(c);
        }
        ps_sub_unref(s);
    }
    r->wq_spare = q;
    r->wq_spare_cap = cap;
    return n;
}

static bool ps_pending(struct reactor* r) {
    pthread_mutex_lock(&r->wq_lock);
    bool pending = r->nwq > 0;
    pthread_mutex_unlock(&r->wq_lock);
    return pending;
}

/* ------------------------------------------------------------------ */
/* Migration                                                          */
/* ------------------------------------------------------------------ */

/* Start a connection on this reactor: register it and run it until it first
   waits (which arms its deadline). */
static void conn_start(struct reactor* r, struct conn* c) {
    c->r = r;
#ifdef _WIN32
    if (!CreateIoCompletionPort((HANDLE)c->fd, r->ep, KEY_IO, 0)) {
        closesocket(c->fd);
        free(c);
        return;
    }
    io_set_modes(c);
#else
    struct epoll_event ev = {.events = c->interest, .data.ptr = c};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, c->fd, &ev);
#endif
    atomic_fetch_add_explicit(&r->active, 1, memory_order_relaxed);
    resume_timed(c);
}

/* Make a connection handed over by another reactor ours (or one that could
   not leave, back ours): its deadline, timer and load count. */
static void adopt_one(struct reactor* r, struct conn* c, bool moved) {
    c->r = r;
    c->win_ns = 0;
    c->settled_at = r->now;
#ifndef _WIN32
    struct epoll_event ev = {.events = c->interest, .data.ptr = c};
    epoll_ctl(r->ep, EPOLL_CTL_ADD, c->fd, &ev);
#endif
    insert_by_deadline(r, c);
    if (c->timer_moved) {
        c->timer_moved = false;
        heap_push(r, c);
    }
    atomic_fetch_add_explicit(&r->active, 1, memory_order_relaxed);
    if (moved) atomic_fetch_add_explicit(&r->migrated_in, 1, memory_order_relaxed);
#ifdef _WIN32
    if (c->sub) atomic_store(&c->sub->owner, r);        /* (it may be coming back) */
    if (c->rd.state == IO_DONE) c->ready |= rd_bits(c);  /* input that arrived in transit */
    if (c->ready || c->sub) {
        c->woken = c->sub != NULL;      /* mail may have arrived in transit */
        resume_timed(c);
    } else if (io_arm(c)) {
        resume_timed(c);
    }
#else
    if (c->sub) {                       /* mail may have arrived while in transit */
        c->woken = true;
        resume_timed(c);
    }
#endif
}

/* Take ownership of everything other reactors have sent us. */
static void adopt_inbox(struct reactor* r) {
#ifndef _WIN32
    notify_drain(r->inboxfd);
#endif
    pthread_mutex_lock(&r->inbox_lock);
    struct conn* list = r->inbox;
    r->inbox = NULL;
    pthread_mutex_unlock(&r->inbox_lock);

    while (list) {
        struct conn* c = list;
        list = c->inbox_next;
        if (c->fresh) {                 /* dealt out by the acceptor, not migrated */
            c->fresh = false;
            conn_start(r, c);
            continue;
        }
        adopt_one(r, c, true);
    }
}

#ifdef _WIN32
/* Give a just-accepted connection (not started yet) to another reactor.
   Returns false if the target is shutting down. */
static bool hand_off_new(struct reactor* to, struct conn* c) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed, was_empty = !to->inbox;
    if (ok) {
        c->fresh = true;
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    /* A non-empty inbox has a wake-up on its way already. */
    if (ok && was_empty) reactor_notify(to, NOTE_INBOX);
    return ok;
}

/* A socket can only move to another completion port with no I/O pending, so
   migration is two steps: migrate() cancels the connection's posted read, and
   when that completes, migrate_finish() rebinds the socket to the target's
   port and hands the connection over. In between it is on no list. */
static void migrate_finish(struct reactor* from, struct conn* c) {
    if (c->migrating) {
        c->migrating = false;
        from->nlimbo--;
    }
    struct reactor* to = c->migrate_to;
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed && io_rebind(c, to);
    if (ok) {
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    if (ok) {
        atomic_fetch_add_explicit(&from->migrated_out, 1, memory_order_relaxed);
        reactor_notify(to, NOTE_INBOX);
    } else {
        adopt_one(from, c, false);      /* can't move it after all: it stays */
    }
}

/* Can this connection move now? Not with a send in flight (its buffers must
   stay put), nor while it's already waiting for a cancelled read. */
static bool can_migrate(const struct conn* c) {
    return c->wr.state != IO_PENDING && !c->kick_pending && !c->migrating && !c->shrink_wanted;
}

/* Hand a suspended connection to another reactor. Returns false (and leaves
   the connection untouched and still ours) if the target is shutting down. */
static bool migrate(struct reactor* from, struct conn* c, struct reactor* to) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed;
    pthread_mutex_unlock(&to->inbox_lock);
    if (!ok) return false;
    dlink_remove(&c->link);
    c->timer_moved = c->heap_idx >= 0;   /* the timer heap is per reactor */
    heap_remove(from, c);
    if (c->sub) atomic_store(&c->sub->owner, to);   /* new mail wakes the new owner */
    c->ready = 0;
    c->migrate_to = to;
    atomic_fetch_sub_explicit(&from->active, 1, memory_order_relaxed);
    if (c->rd.state == IO_PENDING) {
        c->migrating = true;
        from->nlimbo++;
        CancelIoEx((HANDLE)c->fd, &c->rd.ov);
        return true;
    }
    migrate_finish(from, c);
    return true;
}
#else
static bool can_migrate(const struct conn* c) { (void)c; return true; }

/* Hand a suspended connection to another reactor. Returns false (and leaves the
   connection untouched and still ours) if the target is shutting down. */
static bool migrate(struct reactor* from, struct conn* c, struct reactor* to) {
    pthread_mutex_lock(&to->inbox_lock);
    bool ok = !to->inbox_closed;
    if (ok) {
        epoll_ctl(from->ep, EPOLL_CTL_DEL, c->fd, NULL);
        dlink_remove(&c->link);
        c->timer_moved = c->heap_idx >= 0;   /* the timer heap is per reactor */
        heap_remove(from, c);
        if (c->sub) atomic_store(&c->sub->owner, to);   /* new mail wakes the new owner */
        c->ready = 0;                   /* level-triggered: the new epoll set re-reports */
        c->inbox_next = to->inbox;
        to->inbox = c;
    }
    pthread_mutex_unlock(&to->inbox_lock);
    /* From here on, c belongs to `to` and must not be touched. */
    if (ok) {
        atomic_fetch_sub_explicit(&from->active, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&from->migrated_out, 1, memory_order_relaxed);
        reactor_notify(to, NOTE_INBOX);
    }
    return ok;
}
#endif

/* An idle keep-alive connection gives back a grown input buffer. On Windows a
   read is posted into it, so that is cancelled first and io_done() shrinks
   the buffer when the cancellation completes. */
static void in_release_idle(struct conn* c) {
#ifdef _WIN32
    if (c->in != c->in_small && c->rd.state == IO_PENDING && !c->rd.probe
        && c->in_off == c->in_len && !c->shrink_wanted) {
        c->shrink_wanted = true;
        CancelIoEx((HANDLE)c->fd, &c->rd.ov);
        return;
    }
#endif
    in_shrink(c);
}

/* Once per window: publish our load, and if we're clearly the hot spot, move
   our heaviest connections to the least loaded reactor. */
static void rebalance_tick(struct reactor* r) {
    int64_t wall = now_ns(), cpu = thread_cpu_ns();
    int64_t window = wall - r->tick_wall_ns;
    int load = window > 0 ? (int)((cpu - r->tick_cpu_ns) * 1000 / window) : 0;
    r->tick_wall_ns = wall;
    r->tick_cpu_ns = cpu;
    atomic_store_explicit(&r->load_pm, load, memory_order_relaxed);

    /* Find the least loaded peer. */
    struct reactor* target = NULL;
    int tload = INT_MAX;
    for (int i = 0; i < g_nreactors; ++i) {
        if (&g_reactors[i] == r) continue;
        int l = atomic_load_explicit(&g_reactors[i].load_pm, memory_order_relaxed);
        if (l < tload) { tload = l; target = &g_reactors[i]; }
    }
    int gap = target ? load - tload : 0;
    bool act = target && load >= (int)(MIN_LOAD * 1000) && gap >= (int)(MIN_GAP * 1000);

    /* One pass over our connections: reset every window counter, and keep the
       heaviest movable connections in cand[] sorted by weight, descending. */
    struct conn* cand[MAX_MIGRATE];
    int64_t weight[MAX_MIGRATE];
    int ncand = 0;
    for (dlink* p = r->live.next; p != &r->live; p = p->next) {
        struct conn* c = conn_of(p);
        int64_t w = c->win_ns;
        c->win_ns = 0;
        if (!act || w <= 0 || r->now - c->settled_at < COOLDOWN_MS || !can_migrate(c)) continue;
        if (ncand == MAX_MIGRATE) {
            if (w <= weight[ncand - 1]) continue;       /* lighter than all kept */
            --ncand;                                    /* drop the lightest */
        }
        int j = ncand++;
        while (j > 0 && weight[j - 1] < w) {
            cand[j] = cand[j - 1];
            weight[j] = weight[j - 1];
            --j;
        }
        cand[j] = c;
        weight[j] = w;
    }
    if (!act) return;

    /* Greedy: move heaviest first until we've shifted about half the gap. A
       connection bigger than the budget is still worth moving if it's the
       first one and smaller than the whole gap (it still narrows the gap). */
    int budget = gap / 2, moved = 0, nmoved = 0;
    for (int i = 0; i < ncand && moved < budget; ++i) {
        int share = (int)(weight[i] * 1000 / window);   /* per mille of a core */
        if (share <= budget - moved || (nmoved == 0 && share < gap)) {
            if (!migrate(r, cand[i], target)) break;    /* target shutting down */
            moved += share;
            ++nmoved;
        }
    }
    if (moved > 0) {
        /* Pre-adjust published loads so other reactors don't pile onto the
           same target before the next measurement. */
        atomic_fetch_add_explicit(&target->load_pm, moved, memory_order_relaxed);
        atomic_fetch_sub_explicit(&r->load_pm, moved, memory_order_relaxed);
    }
}
