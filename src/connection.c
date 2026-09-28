/*
 * src/connection.c - the connection coroutine: one request after another on a connection.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* Connection coroutine                                                     */
/* ======================================================================== */

/* After waking from a wait in a handler phase: did the peer go away?
   EPOLLRDHUP is reported once, then dropped from the interest set. */
static bool peer_gone(struct conn* c, bool request_complete) {
    if (c->ready & (EPOLLERR | EPOLLHUP)) return true;
    if (c->ready & EPOLLRDHUP) {
        c->rdhup = true;
        return request_complete;    /* nothing more should come: the client left */
    }
    return false;
}

/* Should the WebSocket loop read frames? Only while the message slot is free. */
static bool ws_reading(const http_ctx* x) {
    return !x->ws_msg_ready && !x->ws_msg_held && !x->ws_close_received && !x->ws_failed;
}

/* Start a streaming or WebSocket handler task. */
static bool task_start(struct conn* c, http_stream_fn fn) {
    c->task = calloc(1, c->x->route->task_size);
    if (!c->task) return false;
    c->task->x = c->x;
    c->task_fn = fn;
    return true;
}

/* Stop a handler that hasn't finished (runs its cco_finalize) and free it. */
static void task_end(struct conn* c) {
    if (!c->task) return;
    if (!cco_is_done(c->task)) {
        cco_stop(c->task);
        c->task_fn(c->task);
    }
    free(c->task);
    c->task = NULL;
    ps_release(c);              /* subscriptions end with the handler */
}

/* One loop iteration per request:
     1. read the request head (header timeout applies)
     2. route it
     3. run the handler: buffered (read body, call once), streaming (resume
        the handler coroutine, doing I/O on its behalf in between), or
        WebSocket (upgrade, then the same for frames)
     4. flush the response
     5. drain any unread request body so the connection can be reused
     6. keep-alive: next request; otherwise close
   It refers to its reactor only through c->r, so it keeps working unchanged
   after being migrated to another thread. */
static int conn_run(struct conn* c) {
    http_ctx* x = c->x;                         /* re-read on every resume */
    cco_async (c) {
        /* ---- 0. PROXY protocol header, if configured: only trusted peers,
               and it must arrive within TIMEOUT_MS ---- */
        if (g_proxy_protocol) {
            if (!ip_trusted(&c->peer)) cco_return;
            touch(c);
            for (;;) {
                int pr = proxy_header_parse(c);
                if (pr > 0) break;
                if (pr < 0 || c->eof) cco_return;
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
                if (fill(c) < 0) c->eof = true;
            }
        }

        for (;;) {
            /* ---- 1. Request head: must arrive within TIMEOUT_MS ---- */
            set_interest(c, EPOLLIN);
            touch(c);
            while (!(x && x->head_done)) {
                if (c->in_off < c->in_len) {
                    if (!x && !(x = c->x = ctx_acquire(c))) cco_return;
                    if (feed(c) < 0) break;             /* malformed: x->err set */
                    continue;
                }
                if (c->eof) cco_return;
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
                if (fill(c) < 0) c->eof = true;
            }
            atomic_fetch_add_explicit(&c->r->requests, 1, memory_order_relaxed);

            /* ---- 2. Route ---- */
            if (!x->err) dispatch(x);

            /* ---- 3. Handle ---- */
            if (x->err) {
                respond_error(x);
            } else if (x->body_mode == BODY_BUFFER) {
                /* Read the whole body (bounded by body_limit), then call once. */
                while (!x->msg_done && !x->err) {
                    if (c->in_off < c->in_len || c->paused) { feed(c); continue; }
                    if (c->eof) cco_return;
                    int fr = flush(c);                  /* e.g. a queued 100 Continue */
                    if (fr < 0) cco_return;
                    set_interest(c, fr ? EPOLLIN : EPOLLIN | EPOLLOUT);
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                    int n = fill(c);
                    if (n < 0) c->eof = true;
                    else if (n > 0) touch(c);
                }
                if (x->err) {
                    respond_error(x);
                } else {
                    x->route->handle(x);
                    if (!x->head_sent) { x->err = 500; respond_error(x); }
                }
            } else if (x->route->stream) {
                /* Streaming: resume the handler; whenever it waits, do the I/O
                   it's waiting for (parse more body, or flush output). Timers
                   wake it through c->woken. */
                if (!task_start(c, x->route->stream)) { x->err = 500; respond_error(x); goto flush_response; }
                for (;;) {
                    x->want_body = x->want_write = false;
                    if (c->task_fn(c->task) == cco_DONE) break;
                    if (x->sse_keepalive_due) {         /* idle SSE stream: send a comment */
                        x->sse_keepalive_due = false;   /* (only between fully sent events) */
                        if (x->out_off == x->out_len && x->ext_off == x->ext_len)
                            http_send(x, ": keepalive\n\n", 13);
                    }
                    c->progress = false;
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (x->want_body && x->chunk.len == 0 && !x->msg_done) {
                        if (c->in_off < c->in_len || c->paused) {
                            int before = c->in_len - c->in_off;
                            if (feed(c) < 0) break;     /* malformed body: x->err set */
                            /* progress only if input was consumed or something
                               changed; a no-op parse must fall through to recv */
                            if (c->in_len - c->in_off != before || x->chunk.len || x->msg_done)
                                c->progress = true;
                            else if (!c->eof && fill(c) != 0)
                                c->progress = true;
                        } else if (c->eof) {
                            cco_return;                 /* body truncated by the client */
                        } else {
                            int n = fill(c);
                            if (n != 0) c->progress = true;
                            if (n < 0) c->eof = true;
                        }
                    }
                    if (c->progress) { touch(c); continue; }
                    if (!x->want_body && fr == 1 && c->heap_idx < 0 && !ps_listening(c))
                        cco_return;                     /* waits on nothing */
                    set_interest(c, (x->want_body ? EPOLLIN : 0) | (fr ? 0 : EPOLLOUT)
                                    | (c->rdhup ? 0 : EPOLLRDHUP));
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out) cco_return;
                    if (peer_gone(c, x->msg_done)) cco_return;
                    c->ready = 0;
                    c->woken = false;
                }
                task_end(c);
                if (x->err) respond_error(x);
                else if (!x->head_sent) { x->err = 500; respond_error(x); }
                else if (!x->ended) http_end(x);
            } else {
                /* WebSocket: upgrade, then run the handler, reading frames
                   whenever the message slot is free (that's the backpressure),
                   answering pings and running the close handshake. */
                int st = ws_handshake(x);
                if (st) { x->err = st; x->close = true; respond_error(x); goto flush_response; }
                if (!task_start(c, x->route->websocket)) cco_return;
                for (;;) {
                    x->want_ws = x->want_write = false;
                    if (c->task_fn(c->task) == cco_DONE) break;
                    if (x->ws_failed || (x->ws_close_received && x->ws_close_sent)) break;
                    c->progress = false;
                    ws_queue_control(x);
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (ws_reading(x)) {
                        int before = c->in_len - c->in_off;
                        ws_parse(c);
                        if (c->in_len - c->in_off != before || x->ws_msg_ready || ws_closed(x)) {
                            c->progress = true;
                        } else if (c->eof) {
                            x->ws_failed = true;        /* dropped without a close frame */
                            x->ws_close_code = 1006;
                            c->progress = true;
                        } else {
                            int n = fill(c);
                            if (n != 0) c->progress = true;
                            if (n < 0) c->eof = true;
                        }
                    }
                    if (c->progress) { touch(c); continue; }
                    if (!ws_reading(x) && fr == 1 && c->heap_idx < 0 && !ps_listening(c)
                        && !x->ws_pong_pending && !x->ws_close_pending) cco_return;  /* waits on nothing */
                    set_interest(c, (ws_reading(x) ? EPOLLIN : 0) | (fr ? 0 : EPOLLOUT)
                                    | (c->rdhup || ws_reading(x) ? 0 : EPOLLRDHUP));
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out) cco_return;
                    /* locals don't survive the await, so re-derive from state */
                    if (peer_gone(c, true) && !ws_reading(x)) cco_return;
                    c->ready = 0;
                    c->woken = false;
                }
                task_end(c);
                /* Say goodbye (unless the peer vanished), then close the TCP connection. */
                if (!(c->eof && !x->ws_close_received)) ws_request_close(x, 1000, NULL, 0);
                for (;;) {
                    ws_queue_control(x);
                    int fr = flush(c);
                    if (fr < 0) cco_return;
                    if (fr == 1 && !x->ws_close_pending && !x->ws_pong_pending) break;
                    set_interest(c, EPOLLOUT);
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                }
                x->close = true;
            }

            /* ---- 4. Flush the response ---- */
            flush_response:
            for (;;) {
                c->progress = false;
                int fr = flush(c);
                if (fr < 0) cco_return;
                if (fr == 1) break;
                if (c->progress) touch(c);
                set_interest(c, EPOLLOUT);
                cco_await(c->ready || c->timed_out);
                if (c->timed_out) cco_return;
                c->ready = 0;
            }
            set_interest(c, EPOLLIN);

            /* ---- 5. Drain an unread body so the connection stays usable. If
                   we rejected an Expect: 100-continue request, the client never
                   sends it, so close instead. ---- */
            if (!x->msg_done && !x->close && !(x->expect_continue && !x->sent_continue)) {
                x->body_mode = BODY_DISCARD;
                x->chunk = (http_str){NULL, 0};
                while (!x->msg_done && !x->close) {
                    if (c->in_off < c->in_len || c->paused) { if (feed(c) < 0) break; continue; }
                    if (c->eof) cco_return;
                    cco_await(c->ready || c->timed_out);
                    if (c->timed_out) cco_return;
                    c->ready = 0;
                    int n = fill(c);
                    if (n < 0) c->eof = true;
                    else if (n > 0) touch(c);
                }
            }

            /* ---- 6. Keep-alive or close ---- */
            /* Input may still be arriving: an unread request body, or WebSocket
               frames when we closed first (e.g. 1009) and the peer hasn't sent
               its close frame yet. */
            c->linger = x->ws ? !x->ws_close_received : !x->msg_done;
            if (x->msg_done && x->keep_alive && !x->close) {
                ctx_release(c);
                x = NULL;
                c->served = true;       /* idle time now counts against --keepalive */
                continue;
            }
            ctx_release(c);
            x = NULL;

            /* Lingering close: if the client may still be sending (e.g. we
               answered 413 mid-upload), closing now would make the kernel
               reset the connection and the client might never read our
               response. Stop sending, discard input for up to LINGER_MS
               (bounded by LINGER_MAX bytes), then close. */
            if (c->linger && !c->eof) {
                shutdown(c->fd, SHUT_WR);
                timer_arm(c, c->r->now + LINGER_MS);
                set_interest(c, EPOLLIN);
                c->lingered = 0;
                for (;;) {
                    c->in_off = c->in_len;                  /* discard what's buffered */
                    if (!in_busy(c)) c->in_off = c->in_len = 0;
                    int n = fill(c);
                    if (n > 0) {
                        c->lingered += (size_t)n;
                        if (c->lingered > LINGER_MAX) break;
                        continue;
                    }
                    if (n < 0) break;
                    cco_await(c->ready || c->timed_out || c->woken);
                    if (c->timed_out || c->woken) break;
                    c->ready = 0;
                }
            }
            cco_return;
        }

        cco_finalize:                   /* runs on normal exit, cco_return, or cco_stop */
        task_end(c);                    /* interrupted mid-handler: let it clean up */
        if (c->x && c->x->ws && !c->x->ws_close_sent && !c->eof && !out_busy(c)
            && c->x->out_off == c->x->out_len && c->x->ext_off == c->x->ext_len) {
            /* Shutdown or timeout: tell the peer we're going away (best effort;
               only when no frame is half-sent, or this would corrupt it). */
            static const uint8_t going_away[] = {0x88, 2, 1001 >> 8, 1001 & 0xFF};
            if (sock_send(c->fd, going_away, sizeof going_away) < 0) { /* peer gone */ }
        }
        heap_remove(c->r, c);
        dlink_remove(&c->link);
        sock_close_polled(c->r->ep, c->fd);
        if (!io_busy(c)) conn_free_buffers(c);  /* else once its operations complete */
        atomic_fetch_sub_explicit(&c->r->active, 1, memory_order_relaxed);
    }
    return cco_DONE;
}
