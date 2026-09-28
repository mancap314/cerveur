/*
 * src/http.c - HTTP: parser callbacks, request accessors, response writing and formatting, router, timers.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* llhttp callbacks: copy the request head into the context's arena, and    */
/* route body bytes according to the body mode                              */
/* ======================================================================== */

static http_ctx* parser_ctx(llhttp_t* p) { return ((struct conn*)p->data)->x; }

static int arena_append(http_ctx* x, const char* at, size_t n) {
    if (x->arena_len + n > HDR_ARENA) { x->err = 431; return -1; }
    memcpy(x->arena + x->arena_len, at, n);
    x->arena_len += (int)n;
    return 0;
}

static int on_url(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (!x->target.ptr) x->target.ptr = x->arena + x->arena_len;
    if (arena_append(x, at, n) < 0) return -1;
    x->target.len += n;
    return 0;
}

static int on_header_field(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (x->hstate != 1) {                       /* a new header begins */
        if (x->nheaders == MAX_HEADERS) { x->err = 431; return -1; }
        http_header* h = &x->headers[x->nheaders++];
        h->name = (http_str){x->arena + x->arena_len, 0};
        h->value = (http_str){"", 0};
        x->hstate = 1;
    }
    if (arena_append(x, at, n) < 0) return -1;
    x->headers[x->nheaders - 1].name.len += n;
    return 0;
}

static int on_header_value(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    http_header* h = &x->headers[x->nheaders - 1];
    if (x->hstate != 2) {
        h->value = (http_str){x->arena + x->arena_len, 0};
        x->hstate = 2;
    }
    if (arena_append(x, at, n) < 0) return -1;
    h->value.len += n;
    return 0;
}

static int on_headers_complete(llhttp_t* p) {
    http_ctx* x = parser_ctx(p);
    const char* m = llhttp_method_name((llhttp_method_t)llhttp_get_method(p));
    x->method = (http_str){m, strlen(m)};
    x->version_major = llhttp_get_http_major(p);
    x->version_minor = llhttp_get_http_minor(p);
    if (!x->target.ptr) x->target = (http_str){"/", 1};
    const char* q = memchr(x->target.ptr, '?', x->target.len);
    x->path = (http_str){x->target.ptr, q ? (size_t)(q - x->target.ptr) : x->target.len};
    x->query = q ? (http_str){q + 1, x->target.len - x->path.len - 1} : (http_str){"", 0};
    x->content_length = (p->flags & F_CONTENT_LENGTH) ? (int64_t)p->content_length : -1;
    x->chunked = (p->flags & F_CHUNKED) != 0;
    x->keep_alive = llhttp_should_keep_alive(p);
    x->is_head = http_str_eq(x->method, "HEAD");
    http_str ex = http_header_get(x, "expect");
    x->expect_continue = ex.len == 12 && strncasecmp(ex.ptr, "100-continue", 12) == 0;
    x->head_done = true;
    return HPE_PAUSED;          /* stop here: route before touching the body */
}

static int on_body(llhttp_t* p, const char* at, size_t n) {
    http_ctx* x = parser_ctx(p);
    if (n == 0) return 0;       /* llhttp reports empty spans when resumed without input */
    switch (x->body_mode) {
    case BODY_STREAM:
        x->chunk = (http_str){at, n};           /* zero-copy: points into conn->in */
        return HPE_PAUSED;                      /* hold parsing until it's taken */
    case BODY_BUFFER:
        if (x->body_len + n > x->body_limit) { x->err = 413; return -1; }
        if (x->body_len + n > x->body_cap) {
            size_t cap = x->body_cap ? x->body_cap * 2 : 4096;
            while (cap < x->body_len + n) cap *= 2;
            if (cap > x->body_limit) cap = x->body_limit;
            char* b = realloc(x->body, cap);
            if (!b) { x->err = 500; return -1; }
            x->body = b;
            x->body_cap = cap;
        }
        memcpy(x->body + x->body_len, at, n);
        x->body_len += n;
        return 0;
    default:                                    /* BODY_DISCARD */
        x->discarded += n;
        if (x->discarded > MAX_DRAIN) { x->close = true; return -1; }
        return 0;
    }
}

static int on_message_complete(llhttp_t* p) {
    parser_ctx(p)->msg_done = true;
    return HPE_PAUSED;          /* don't start parsing a pipelined request yet */
}

/* ---- Input ---- */

/* Parse buffered input. Returns 0, or -1 on a protocol error (x->err set). */
static int feed(struct conn* c) {
    http_ctx* x = c->x;
    const char* start = c->in + c->in_off;
    llhttp_errno_t e = llhttp_execute(&c->parser, start, (size_t)(c->in_len - c->in_off));
    if (e == HPE_OK) {
        c->in_off = c->in_len;
        c->paused = false;
    } else if (e == HPE_PAUSED) {
        c->in_off = (int)(llhttp_get_error_pos(&c->parser) - c->in);
        llhttp_resume(&c->parser);
        c->paused = true;       /* a zero-byte feed may still make progress */
    } else {
        if (!x->err) x->err = 400;              /* HPE_USER keeps our own status */
        x->close = true;
        return -1;
    }
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
    return 0;
}

/* The input buffer starts as the 16 KiB one inside the connection. A read that
   fills it completely means more is waiting (a large body, a busy WebSocket),
   so it grows to IN_BIG_CAP: each recv() then moves 4x as much, and streaming
   handlers are resumed 4x less often, which matters most on Windows where each
   socket call costs more. It shrinks back once the connection sits idle
   between requests (in_shrink), so idle keep-alive connections stay small. */
static void in_grow(struct conn* c) {
    char* big = malloc(IN_BIG_CAP);
    if (!big) return;                           /* keep working with the small one */
    memcpy(big, c->in, (size_t)c->in_len);
    c->in = big;
    c->in_cap = IN_BIG_CAP;
}

static void in_shrink(struct conn* c) {
    if (c->in == c->in_small || c->in_len - c->in_off > IN_CAP || in_busy(c)) return;
    memcpy(c->in_small, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
    free(c->in);
    c->in = c->in_small;
    c->in_cap = IN_CAP;
    c->in_len -= c->in_off;
    c->in_off = 0;
}

#ifdef _WIN32
/* Post an overlapped read into the free end of `in`: the data lands in place,
   with no copy and no separate recv(). Leaves rd PENDING, or DONE if it
   completed at once (data was already waiting).
   A probe reads zero bytes instead: it only tells a connection that isn't
   reading that data or a close arrived, and never writes into `in` (a
   handler may still hold a body chunk pointing into it). */
static void rd_post(struct conn* c, bool probe) {
    struct io_op* op = &c->rd;
    memset(&op->ov, 0, sizeof op->ov);
    static char none;
    WSABUF b = probe ? (WSABUF){0, &none} : (WSABUF){(ULONG)(c->in_cap - c->in_len), c->in + c->in_len};
    DWORD n = 0, flags = 0;
    IOSTAT(c->r, IO_RECV, 1);
    int rc = WSARecv(c->fd, &b, 1, &n, &flags, &op->ov, NULL);
    op->cancelled = false;
    op->probe = probe;
    if (!probe) c->probe_seen = false;
    if (rc == 0 && c->skip) {
        op->state = IO_DONE;
        op->bytes = n;
        op->failed = false;
    } else if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) {
        op->state = IO_PENDING;                 /* a completion will follow */
        IOSTAT(c->r, IO_RECV_EMPTY, 1);
    } else {
        op->state = IO_DONE;
        op->bytes = 0;
        op->failed = true;
    }
}

/* Take a completed read's result, like recv(): bytes, or -1 on EOF or error. */
static int rd_take(struct conn* c) {
    struct io_op* op = &c->rd;
    op->state = IO_IDLE;
    if (op->failed || op->bytes == 0) return -1;
    c->in_len += (int)op->bytes;
    c->last_rx = c->r->now;
    if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
    return (int)op->bytes;
}

/* The event bits a completed read stands for. */
static uint32_t rd_bits(const struct conn* c) {
    return c->rd.failed ? EPOLLIN | EPOLLERR | EPOLLHUP : c->rd.bytes ? EPOLLIN : EPOLLIN | EPOLLRDHUP;
}

/* A probe completed: data waiting, the peer closed, or an error? (A zero-byte
   read completes the same way for data and for a close, so peek.) Returns the
   event bits, 0 if it was spurious; the read slot is free again either way. */
static uint32_t probe_result(struct conn* c) {
    c->rd.state = IO_IDLE;
    uint32_t bits;
    if (c->rd.failed) {
        bits = EPOLLIN | EPOLLERR | EPOLLHUP;
    } else {
        char b;
        int n = recv(c->fd, &b, 1, MSG_PEEK);
        bits = n > 0 ? EPOLLIN : n == 0 ? EPOLLIN | EPOLLRDHUP
             : WSAGetLastError() == WSAEWOULDBLOCK ? 0 : EPOLLIN | EPOLLERR | EPOLLHUP;
    }
    if (bits) c->probe_seen = true;     /* no new probe until it reads */
    return bits;
}
#endif

/* Read from the socket. Returns bytes read, 0 if nothing available (or no
   room), -1 on EOF or error. Only called when no stream chunk is outstanding,
   so compacting or growing the buffer can't invalidate a pointer a handler holds. */
static int fill(struct conn* c) {
#ifdef _WIN32
    if (c->rd.state == IO_PENDING) return 0;
    if (c->rd.state == IO_DONE) return rd_take(c);
#endif
    if (c->in_off > 0) {
        memmove(c->in, c->in + c->in_off, (size_t)(c->in_len - c->in_off));
        c->in_len -= c->in_off;
        c->in_off = 0;
    }
    if (c->in_len == c->in_cap) return 0;
#ifdef _WIN32
    rd_post(c, false);
    return c->rd.state == IO_DONE ? rd_take(c) : 0;
#else
    ssize_t n = sock_recv(c->fd, c->in + c->in_len, (size_t)(c->in_cap - c->in_len));
    IOSTAT(c->r, IO_RECV, 1);
    if (n > 0) {
        c->in_len += (int)n;
        c->last_rx = c->r->now;
        if (c->in_len == c->in_cap && c->in == c->in_small) in_grow(c);
        return (int)n;
    }
    if (n < 0 && would_block()) { IOSTAT(c->r, IO_RECV_EMPTY, 1); return 0; }
    return -1;
#endif
}

/* ======================================================================== */
/* Request accessors                                                        */
/* ======================================================================== */

http_str http_method(const http_ctx* x) { return x->method; }
http_str http_path(const http_ctx* x) { return x->path; }
http_str http_body(const http_ctx* x) { return (http_str){x->body ? x->body : "", x->body_len}; }

http_str http_header_get(const http_ctx* x, const char* name) {
    size_t n = strlen(name);
    for (int i = 0; i < x->nheaders; ++i)
        if (x->headers[i].name.len == n && strncasecmp(x->headers[i].name.ptr, name, n) == 0)
            return x->headers[i].value;
    return (http_str){NULL, 0};
}

http_str http_param(const http_ctx* x, const char* name) {
    for (int i = 0; i < x->nparams; ++i)
        if (http_str_eq(x->params[i].name, name)) return x->params[i].value;
    return (http_str){NULL, 0};
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Percent-decode src into dst (NUL-terminated). Returns length, or -1 if it
   doesn't fit. plus_is_space applies to query strings. */
static int url_decode(http_str src, char* dst, size_t cap, bool plus_is_space) {
    size_t j = 0;
    for (size_t i = 0; i < src.len; ++i) {
        char ch = src.ptr[i];
        if (ch == '%' && i + 2 < src.len
            && hexval(src.ptr[i + 1]) >= 0 && hexval(src.ptr[i + 2]) >= 0) {
            ch = (char)(hexval(src.ptr[i + 1]) * 16 + hexval(src.ptr[i + 2]));
            i += 2;
        } else if (ch == '+' && plus_is_space) {
            ch = ' ';
        }
        if (j + 1 >= cap) return -1;
        dst[j++] = ch;
    }
    if (cap) dst[j] = '\0';
    return (int)j;
}

/* Find query parameter `key`, decode its value into buf. */
bool http_query(const http_ctx* x, const char* key, char* buf, size_t cap) {
    size_t klen = strlen(key);
    const char* p = x->query.ptr;
    const char* end = p + x->query.len;
    while (p < end) {
        const char* amp = memchr(p, '&', (size_t)(end - p));
        const char* stop = amp ? amp : end;
        const char* eq = memchr(p, '=', (size_t)(stop - p));
        const char* kend = eq ? eq : stop;
        if ((size_t)(kend - p) == klen && memcmp(p, key, klen) == 0) {
            http_str v = eq ? (http_str){eq + 1, (size_t)(stop - eq - 1)} : (http_str){"", 0};
            return url_decode(v, buf, cap, true) >= 0;
        }
        p = stop + 1;
    }
    return false;
}

/* ---- Streaming request body ---- */

bool http_body_ready(http_ctx* x) {
    if (x->chunk.len > 0 || x->msg_done) return true;
    x->want_body = true;        /* tells the connection to read and parse more */
    return false;
}
bool http_body_done(const http_ctx* x) { return x->msg_done && x->chunk.len == 0; }
/* At most HTTP_SEND_MAX bytes at a time, so a chunk can always be passed
straight to http_send(); the rest stays for the next call. */
http_str http_body_take(http_ctx* x) {
    http_str s = x->chunk;
    if (s.len > HTTP_SEND_MAX) s.len = HTTP_SEND_MAX;
    x->chunk.ptr += s.len;
    x->chunk.len -= s.len;
    if (!x->chunk.len) x->chunk.ptr = NULL;
    return s;
}

/* ======================================================================== */
/* Response writing                                                         */
/* ======================================================================== */

static const char* reason_phrase(int s) {
    switch (s) {
    case 100: return "Continue";            case 101: return "Switching Protocols";
    case 200: return "OK";                  case 426: return "Upgrade Required";
    case 201: return "Created";             case 202: return "Accepted";
    case 204: return "No Content";          case 301: return "Moved Permanently";
    case 302: return "Found";               case 304: return "Not Modified";
    case 400: return "Bad Request";         case 401: return "Unauthorized";
    case 403: return "Forbidden";           case 404: return "Not Found";
    case 405: return "Method Not Allowed";  case 408: return "Request Timeout";
    case 409: return "Conflict";            case 413: return "Content Too Large";
    case 414: return "URI Too Long";        case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content"; case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

static const char* cached_date(struct reactor* r) {
    time_t t = time(NULL);
    if (t != r->date_sec) {
        struct tm tm;
        gmtime_r(&t, &tm);
        strftime(r->date, sizeof r->date, "%a, %d %b %Y %H:%M:%S GMT", &tm);
        r->date_sec = t;
    }
    return r->date;
}

/* ---- Formatting ----
   printf is the main cost of handlers that format their output: 40-75 ns a
   call on Windows, several times the cost of the work itself. So the *printf
   handler APIs and the response headers go through fmt_v(), which does the
   common conversions itself: %d %i %u %x %X %c %s and %%, with the l, ll and z
   length modifiers, the '-' and '0' flags, a field width, and a precision for
   %s (width and precision may be '*'). On anything else it starts over with
   vsnprintf, from a copy of the arguments taken on entry. Same result as
   vsnprintf: returns the full length, writes at most cap-1 characters and a NUL. */

typedef struct { char* p; size_t room, n; } fmt_out;    /* room: capacity minus the NUL */

static void fmt_put(fmt_out* o, const char* s, size_t len) {
    if (o->n < o->room) {
        size_t k = o->room - o->n;
        if (len < k) k = len;
        char* d = o->p + o->n;
        if (k <= 16) while (k--) *d++ = *s++;   /* most pieces are short: skip the call */
        else memcpy(d, s, k);
    }
    o->n += len;
}

static void fmt_pad(fmt_out* o, char c, size_t len) {
    if (o->n < o->room) {
        size_t k = o->room - o->n;
        memset(o->p + o->n, c, len < k ? len : k);
    }
    o->n += len;
}

static int fmt_v(char* buf, size_t cap, const char* f, va_list ap) {
    const char* start = f;
    va_list ap0;
    va_copy(ap0, ap);
    fmt_out o = {buf, cap ? cap - 1 : 0, 0};
    while (*f) {
        const char* lit = f;
        while (*f && *f != '%') ++f;
        if (f > lit) fmt_put(&o, lit, (size_t)(f - lit));
        if (!*f) break;
        if (*++f == '%') { fmt_put(&o, "%", 1); ++f; continue; }
        bool left = false, zero = false;
        for (;; ++f) {
            if (*f == '-') left = true;
            else if (*f == '0') zero = true;
            else break;
        }
        int width = 0, prec = -1;
        if (*f == '*') {
            width = va_arg(ap, int);
            if (width < 0) { left = true; width = width == INT_MIN ? INT_MAX : -width; }
            ++f;
        } else {
            while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        }
        bool has_prec = *f == '.';
        if (has_prec) {
            prec = 0;
            if (*++f == '*') { prec = va_arg(ap, int); ++f; }   /* negative: no precision */
            else while (*f >= '0' && *f <= '9') prec = prec * 10 + (*f++ - '0');
        }
        int size = 0;                                       /* 0 int, 1 long, 2 long long, 3 size_t */
        if (*f == 'l') { size = 1; if (*++f == 'l') { size = 2; ++f; } }
        else if (*f == 'z') { size = 3; ++f; }
        char conv = *f++;

        char tmp[24];
        const char* s;
        size_t n;
        bool neg = false;
        if (conv == 's' && size == 0) {
            s = va_arg(ap, const char*);
            if (!s) s = "(null)";
            if (prec >= 0) { const char* e = memchr(s, '\0', (size_t)prec); n = e ? (size_t)(e - s) : (size_t)prec; }
            else n = strlen(s);
            zero = false;
        } else if (conv == 'c' && size == 0 && !has_prec) {
            tmp[0] = (char)va_arg(ap, int);
            s = tmp;
            n = 1;
            zero = false;
        } else if ((conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x' || conv == 'X') && !has_prec) {
            unsigned long long v;
            if (conv == 'd' || conv == 'i') {
                long long sv = size == 0 ? va_arg(ap, int) : size == 1 ? va_arg(ap, long)
                             : size == 2 ? va_arg(ap, long long) : (long long)va_arg(ap, ptrdiff_t);
                neg = sv < 0;
                v = neg ? 0ULL - (unsigned long long)sv : (unsigned long long)sv;
            } else {
                v = size == 0 ? va_arg(ap, unsigned) : size == 1 ? va_arg(ap, unsigned long)
                  : size == 2 ? va_arg(ap, unsigned long long) : va_arg(ap, size_t);
            }
            char* e = tmp + sizeof tmp;
            char* d = e;
            if (conv == 'x' || conv == 'X') {       /* constant bases: shifts and multiplies */
                const char* digits = conv == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
                do *--d = digits[v & 15]; while ((v >>= 4));
            } else if (v <= UINT32_MAX) {           /* 32-bit division is cheaper still */
                uint32_t w = (uint32_t)v;
                do *--d = (char)('0' + w % 10); while ((w /= 10));
            } else {
                do *--d = (char)('0' + v % 10); while ((v /= 10));
            }
            s = d;
            n = (size_t)(e - d);
        } else {                                    /* not ours (or a stray '%' at the end) */
            int r = vsnprintf(buf, cap, start, ap0);
            va_end(ap0);
            return r;
        }
        size_t body = n + neg;
        size_t fill = (size_t)width > body ? (size_t)width - body : 0;
        if (!left && !zero) fmt_pad(&o, ' ', fill);
        if (neg) fmt_put(&o, "-", 1);
        if (!left && zero) fmt_pad(&o, '0', fill);
        fmt_put(&o, s, n);
        if (left) fmt_pad(&o, ' ', fill);
    }
    va_end(ap0);
    if (cap) buf[o.n < o.room ? o.n : o.room] = '\0';
    return o.n > INT_MAX ? INT_MAX : (int)o.n;
}

static int fmt_to(char* buf, size_t cap, const char* f, ...) PRINTF_LIKE(3, 4);
static int fmt_to(char* buf, size_t cap, const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = fmt_v(buf, cap, f, ap);
    va_end(ap);
    return n;
}

static void out_compact(http_ctx* x) {
    if (x->out_off == 0 || out_busy(x->c)) return;     /* the kernel is still reading it */
    memmove(x->out, x->out + x->out_off, (size_t)(x->out_len - x->out_off));
    if (x->open_chunk >= 0) x->open_chunk -= x->out_off;
    x->out_len -= x->out_off;
    x->out_off = 0;
}

void http_set_header(http_ctx* x, const char* name, const char* value) {
    if (x->head_sent) return;
    int n = fmt_to(x->xhdr + x->xhdr_len, sizeof x->xhdr - (size_t)x->xhdr_len,
                   "%s: %s\r\n", name, value);
    if (n > 0 && x->xhdr_len + n < (int)sizeof x->xhdr) x->xhdr_len += n;
}

/* Status line + headers. content_length < 0 means a streamed body. */
static void write_head(http_ctx* x, int status, const char* ctype, int64_t content_length) {
    if (x->head_sent) return;
    bool streamed = content_length < 0;
    x->chunked_out = streamed && (x->version_major > 1 || x->version_minor >= 1);
    if (streamed && !x->chunked_out) x->close = true;   /* HTTP/1.0: body ends at close */
    bool keep = x->keep_alive && !x->close;

    out_compact(x);
    char* p = x->out + x->out_len;
    size_t cap = OUT_CAP - (size_t)x->out_len;
    int n = fmt_to(p, cap, "HTTP/1.1 %d %s\r\nDate: %s\r\n", status, reason_phrase(status),
                   cached_date(x->c->r));
    if (ctype) n += fmt_to(p + n, cap - (size_t)n, "Content-Type: %s\r\n", ctype);
    if (streamed && ctype && strncmp(ctype, "text/event-stream", 17) == 0) {
        x->sse = true;          /* eligible for keepalive comments */
        n += fmt_to(p + n, cap - (size_t)n, "X-Accel-Buffering: no\r\n");   /* nginx: don't buffer */
    }
    if (!streamed)
        n += fmt_to(p + n, cap - (size_t)n, "Content-Length: %lld\r\n", (long long)content_length);
    else if (x->chunked_out)
        n += fmt_to(p + n, cap - (size_t)n, "Transfer-Encoding: chunked\r\n");
    if (!keep)
        n += fmt_to(p + n, cap - (size_t)n, "Connection: close\r\n");
    else if (x->version_minor == 0)
        n += fmt_to(p + n, cap - (size_t)n, "Connection: keep-alive\r\n");
    n += fmt_to(p + n, cap - (size_t)n, "%.*s\r\n", x->xhdr_len, x->xhdr);
    x->out_len += n;
    x->head_sent = true;
}

void http_respond(http_ctx* x, int status, const char* ctype, const void* body, size_t len) {
    if (x->head_sent) return;
    write_head(x, status, ctype, (int64_t)len);
    x->ended = true;
    if (x->is_head || len == 0) return;
    if (len <= OUT_CAP - (size_t)x->out_len) {
        memcpy(x->out + x->out_len, body, len);
        x->out_len += (int)len;
    } else {                                    /* too big for the buffer: keep a copy */
        x->ext = malloc(len);
        if (!x->ext) { x->close = true; return; }
        memcpy(x->ext, body, len);
        x->ext_len = len;
        x->ext_off = 0;
    }
}

void http_respondf(http_ctx* x, int status, const char* ctype, const char* fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
    http_respond(x, status, ctype, buf, (size_t)n);
}

void http_start(http_ctx* x, int status, const char* ctype) {
    write_head(x, status, ctype, -1);
}

/* Close the open chunk: fill in its reserved size field and add the CRLF. */
static void close_chunk(http_ctx* x) {
    if (x->open_chunk < 0) return;
    size_t size = (size_t)(x->out_len - x->open_chunk - 10);
    if (size == 0) {
        x->out_len = x->open_chunk;             /* nothing was written: drop the header */
    } else {
        char hdr[24];           /* size < OUT_CAP, so it always fits in 8 hex digits */
        fmt_to(hdr, sizeof hdr, "%08x\r\n", (unsigned)size);     /* leading zeros are valid */
        memcpy(x->out + x->open_chunk, hdr, 10);
        memcpy(x->out + x->out_len, "\r\n", 2);
        x->out_len += 2;
    }
    x->open_chunk = -1;
}

/* Queue body bytes. All-or-nothing: returns false (and asks the connection to
   flush) if they don't fit yet, so handlers write cco_await(http_send(...)).
   Consecutive sends between flushes are coalesced into one chunk. */
bool http_send(http_ctx* x, const void* data, size_t len) {
    if (!x->head_sent) http_start(x, 200, "application/octet-stream");
    if (x->ended || x->is_head || len == 0) return true;
    if (len > HTTP_SEND_MAX) len = HTTP_SEND_MAX;   /* contract violation: truncate */
    size_t need = len;
    if (x->chunked_out) need += (x->open_chunk < 0 ? 10 : 0) + 2 + 5;  /* size, CRLF, room for end */
    if (need > OUT_CAP - (size_t)x->out_len) out_compact(x);
    if (need > OUT_CAP - (size_t)x->out_len) {
        x->want_write = true;
        return false;
    }
    if (x->chunked_out && x->open_chunk < 0) {
        x->open_chunk = x->out_len;
        x->out_len += 10;
    }
    memcpy(x->out + x->out_len, data, len);
    x->out_len += (int)len;
    return true;
}

bool http_sendf(http_ctx* x, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return true;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
return http_send(x, buf, (size_t)n);
}

void http_end(http_ctx* x) {
    if (!x->head_sent) http_start(x, 200, "application/octet-stream");
    if (x->ended) return;
    x->ended = true;
    if (!x->chunked_out || x->is_head) return;
    close_chunk(x);
    if (5 > OUT_CAP - x->out_len) out_compact(x);
    memcpy(x->out + x->out_len, "0\r\n\r\n", 5);   /* space was reserved by http_send */
    x->out_len += 5;
}

#ifdef _WIN32
/* Largest single WSASend: an overlapped send completes only once all of it is
   handed over, and progress (last_tx) is only seen at completion, so a large
   body goes out in steps rather than as one multi-megabyte operation. */
#define SEND_STEP (256 * 1024)

/* Account for a completed write. -1 if it failed. */
static int wr_take(struct conn* c) {
    struct io_op* op = &c->wr;
    http_ctx* x = c->x;
    op->state = IO_IDLE;
    if (op->failed) return -1;
    size_t n = op->bytes, a = n < op->out_n ? n : op->out_n;
    x->out_off += (int)a;
    x->ext_off += n - a;
    if (n) {
        c->progress = true;
        c->last_tx = c->r->now;
        c->tx_total += n;
    }
    return 0;
}

/* Send what's queued: one overlapped WSASend covering x->out and x->ext.
   Returns 1 when everything went out, 0 while a send is in flight, -1 on
   error. Sets c->progress when bytes were handed over. */
static int flush(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return 1;
    for (;;) {
        if (c->wr.state == IO_PENDING) return 0;
        if (c->wr.state == IO_DONE && wr_take(c) < 0) return -1;
        close_chunk(x);
        size_t a = (size_t)(x->out_len - x->out_off), b = x->ext_len - x->ext_off;
        if (a + b == 0) break;
        if (a > SEND_STEP) a = SEND_STEP;
        if (b > SEND_STEP - a) b = SEND_STEP - a;
        WSABUF bufs[2];
        DWORD nb = 0, sent = 0;
        if (a) bufs[nb++] = (WSABUF){(ULONG)a, x->out + x->out_off};
        if (b) bufs[nb++] = (WSABUF){(ULONG)b, x->ext + x->ext_off};
        struct io_op* op = &c->wr;
        memset(&op->ov, 0, sizeof op->ov);
        op->out_n = a;
        op->cancelled = false;
        IOSTAT(c->r, IO_SEND, 1);
        int rc = WSASend(c->fd, bufs, nb, &sent, 0, &op->ov, NULL);
        if (rc == 0 && c->skip) {               /* done at once: account and go on */
            op->state = IO_DONE;
            op->bytes = sent;
            op->failed = false;
            continue;
        }
        if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) {
            op->state = IO_PENDING;
            IOSTAT(c->r, IO_SEND_FULL, 1);
            return 0;
        }
        return -1;
    }
    x->out_off = x->out_len = 0;
    if (x->ext) {
        free(x->ext);
        x->ext = NULL;
        x->ext_len = x->ext_off = 0;
    }
    return 1;
}
#else
/* Send buf[*off .. len). Returns 1 when all of it went out, 0 if the socket
   is full, -1 on error. Sets c->progress when any byte was written. */
static int send_from(struct conn* c, const char* buf, size_t len, size_t* off) {
    if (*off < len && c->tx_full) return 0;     /* until the reactor sees EPOLLOUT */
    while (*off < len) {
        size_t want = len - *off;
        ssize_t n = sock_send(c->fd, buf + *off, want);
        IOSTAT(c->r, IO_SEND, 1);
        if (n > 0) {
            *off += (size_t)n;
            c->progress = true;
            c->last_tx = c->r->now;
            c->tx_total += (uint64_t)n;
            /* A short write means the socket buffer just filled up: another
               send() now would only fail with EAGAIN, so wait for EPOLLOUT. */
            if ((size_t)n < want) IOSTAT(c->r, IO_SEND_SHORT, 1);
            if ((size_t)n < want && want <= INT_MAX) { c->tx_full = true; return 0; }
            continue;
        }
        if (n < 0 && would_block()) { IOSTAT(c->r, IO_SEND_FULL, 1); c->tx_full = true; return 0; }
        return -1;
    }
    return 1;
}

/* Send what's queued. Returns 1 when everything went out, 0 if the socket
   is full, -1 on error. Sets c->progress when any byte was written. */
static int flush(struct conn* c) {
    http_ctx* x = c->x;
    if (!x) return 1;
    close_chunk(x);
    size_t off = (size_t)x->out_off;
    int r = send_from(c, x->out, (size_t)x->out_len, &off);
    x->out_off = (int)off;
    if (r <= 0) return r;
    x->out_off = x->out_len = 0;
    r = send_from(c, x->ext, x->ext_len, &x->ext_off);
    if (r <= 0) return r;
    if (x->ext) {
        free(x->ext);
        x->ext = NULL;
        x->ext_len = x->ext_off = 0;
    }
    return 1;
}
#endif

static void respond_error(http_ctx* x) {
    const char* msg;
    switch (x->err) {
    case 404: msg = "not found\n"; break;
    case 405: msg = "method not allowed\n"; break;
    case 413: msg = "request body too large\n"; break;
    case 431: msg = "request headers too large\n"; break;
    case 426: msg = "this endpoint requires a WebSocket upgrade\n"; break;
    case 500: msg = "internal server error\n"; break;
    default:  msg = "bad request\n"; break;
    }
    if (!x->head_sent) {
        if (x->err != 405 && x->err != 426) x->xhdr_len = 0;  /* keep Allow / Upgrade headers */
        http_respond(x, x->err, "text/plain", msg, strlen(msg));
    } else {
        x->close = true;        /* a response was already under way: cut it off */
    }
}

/* ======================================================================== */
/* Router                                                                   */
/* ======================================================================== */

/* Match a pattern against x->path. ":name" matches one non-empty segment,
   "*name" (only at the end) matches the rest of the path. Parameters are
   percent-decoded into the arena. */
static bool match_pattern(http_ctx* x, const char* pat) {
    const char* p = x->path.ptr;
    const char* pend = p + x->path.len;
    x->nparams = 0;
    int arena_mark = x->arena_len;
    while (*pat) {
        if (*pat == ':' || *pat == '*') {
            bool rest = *pat == '*';
            const char* name = ++pat;
            while (*pat && *pat != '/') ++pat;
            const char* seg = p;
            if (rest) p = pend;
            else while (p < pend && *p != '/') ++p;
            if (!rest && p == seg) goto fail;   /* ":param" must not be empty */
            if (x->nparams == MAX_PARAMS) goto fail;
            int cap = HDR_ARENA - x->arena_len;
            int n = url_decode((http_str){seg, (size_t)(p - seg)}, x->arena + x->arena_len,
                               (size_t)cap, false);
            if (n < 0) goto fail;
            x->params[x->nparams].name = (http_str){name, (size_t)(pat - name)};
            x->params[x->nparams].value = (http_str){x->arena + x->arena_len, (size_t)n};
            x->nparams++;
            x->arena_len += n + 1;
            continue;
        }
        if (p == pend || *p != *pat) goto fail;
        ++p, ++pat;
    }
    if (p == pend) return true;
fail:
    x->nparams = 0;
    x->arena_len = arena_mark;
    return false;
}

static bool method_matches(const http_route* rt, const http_ctx* x) {
    if (!rt->method) return true;
    if (http_str_eq(x->method, rt->method)) return true;
    return x->is_head && strcmp(rt->method, "GET") == 0;
}

/* Pick the route and body mode, or set x->err. */
static void dispatch(http_ctx* x) {
    char allow[128] = "";
    size_t alen = 0;
    bool path_found = false;
    for (const http_route* rt = g_routes; rt->pattern; ++rt) {
        if (!match_pattern(x, rt->pattern)) continue;
        path_found = true;
        if (method_matches(rt, x)) { x->route = rt; break; }
        if (rt->method && alen + strlen(rt->method) + 3 < sizeof allow)
            alen += (size_t)snprintf(allow + alen, sizeof allow - alen, "%s%s", alen ? ", " : "", rt->method);
    }
    if (!x->route) {
        x->err = path_found ? 405 : 404;
        if (alen) http_set_header(x, "Allow", allow);
        x->body_mode = BODY_DISCARD;
        return;
    }
    bool has_body = x->content_length > 0 || x->chunked;
    if (x->route->websocket) {
        x->body_mode = BODY_DISCARD;
        if (has_body) { x->err = 400; x->close = true; }
        return;
    }
    if (x->route->stream) {
        x->body_mode = BODY_STREAM;
    } else {
        x->body_mode = BODY_BUFFER;
        x->body_limit = x->route->body_limit ? x->route->body_limit : DEFAULT_BODY_LIMIT;
        if (x->content_length > (int64_t)x->body_limit) {
            x->err = 413;                       /* reject before reading anything */
            x->close = true;                    /* the body isn't worth draining */
            x->body_mode = BODY_DISCARD;
            return;
        }
    }
    if (x->expect_continue && has_body) {       /* client is waiting for our go-ahead */
        static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
        memcpy(x->out + x->out_len, cont, sizeof cont - 1);
        x->out_len += (int)sizeof cont - 1;
        x->sent_continue = true;
    }
}

/* ======================================================================== */
/* Handler timers                                                           */
/* ======================================================================== */

void http_timer_start(http_ctx* x, http_timer* t, int64_t ms) {
    t->when = x->c->r->now + ms;
}
bool http_timer_expired(const http_ctx* x, const http_timer* t) {
    return x->c->r->now >= t->when;
}
bool http_timer_done(http_ctx* x, http_timer* t) {
    if (http_timer_expired(x, t)) return true;
    timer_arm(x->c, t->when);   /* wake the connection then */
    return false;
}
