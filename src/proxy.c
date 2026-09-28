/*
 * src/proxy.c - behind a proxy: client addresses, X-Forwarded-*, the PROXY protocol.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* Behind a proxy: client addresses and the PROXY protocol                  */
/* ======================================================================== */

static void ip_from_sockaddr(const struct sockaddr* sa, ipaddr* out) {
    memset(out, 0, sizeof *out);
    if (sa->sa_family == AF_INET6) {
        memcpy(out->b, &((const struct sockaddr_in6*)sa)->sin6_addr, 16);
    } else if (sa->sa_family == AF_INET) {      /* store as ::ffff:a.b.c.d */
        out->b[10] = out->b[11] = 0xFF;
        memcpy(out->b + 12, &((const struct sockaddr_in*)sa)->sin_addr, 4);
    }
}

static bool ip_is_v4(const ipaddr* a) {
    static const uint8_t prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
    return memcmp(a->b, prefix, 12) == 0;
}

static void ip_to_str(const ipaddr* a, char* buf, size_t cap) {
    if (ip_is_v4(a)) inet_ntop(AF_INET, a->b + 12, buf, (socklen_t)cap);
    else inet_ntop(AF_INET6, a->b, buf, (socklen_t)cap);
}

/* Parse "1.2.3.4", "1.2.3.4:80", "2001:db8::1", "[2001:db8::1]:443" (surrounding
   spaces allowed). Anything else ("unknown", junk) fails. */
static bool ip_parse(const char* s, size_t n, ipaddr* out) {
    while (n && (*s == ' ' || *s == '\t')) ++s, --n;
    while (n && (s[n-1] == ' ' || s[n-1] == '\t')) --n;
    char buf[64];
    if (n == 0 || n >= sizeof buf) return false;
    memcpy(buf, s, n);
    buf[n] = '\0';
    char* a = buf;
    if (*a == '[') {                            /* [v6] or [v6]:port */
        char* close = strchr(a, ']');
        if (!close) return false;
        *close = '\0';
        ++a;
    } else if (strchr(a, '.') && strchr(a, ':') && strchr(a, ':') == strrchr(a, ':')) {
        *strchr(a, ':') = '\0';                 /* v4:port */
    }
    memset(out, 0, sizeof *out);
    uint8_t v4[4];
    if (inet_pton(AF_INET, a, v4) == 1) {
        out->b[10] = out->b[11] = 0xFF;
        memcpy(out->b + 12, v4, 4);
        return true;
    }
    return inet_pton(AF_INET6, a, out->b) == 1;
}

/* "addr" or "addr/bits"; IPv4 prefixes are relative to the mapped form. */
static bool cidr_parse(const char* s, size_t n, cidr* out) {
    const char* slash = memchr(s, '/', n);
    if (!ip_parse(s, slash ? (size_t)(slash - s) : n, &out->net)) return false;
    int max = ip_is_v4(&out->net) ? 32 : 128;
    int bits = max;
    if (slash) {
        char buf[8];
        size_t bl = n - (size_t)(slash - s) - 1;
        if (bl == 0 || bl >= sizeof buf) return false;
        memcpy(buf, slash + 1, bl);
        buf[bl] = '\0';
        char* end;
        long v = strtol(buf, &end, 10);
        if (*end || v < 0 || v > max) return false;
        bits = (int)v;
    }
    out->bits = bits + (max == 32 ? 96 : 0);
    return true;
}

static bool ip_in(const ipaddr* a, const cidr* c) {
    int full = c->bits / 8, rest = c->bits % 8;
    if (memcmp(a->b, c->net.b, (size_t)full) != 0) return false;
    if (!rest) return true;
    uint8_t mask = (uint8_t)(0xFF << (8 - rest));
    return (a->b[full] & mask) == (c->net.b[full] & mask);
}

static bool ip_trusted(const ipaddr* a) {
    for (int i = 0; i < g_ntrusted; ++i)
        if (ip_in(a, &g_trusted[i])) return true;
    return false;
}

static bool header_name_is(const http_header* h, const char* name) {
    size_t n = strlen(name);
    return h->name.len == n && strncasecmp(h->name.ptr, name, n) == 0;
}

const char* http_client_ip(http_ctx* x) {
    if (x->client_ip[0]) return x->client_ip;
    ipaddr who = x->c->client;
    if (ip_trusted(&who)) {
        /* All X-Forwarded-For entries, in order (the header may repeat).
           Keep the rightmost 64: we walk from the right. */
        http_str ent[64];
        int n = 0;
        for (int i = 0; i < x->nheaders; ++i) {
            if (!header_name_is(&x->headers[i], "x-forwarded-for")) continue;
            const char* p = x->headers[i].value.ptr;
            const char* end = p + x->headers[i].value.len;
            while (p < end) {
                const char* comma = memchr(p, ',', (size_t)(end - p));
                const char* stop = comma ? comma : end;
                if (n == 64) { memmove(ent, ent + 1, sizeof ent - sizeof ent[0]); n = 63; }
                ent[n++] = (http_str){p, (size_t)(stop - p)};
                p = stop + 1;
            }
        }
        /* Right to left: each trusted hop vouches for the entry before it.
           Stop at the first untrusted address, which is the client. */
        for (int k = n - 1; k >= 0; --k) {
            ipaddr a;
            if (!ip_parse(ent[k].ptr, ent[k].len, &a)) break;   /* junk: keep the last good hop */
            who = a;
            if (!ip_trusted(&a)) break;
        }
    }
    ip_to_str(&who, x->client_ip, sizeof x->client_ip);
    return x->client_ip;
}

const char* http_scheme(http_ctx* x) {
    struct conn* c = x->c;
    if (c->client_tls) return "https";
    if (ip_trusted(&c->client)) {
        http_str p = http_header_get(x, "x-forwarded-proto");
        if (p.ptr) {
            size_t n = 0;
            while (n < p.len && p.ptr[n] != ',' && p.ptr[n] != ' ') ++n;
            if (n == 5 && strncasecmp(p.ptr, "https", 5) == 0) return "https";
        }
    }
    return "http";
}

/* Parse a PROXY protocol (v1 or v2) header at the start of the input.
   Returns 1 once parsed and consumed, 0 if more input is needed, -1 if invalid. */
static int proxy_header_parse(struct conn* c) {
    const uint8_t* p = (const uint8_t*)c->in + c->in_off;
    size_t n = (size_t)(c->in_len - c->in_off);
    static const uint8_t sig2[12] = {0x0D,0x0A,0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A};

    if (n && p[0] == 0x0D) {                                /* ---- v2 (binary) ---- */
        if (n < 16) return memcmp(p, sig2, n < 12 ? n : 12) ? -1 : 0;
        if (memcmp(p, sig2, 12) != 0) return -1;
        int ver = p[12] >> 4, cmd = p[12] & 0x0F, fam = p[13];
        size_t len = (size_t)p[14] << 8 | p[15];
        if (ver != 2 || cmd > 1) return -1;
        if (16 + len > IN_CAP) return -1;
        if (n < 16 + len) return 0;
        const uint8_t* a = p + 16;
        if (cmd == 1) {                                     /* PROXY (cmd 0 = LOCAL: keep the peer) */
            size_t off;
            ipaddr src;
            memset(&src, 0, sizeof src);
            if (fam == 0x11 || fam == 0x12) {               /* TCP/UDP over IPv4 */
                if (len < 12) return -1;
                src.b[10] = src.b[11] = 0xFF;
                memcpy(src.b + 12, a, 4);
                c->client = src;
                off = 12;
            } else if (fam == 0x21 || fam == 0x22) {        /* TCP/UDP over IPv6 */
                if (len < 36) return -1;
                memcpy(src.b, a, 16);
                c->client = src;
                off = 36;
            } else if (fam == 0x31 || fam == 0x32) {        /* unix sockets: no address */
                if (len < 216) return -1;
                off = 216;
            } else if (fam == 0x00) {
                off = 0;
            } else {
                return -1;
            }
            while (off + 3 <= len) {                        /* TLVs: look for "client used TLS" */
                int type = a[off];
                size_t tl = (size_t)a[off + 1] << 8 | a[off + 2];
                if (off + 3 + tl > len) return -1;
                if (type == 0x20 && tl >= 1 && (a[off + 3] & 0x01)) c->client_tls = true;
                off += 3 + tl;
            }
        }
        c->in_off += (int)(16 + len);
    } else {                                                /* ---- v1 (text) ---- */
        if (n < 6) return memcmp(p, "PROXY ", n) ? -1 : 0;
        if (memcmp(p, "PROXY ", 6) != 0) return -1;
        const uint8_t* eol = mem_find(p, n < 107 ? n : 107, "\r\n", 2);
        if (!eol) return n >= 107 ? -1 : 0;                 /* v1 lines are at most 107 bytes */
        char line[108], proto[8], src[64], dst[64];
        size_t ll = (size_t)(eol - p);
        memcpy(line, p, ll);
        line[ll] = '\0';
        unsigned sport, dport;
        ipaddr a;
        if (strncmp(line, "PROXY UNKNOWN", 13) == 0) {
            /* keep the peer address */
        } else if (sscanf(line, "PROXY %7s %63s %63s %u %u", proto, src, dst, &sport, &dport) == 5
                   && (strcmp(proto, "TCP4") == 0 || strcmp(proto, "TCP6") == 0)
                   && sport <= 65535 && dport <= 65535 && ip_parse(src, strlen(src), &a)) {
            c->client = a;
        } else {
            return -1;
        }
        c->in_off += (int)(ll + 2);
    }
    ip_to_str(&c->client, c->client_str, sizeof c->client_str);
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
    return 1;
}

/* The request context and a grown input buffer. Idempotent. */
static void conn_free_buffers(struct conn* c) {
    ctx_release(c);
    if (c->in != c->in_small) {
        free(c->in);
        c->in = c->in_small;
    }
}
