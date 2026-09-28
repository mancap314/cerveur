/*
 * src/websocket.c - WebSocket (RFC 6455): handshake, framing, handler API.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* WebSocket                                                                */
/* ======================================================================== */

/* ---- SHA-1 and base64, for the Sec-WebSocket-Accept header ---- */

static uint32_t rol32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t nblocks = (len + 1 + 8 + 63) / 64;
    for (size_t b = 0; b < nblocks; ++b) {
        uint8_t block[64];
        for (size_t i = 0; i < 64; ++i) {
            size_t idx = b * 64 + i;
            if (idx < len) block[i] = data[idx];
            else if (idx == len) block[i] = 0x80;
            else if (idx >= nblocks * 64 - 8)
                block[i] = (uint8_t)(((uint64_t)len * 8) >> (8 * (nblocks * 64 - 1 - idx)));
            else block[i] = 0;
        }
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)block[4*i] << 24 | (uint32_t)block[4*i+1] << 16 | (uint32_t)block[4*i+2] << 8 | block[4*i+3];
        for (int i = 16; i < 80; ++i) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (bb & c) | (~bb & d);           k = 0x5A827999; }
            else if (i < 40) { f = bb ^ c ^ d;                     k = 0x6ED9EBA1; }
            else if (i < 60) { f = (bb & c) | (bb & d) | (c & d);  k = 0x8F1BBCDC; }
            else             { f = bb ^ c ^ d;                     k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol32(bb, 30); bb = a; a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
    }
    for (int i = 0; i < 5; ++i) {
        out[4*i] = (uint8_t)(h[i] >> 24); out[4*i+1] = (uint8_t)(h[i] >> 16);
        out[4*i+2] = (uint8_t)(h[i] >> 8); out[4*i+3] = (uint8_t)h[i];
    }
}

static void base64_encode(const uint8_t* in, size_t n, char* out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i+1] << 8 : 0) | (i + 2 < n ? in[i+2] : 0);
        out[j++] = tbl[(v >> 18) & 63];
        out[j++] = tbl[(v >> 12) & 63];
        out[j++] = i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < n ? tbl[v & 63] : '=';
    }
    out[j] = '\0';
}

static bool utf8_valid(const uint8_t* s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c0 = s[i];
        if (c0 < 0x80) { ++i; continue; }
        size_t len;
        uint32_t cp, min;
        if ((c0 & 0xE0) == 0xC0)      { len = 2; cp = c0 & 0x1F; min = 0x80; }
        else if ((c0 & 0xF0) == 0xE0) { len = 3; cp = c0 & 0x0F; min = 0x800; }
        else if ((c0 & 0xF8) == 0xF0) { len = 4; cp = c0 & 0x07; min = 0x10000; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

/* Is `tok` one of the comma-separated tokens in v (case-insensitive)? */
static bool header_has_token(http_str v, const char* tok) {
    size_t tl = strlen(tok);
    if (!v.ptr) return false;                   /* header absent (NULL + 0 is undefined) */
    const char* p = v.ptr;
    const char* end = p + v.len;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) ++p;
        const char* q = p;
        while (q < end && *q != ',') ++q;
        const char* e = q;
        while (e > p && (e[-1] == ' ' || e[-1] == '\t')) --e;
        if ((size_t)(e - p) == tl && strncasecmp(p, tok, tl) == 0) return true;
        p = q;
    }
    return false;
}

/* Validate the upgrade request and queue the 101 response. Returns 0, or an
   HTTP status to reject with. */
static int ws_handshake(http_ctx* x) {
    if (!header_has_token(http_header_get(x, "upgrade"), "websocket") ||
        !header_has_token(http_header_get(x, "connection"), "upgrade")) {
        http_set_header(x, "Upgrade", "websocket");
        return 426;
    }
    if (!http_str_eq(x->method, "GET")) return 400;
    http_str ver = http_header_get(x, "sec-websocket-version");
    if (!ver.ptr || !(ver.len == 2 && memcmp(ver.ptr, "13", 2) == 0)) {
        http_set_header(x, "Sec-WebSocket-Version", "13");
        return 426;
    }
    http_str key = http_header_get(x, "sec-websocket-key");
    if (!key.ptr || key.len != 24) return 400;

    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t buf[24 + sizeof guid - 1], digest[20];
    memcpy(buf, key.ptr, 24);
    memcpy(buf + 24, guid, sizeof guid - 1);
    sha1(buf, sizeof buf, digest);
    char accept[32];
    base64_encode(digest, 20, accept);

    out_compact(x);
    x->out_len += fmt_to(x->out + x->out_len, OUT_CAP - (size_t)x->out_len,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    x->head_sent = x->ended = true;   /* the HTTP part is over */
    x->ws = true;
    x->close = true;                  /* no HTTP keep-alive after a WebSocket */
    return 0;
}

/* ---- Outgoing frames (server frames are never masked) ---- */

static size_t ws_frame_header(uint8_t* h, int op, size_t len) {
    h[0] = (uint8_t)(0x80 | op);
    if (len < 126) { h[1] = (uint8_t)len; return 2; }
    if (len <= 0xFFFF) { h[1] = 126; h[2] = (uint8_t)(len >> 8); h[3] = (uint8_t)len; return 4; }
    h[1] = 127;
    for (int i = 0; i < 8; ++i) h[2 + i] = (uint8_t)((uint64_t)len >> (56 - 8 * i));
    return 10;
}

/* Queue one frame. Frames go into the output buffer; a frame too large for
   it is sent from a heap copy, but only once nothing else is queued, so
   frames can't be reordered. Returns false if it must wait for a flush. */
static bool ws_put_frame(http_ctx* x, int op, const void* data, size_t len) {
    if (x->ext_off < x->ext_len) return false;          /* a large frame is still going out */
    uint8_t h[10];
    size_t hl = ws_frame_header(h, op, len);
    if (hl + len > OUT_CAP - (size_t)x->out_len) out_compact(x);
    if (hl + len <= OUT_CAP - (size_t)x->out_len) {
        memcpy(x->out + x->out_len, h, hl);
        if (len) memcpy(x->out + x->out_len + hl, data, len);
        x->out_len += (int)(hl + len);
        return true;
    }
    if (hl + len <= OUT_CAP || x->out_len > x->out_off) return false;   /* wait for room */
    char* copy = malloc(len);
    if (!copy) { x->ws_failed = true; x->close = true; return true; }
    memcpy(copy, data, len);
    x->ext = copy;
    x->ext_len = len;
    x->ext_off = 0;
    memcpy(x->out + x->out_len, h, hl);
    x->out_len += (int)hl;
    return true;
}

/* Emit pending control frames (pong, then close) when there's room. */
static void ws_queue_control(http_ctx* x) {
    if (x->ws_pong_pending && ws_put_frame(x, 0xA, x->ws_pong, (size_t)x->ws_pong_len))
        x->ws_pong_pending = false;
    if (x->ws_ping_due && !x->ws_close_queued && ws_put_frame(x, 0x9, "", 0))
        x->ws_ping_due = false;     /* keepalive ping requested by the reactor */
    if (x->ws_close_pending && !x->ws_pong_pending &&
        ws_put_frame(x, 0x8, x->ws_closebuf, (size_t)x->ws_close_len)) {
        x->ws_close_pending = false;
        x->ws_close_sent = true;
    }
}

static void ws_request_close(http_ctx* x, int code, const char* reason, size_t rlen) {
    if (x->ws_close_queued) return;
    x->ws_close_queued = x->ws_close_pending = true;
    size_t n = 0;
    if (code) {
        x->ws_closebuf[0] = (char)(code >> 8);
        x->ws_closebuf[1] = (char)(code & 0xFF);
        if (rlen > 123) rlen = 123;
        if (rlen) memcpy(x->ws_closebuf + 2, reason, rlen);
        n = 2 + rlen;
    }
    x->ws_close_len = (int)n;
    ws_queue_control(x);
}

/* Protocol violation: close with `code` and stop reading. */
static void ws_fail(http_ctx* x, int code) {
    x->ws_failed = true;
    if (!x->ws_close_code) x->ws_close_code = code;
    ws_request_close(x, code, NULL, 0);
}

static void ws_control(http_ctx* x, int op, const char* pl, size_t len) {
    if (op == 0x9) {                                    /* ping -> pong (latest wins) */
        if (x->ws_close_queued) return;
        memcpy(x->ws_pong, pl, len);
        x->ws_pong_len = (int)len;
        x->ws_pong_pending = true;
        ws_queue_control(x);
    } else if (op == 0x8) {                             /* close */
        int code = 1005;                                /* "no status received" */
        if (len == 1) { ws_fail(x, 1002); return; }
        if (len >= 2) {
            code = (uint8_t)pl[0] << 8 | (uint8_t)pl[1];
            bool valid = (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014)
                      || (code >= 3000 && code <= 4999);
            if (!valid) { ws_fail(x, 1002); return; }
            if (!utf8_valid((const uint8_t*)pl + 2, len - 2)) { ws_fail(x, 1007); return; }
        }
        x->ws_close_received = true;
        x->ws_close_code = code;
        ws_request_close(x, code == 1005 ? 0 : code, NULL, 0);   /* echo the code */
    }                                                   /* pong: nothing to do */
}

/* ---- Incoming frames: parse buffered input while the message slot is free ---- */

static void ws_parse(struct conn* c) {
    http_ctx* x = c->x;
    while (!x->ws_msg_ready && !x->ws_msg_held && !x->ws_close_received && !x->ws_failed) {
        size_t avail = (size_t)(c->in_len - c->in_off);
        const uint8_t* p = (const uint8_t*)c->in + c->in_off;

        if (x->ws_in_frame) {                           /* payload of a data frame */
            if (!avail && x->ws_frame_left) break;
            size_t n = avail < x->ws_frame_left ? avail : (size_t)x->ws_frame_left;
            if (n) {                                    /* (ws_msg is NULL until a payload arrives) */
                char* dst = x->ws_msg + x->ws_msg_len;
                for (size_t i = 0; i < n; ++i) dst[i] = (char)(p[i] ^ x->ws_mask[(x->ws_mask_pos + i) & 3]);
            }
            x->ws_mask_pos += n;
            x->ws_msg_len += n;
            x->ws_frame_left -= n;
            c->in_off += (int)n;
            if (x->ws_frame_left) break;
            x->ws_in_frame = false;
            if (x->ws_frame_fin) {
                x->ws_in_msg = false;
                if (x->ws_msg_op == WS_TEXT && !utf8_valid((const uint8_t*)x->ws_msg, x->ws_msg_len)) {
                    ws_fail(x, 1007);
                    break;
                }
                x->ws_msg_ready = true;
            }
            continue;
        }

        if (avail < 2) break;                           /* frame header */
        bool fin = p[0] & 0x80, masked = p[1] & 0x80;
        int rsv = p[0] & 0x70, op = p[0] & 0x0F;
        uint64_t len = p[1] & 0x7F;
        size_t hl = 2 + (len == 126 ? 2 : len == 127 ? 8 : 0) + 4;
        if (rsv || !masked) { ws_fail(x, 1002); break; }   /* no extensions; clients must mask */
        if (avail < hl) break;
        if (len == 126) len = (uint64_t)p[2] << 8 | p[3];
        else if (len == 127) {
            len = 0;
            for (int i = 0; i < 8; ++i) len = len << 8 | p[2 + i];
            if (len >> 63) { ws_fail(x, 1002); break; }
        }
        const uint8_t* mask = p + hl - 4;

        if (op >= 0x8) {                                /* control frame: whole, <= 125 bytes */
            if (!fin || len > 125 || op > 0xA) { ws_fail(x, 1002); break; }
            if (avail < hl + len) break;
            char pl[125];
            for (size_t i = 0; i < len; ++i) pl[i] = (char)(p[hl + i] ^ mask[i & 3]);
            c->in_off += (int)(hl + len);
            ws_control(x, op, pl, (size_t)len);
            continue;
        }
        /* data frame: text/binary starts a message, continuation extends it */
        if (op == 0 ? !x->ws_in_msg : (op > 2 || x->ws_in_msg)) { ws_fail(x, 1002); break; }
        if (op != 0) { x->ws_msg_op = op; x->ws_in_msg = true; x->ws_msg_len = 0; }
        if (x->ws_msg_len + len > WS_MAX_MSG) { ws_fail(x, 1009); break; }
        size_t need = x->ws_msg_len + (size_t)len;
        if (need > x->ws_msg_cap) {
            size_t cap = x->ws_msg_cap ? x->ws_msg_cap : 4096;
            while (cap < need) cap *= 2;
            if (cap > WS_MAX_MSG) cap = WS_MAX_MSG;
            char* m = realloc(x->ws_msg, cap);
            if (!m) { ws_fail(x, 1011); break; }
            x->ws_msg = m;
            x->ws_msg_cap = cap;
        }
        memcpy(x->ws_mask, mask, 4);
        x->ws_mask_pos = 0;
        x->ws_frame_left = len;
        x->ws_frame_fin = fin;
        x->ws_in_frame = true;
        c->in_off += (int)hl;
    }
    if (c->in_off == c->in_len && !in_busy(c)) c->in_off = c->in_len = 0;
}

/* ---- Handler API ---- */

bool ws_has_message(const http_ctx* x) { return x->ws_msg_ready; }
bool ws_closed(const http_ctx* x) {
    return !x->ws_msg_ready && (x->ws_close_received || x->ws_failed);
}
int ws_close_code(const http_ctx* x) { return x->ws_close_code ? x->ws_close_code : 1006; }

bool ws_recv_ready(http_ctx* x) {
    if (x->ws_msg_held) {                               /* release the previous message */
        x->ws_msg_held = false;
        x->ws_msg_len = 0;
    }
    if (x->ws_msg_ready || ws_closed(x)) return true;
    x->want_ws = true;
    return false;
}

ws_message ws_recv(http_ctx* x) {
    if (!x->ws_msg_ready) return (ws_message){0, "", 0};
    x->ws_msg_ready = false;
    x->ws_msg_held = true;
    return (ws_message){x->ws_msg_op, x->ws_msg ? x->ws_msg : "", x->ws_msg_len};
}

bool ws_send(http_ctx* x, int opcode, const void* data, size_t len) {
    if (x->ws_close_queued || x->ws_failed) return true;   /* closing: drop */
    ws_queue_control(x);                                /* control frames go first */
    if (!x->ws_pong_pending && ws_put_frame(x, opcode, data, len)) return true;
    x->want_write = true;
    return false;
}

bool ws_sendf(http_ctx* x, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = fmt_v(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return true;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
return ws_send(x, WS_TEXT, buf, (size_t)n);
}

void ws_close(http_ctx* x, int code, const char* reason) {
    ws_request_close(x, code, reason, reason ? strlen(reason) : 0);
}
