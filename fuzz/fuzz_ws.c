/*
 * fuzz_ws.c - WebSocket frames from a client, through the frame parser,
 * message reassembly, UTF-8 validation, control frames and the close
 * handshake. SPDX-License-Identifier: MIT
 *
 * Input: one control byte (how reads are split), then the bytes a client
 * sends after the upgrade.
 */
#define FUZZ_NAME "fuzz_ws"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fz_init_common();
    if (size < 1) return 0;
    size_t piece = 1 + (data[0] & 127);
    ++data, --size;
    struct conn* c = fz_conn();
    http_ctx* x = c->x = ctx_acquire(c);
    if (!x) return 0;
    x->ws = x->head_sent = x->ended = x->close = true;     /* as after the upgrade */
    for (;;) {
        int before = c->in_len - c->in_off;
        ws_parse(c);
        bool progress = c->in_len - c->in_off != before;
        if (x->ws_msg_ready) {                  /* the handler takes the message */
            ws_message m = ws_recv(x);
            if (m.len && m.data[0] == 0x7f) ws_close(x, 1000, "bye");
            (void)ws_recv_ready(x);
            progress = true;
        }
        ws_queue_control(x);                    /* pongs and close frames go out... */
        x->out_off = x->out_len = 0;            /* ... and we pretend they were sent */
        if (x->ws_failed || (x->ws_close_received && x->ws_close_sent)) break;
        if (progress) continue;
        if (!size) break;
        size_t k = fz_push(c, data, size < piece ? size : piece);
        if (!k) break;
        data += k, size -= k;
    }
    conn_free_buffers(c);
    return 0;
}

/* Client frames are masked; mask 00 00 00 00 keeps the payloads readable. */
static const fz_seed fuzz_seeds[] FZ_UNUSED = {
    FZ_SEED("\x10\x81\x85\x00\x00\x00\x00" "hello"),                            /* text */
    FZ_SEED("\x02\x82\x83\x00\x00\x00\x00\x01\x02\x03"),                        /* binary */
    FZ_SEED("\x04\x01\x83\x00\x00\x00\x00" "hel" "\x89\x80\x00\x00\x00\x00"     /* fragments, */
            "\x80\x82\x00\x00\x00\x00" "lo"),                                   /* ping between */
    FZ_SEED("\x7f\x88\x82\x00\x00\x00\x00\x03\xe8"),                            /* close 1000 */
    FZ_SEED("\x08\x81\xfe\x00\x05\x00\x00\x00\x00" "abcde"),                    /* 16-bit length */
    FZ_SEED("\x08\x82\xff\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00" "xyz"),  /* 64-bit length */
    FZ_SEED("\x01\x81\x82\x01\x02\x03\x04\xc3\xa9"),                            /* masked UTF-8 */
    FZ_SEED("\x05\x8a\x80\x00\x00\x00\x00"),                                    /* unsolicited pong */
};
static const fz_seed fuzz_dict[] FZ_UNUSED = {
    FZ_SEED("\x81"), FZ_SEED("\x82"), FZ_SEED("\x80"), FZ_SEED("\x01"), FZ_SEED("\x00"), FZ_SEED("\x88"),
    FZ_SEED("\x89"), FZ_SEED("\x8a"), FZ_SEED("\x7e"), FZ_SEED("\x7f"), FZ_SEED("\xfe"), FZ_SEED("\xff"),
    FZ_SEED("\x00\x00\x00\x00"), FZ_SEED("\xc3\xa9"), FZ_SEED("\xed\xa0\x80"), FZ_SEED("\xf4\x90\x80\x80"),
    FZ_SEED("\x03\xe8"), FZ_SEED("\x03\xed"),
};
#include "fuzz_main.h"
