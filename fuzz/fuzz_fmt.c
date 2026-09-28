/*
 * fuzz_fmt.c - the server's formatter (fmt_v) against the C library's
 * vsnprintf: same output and return value for every format and buffer size.
 * SPDX-License-Identifier: MIT
 *
 * Input: bytes that pick a conversion (flags, width, precision, length
 * modifier, conversion, including the ones fmt_v hands to vsnprintf), its
 * argument, some literal text around it, and the buffer size. One conversion
 * per call, so the argument can always be passed with its correct type.
 */
#define FUZZ_NAME "fuzz_fmt"
#include "fuzz.h"

static int ref(char* b, size_t cap, const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = vsnprintf(b, cap, f, ap);
    va_end(ap);
    return n;
}

static int ours(char* b, size_t cap, const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = fmt_v(b, cap, f, ap);
    va_end(ap);
    return n;
}

static void check(const char* f, int n1, const char* b1, int n2, const char* b2, size_t cap) {
    if (n1 != n2 || (cap && memcmp(b1, b2, (size_t)(n1 < (int)cap ? n1 + 1 : (int)cap)) != 0)) {
        fprintf(stderr, "fmt mismatch for \"%s\" (cap %zu): vsnprintf %d \"%.*s\", fmt_v %d \"%.*s\"\n",
                f, cap, n1, (int)cap, b1, n2, (int)cap, b2);
        abort();
    }
}

/* Call both with the same (correctly typed) arguments and compare. */
#define BOTH(...) do { \
        memset(b1, 'W', sizeof b1); memset(b2, 'W', sizeof b2); \
        int n1 = ref(b1, cap, f, __VA_ARGS__), n2 = ours(b2, cap, f, __VA_ARGS__); \
        check(f, n1, b1, n2, b2, cap); \
    } while (0)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fz_init_common();
    if (size < 12) return 0;
    const uint8_t* d = data;
    size_t cap = d[0] % 96;                    /* 0 .. 95: every truncation point */
    static const char* const flags[] = {"", "-", "0", "-0", "+", " ", "#"};
    static const char* const lens[] = {"", "l", "ll", "z", "h"};
    static const char convs[] = "diuxXcsp%fe";
    const char* fl = flags[d[1] % 7];
    int star_w = d[2] & 1, star_p = d[2] & 2, has_p = d[2] & 4;
    int w = d[3] % 40, p = d[4] % 20;
    const char* len = lens[d[5] % 5];
    char conv = convs[d[6] % (sizeof convs - 1)];
    long long v = 0;
    memcpy(&v, d + 7, sizeof v < size - 7 ? sizeof v : size - 7);
    /* Keep to combinations the C standard defines, so vsnprintf is a reference:
       '#' only with x/X/f/e; '0' not with c/s/p; no precision with c/p; %% bare. */
    if (fl[0] == '#' && !strchr("xXfe", conv)) fl = "";
    if (strchr(fl, '0') && strchr("csp", conv)) fl = "-";
    if (strchr("cp", conv)) star_p = has_p = 0;
    if (conv == '%') { fl = ""; star_w = star_p = has_p = 0; w = 0; }
    int sw = (int)(int8_t)d[8] % 50, sp = (int)(int8_t)d[9] % 30;   /* '*' arguments, may be negative */

    char text[64];                              /* literal text and %s argument from the rest */
    size_t tn = size - 12 < sizeof text - 1 ? size - 12 : sizeof text - 1;
    for (size_t i = 0; i < tn; ++i) text[i] = d[12 + i] == '%' || !d[12 + i] ? '_' : (char)d[12 + i];
    text[tn] = '\0';

    char f[160];
    char prec[16] = "";
    if (star_p) snprintf(prec, sizeof prec, ".*");
    else if (has_p) snprintf(prec, sizeof prec, ".%d", p);
    char width[8] = "";
    if (star_w) snprintf(width, sizeof width, "*");
    else if (w) snprintf(width, sizeof width, "%d", w);
    if (conv == 'c' || conv == 's' || conv == 'p' || conv == '%' || conv == 'f' || conv == 'e') len = "";
    snprintf(f, sizeof f, "<%.10s%%%s%s%s%s%c%.10s>", text, fl, width, prec, len, conv, text + (tn > 10 ? tn - 10 : 0));

    static char b1[256], b2[256];
    char sarg[64];
    memcpy(sarg, text, tn + 1);
    const char* s = d[10] & 1 ? sarg : (d[10] & 2 ? NULL : "");
    if (!s && conv == 's') s = "";            /* NULL for %s is not defined by the C standard */

#define ARGS(...) \
    do { \
        if (star_w && star_p) BOTH(sw, sp, __VA_ARGS__); \
        else if (star_w) BOTH(sw, __VA_ARGS__); \
        else if (star_p) BOTH(sp, __VA_ARGS__); \
        else BOTH(__VA_ARGS__); \
    } while (0)

    int is_signed = conv == 'd' || conv == 'i';
    switch (conv) {
    case '%': BOTH(0); break;                   /* no argument (the 0 is ignored) */
    case 'c': ARGS((int)(v & 0x7f ? v & 0x7f : 'x')); break;
    case 's': ARGS(s); break;
    case 'p': ARGS((void*)(uintptr_t)v); break;
    case 'f': case 'e': ARGS((double)v / 7.0); break;
    default:
        if (!strcmp(len, "")) { if (is_signed) ARGS((int)v); else ARGS((unsigned)v); }
        else if (!strcmp(len, "l")) { if (is_signed) ARGS((long)v); else ARGS((unsigned long)v); }
        else if (!strcmp(len, "ll")) { if (is_signed) ARGS((long long)v); else ARGS((unsigned long long)v); }
        else if (!strcmp(len, "z")) { if (is_signed) ARGS((ptrdiff_t)v); else ARGS((size_t)v); }
        else { if (is_signed) ARGS((int)(short)v); else ARGS((int)(unsigned short)v); }     /* %h: promoted */
    }
    return 0;
}

static const fz_seed fuzz_seeds[] FZ_UNUSED = {
    FZ_SEED("\x40\x00\x00\x08\x00\x00\x00\x2a\x00\x00\x01\x00" "line text"),
    FZ_SEED("\x10\x02\x04\x10\x05\x02\x03\xff\xff\xff\xff\xff\xff\xff\x7f" "hello world"),
    FZ_SEED("\x05\x01\x03\x00\x00\x01\x08\x80\x00\x00\x00\x00\x00\x00\x80" "abc"),
    FZ_SEED("\x5f\x00\x04\x00\x03\x00\x07\x41\x42\x43\x44\x00\x01\x00" "abcdefgh"),
};
static const fz_seed fuzz_dict[] FZ_UNUSED = {
    FZ_SEED("\x00"), FZ_SEED("\xff"), FZ_SEED("\x7f"), FZ_SEED("\x80"), FZ_SEED("%"), FZ_SEED("abc"),
};
#include "fuzz_main.h"
