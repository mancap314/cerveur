/*
 * fuzz_main.h - standalone driver for the fuzz targets, for compilers without
 * libFuzzer (built with -DFUZZ_STANDALONE; include it at the end of a target).
 * SPDX-License-Identifier: MIT
 *
 * The target defines fuzz_seeds[] (example inputs) and fuzz_dict[] (tokens
 * worth inserting), written with FZ_SEED("...") so they may contain zero
 * bytes. The driver mutates random seeds for FUZZ_SECONDS seconds (default
 * 10) and feeds them to LLVMFuzzerTestOneInput(). Each input sits
 * right before an inaccessible page, so reading past its end crashes. On a
 * crash the input is saved as crash-<target>.bin; pass files as arguments to
 * replay them. `--write-seeds DIR` writes the seeds out as a libFuzzer corpus.
 */
#ifdef FUZZ_STANDALONE
#include <signal.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#define FZ_MAX 65536

static const uint8_t* fz_cur;
static size_t fz_cur_len;

static void fz_save(const char* path, const uint8_t* p, size_t n) {
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(p, 1, n, f); fclose(f); }
}

static void fz_on_crash(int sig) {
    fz_save("crash-" FUZZ_NAME ".bin", fz_cur, fz_cur_len);
    fprintf(stderr, "\n*** %s: signal %d; input saved as crash-" FUZZ_NAME ".bin (%zu bytes)\n",
            FUZZ_NAME, sig, fz_cur_len);
    _exit(1);
}

/* FZ_MAX bytes ending right before a page we can't access. */
static uint8_t* fz_guarded(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t pg = si.dwPageSize, span = (FZ_MAX + pg - 1) / pg * pg;
    uint8_t* b = VirtualAlloc(NULL, span + pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old;
    if (!b || !VirtualProtect(b + span, pg, PAGE_NOACCESS, &old)) abort();
#else
    size_t pg = (size_t)sysconf(_SC_PAGESIZE), span = (FZ_MAX + pg - 1) / pg * pg;
    uint8_t* b = mmap(NULL, span + pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b == MAP_FAILED || mprotect(b + span, pg, PROT_NONE) != 0) abort();
#endif
    return b + span;                            /* inputs are placed to end here */
}

static uint64_t fz_rng;
static uint32_t fz_rand(void) {
    fz_rng ^= fz_rng << 13; fz_rng ^= fz_rng >> 7; fz_rng ^= fz_rng << 17;
    return (uint32_t)(fz_rng >> 16);
}

static void fz_run(uint8_t* end, const uint8_t* p, size_t n) {
    uint8_t* in = end - n;                      /* flush against the guard page */
    memmove(in, p, n);
    fz_cur = in;
    fz_cur_len = n;
    LLVMFuzzerTestOneInput(in, n);
}

static size_t fz_mutate(uint8_t* b, size_t n) {
    int rounds = 1 + (int)(fz_rand() % 6);
    size_t nseeds = sizeof fuzz_seeds / sizeof fuzz_seeds[0], ndict = sizeof fuzz_dict / sizeof fuzz_dict[0];
    while (rounds--) {
        size_t at = n ? fz_rand() % (n + 1) : 0;
        switch (fz_rand() % 8) {
        case 0: if (n) b[fz_rand() % n] ^= (uint8_t)(1u << (fz_rand() % 8)); break;
        case 1: if (n) b[fz_rand() % n] = (uint8_t)fz_rand(); break;
        case 2: if (n < FZ_MAX) { memmove(b + at + 1, b + at, n - at); b[at] = (uint8_t)fz_rand(); ++n; } break;
        case 3: if (at < n) {                                       /* delete a few bytes */
                    size_t k = 1 + fz_rand() % 16;
                    if (k > n - at) k = n - at;
                    memmove(b + at, b + at + k, n - at - k);
                    n -= k;
                } break;
        case 4: if (n) {                                            /* duplicate a range */
                    uint8_t tmp[256];
                    size_t from = fz_rand() % n, k = 1 + fz_rand() % (n - from);
                    if (k > sizeof tmp) k = sizeof tmp;
                    if (n + k > FZ_MAX) break;
                    memcpy(tmp, b + from, k);
                    memmove(b + at + k, b + at, n - at);
                    memcpy(b + at, tmp, k);
                    n += k;
                } break;
        case 5: { size_t di = fz_rand() % ndict; const char* t = fuzz_dict[di].s; size_t k = fuzz_dict[di].n;
                  if (n + k <= FZ_MAX) { memmove(b + at + k, b + at, n - at); memcpy(b + at, t, k); n += k; } } break;
        case 6: { size_t si = fz_rand() % nseeds; const char* s = fuzz_seeds[si].s; size_t k = fuzz_seeds[si].n, from = k ? fz_rand() % k : 0;
                  k -= from; if (k > 64) k = 64; if (n + k <= FZ_MAX) { memmove(b + at + k, b + at, n - at); memcpy(b + at, s + from, k); n += k; } } break;
        case 7: { char num[24]; int k = snprintf(num, sizeof num, "%u", fz_rand() % 5 ? fz_rand() % 1000 : fz_rand());
                  if (n + (size_t)k <= FZ_MAX) { memmove(b + at + k, b + at, n - at); memcpy(b + at, num, (size_t)k); n += (size_t)k; } } break;
        }
    }
    return n;
}

int main(int argc, char** argv) {
    signal(SIGSEGV, fz_on_crash);
    signal(SIGILL, fz_on_crash);
    signal(SIGABRT, fz_on_crash);
    signal(SIGFPE, fz_on_crash);
    uint8_t* end = fz_guarded();
    static uint8_t buf[FZ_MAX];
    size_t nseeds = sizeof fuzz_seeds / sizeof fuzz_seeds[0];

    if (argc > 2 && strcmp(argv[1], "--write-seeds") == 0) {
        for (size_t i = 0; i < nseeds; ++i) {
            char path[1024];
            snprintf(path, sizeof path, "%s/seed-%zu", argv[2], i);
            fz_save(path, (const uint8_t*)fuzz_seeds[i].s, fuzz_seeds[i].n);
        }
        return 0;
    }
    if (argc > 1) {                             /* replay files */
        for (int i = 1; i < argc; ++i) {
            FILE* f = fopen(argv[i], "rb");
            if (!f) { perror(argv[i]); return 2; }
            size_t n = fread(buf, 1, FZ_MAX, f);
            fclose(f);
            fz_run(end, buf, n);
        }
        printf("%s: %d input(s) ran fine\n", FUZZ_NAME, argc - 1);
        return 0;
    }
    double secs = getenv("FUZZ_SECONDS") ? atof(getenv("FUZZ_SECONDS")) : 10;
    fz_rng = getenv("FUZZ_SEED") ? strtoull(getenv("FUZZ_SEED"), NULL, 10) : (uint64_t)time(NULL) * 2654435761u | 1;
    uint64_t seed = fz_rng;
    time_t stop = time(NULL) + (time_t)secs;
    long runs = 0;
    for (size_t i = 0; i < nseeds; ++i, ++runs)                     /* the seeds as they are */
        fz_run(end, (const uint8_t*)fuzz_seeds[i].s, fuzz_seeds[i].n);
    while (time(NULL) < stop) {
        for (int k = 0; k < 256; ++k, ++runs) {
            size_t si = fz_rand() % nseeds, n = fuzz_seeds[si].n;
            memcpy(buf, fuzz_seeds[si].s, n);
            n = fz_mutate(buf, n);
            fz_run(end, buf, n);
        }
    }
    printf("%s: %ld inputs in %.0f s, no crash (seed %llu)\n", FUZZ_NAME, runs, secs, (unsigned long long)seed);
    return 0;
}
#endif /* FUZZ_STANDALONE */
