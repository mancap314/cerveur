/*
 * src/platform.c - the OS layer: sockets, wake-ups, signals, threads (Linux and Windows).
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ---- Platform layer: sockets, wake-up handles, signals, threads ----
   Linux uses epoll, eventfd and SO_REUSEPORT directly. Windows uses an I/O
   completion port per reactor (see "Windows: I/O completion ports" in src/eventloop.c):
   reads and writes are overlapped WSARecv/WSASend straight into the
   connection's buffers, wake-ups are posted completion packets, and reactor 0
   accepts (AcceptEx) and deals new connections out round-robin through the
   other reactors' inboxes, as there is no SO_REUSEPORT. */
#ifdef _WIN32
typedef SOCKET sock_t;
typedef HANDLE poll_t;                      /* the reactor's completion port */
#define BAD_SOCK     INVALID_SOCKET
#define BAD_POLL     NULL
#define SHUT_WR      SD_SEND
#define poll_close   CloseHandle
/* The connection coroutine waits on these bits on both platforms; on Windows
   the reactor sets them from I/O completions. */
enum { EPOLLIN = 0x001, EPOLLOUT = 0x004, EPOLLERR = 0x008, EPOLLHUP = 0x010, EPOLLRDHUP = 0x2000 };
#define PRINTF_LIKE(f, a) HTTP_PRINTF(f, a)     /* from server.h: MinGW gcc checks C99 formats */

static struct tm* gmtime_r(const time_t* t, struct tm* out) { return gmtime_s(out, t) ? NULL : out; }

static ssize_t sock_send(sock_t s, const void* buf, size_t n) {
    return send(s, buf, n > INT_MAX ? INT_MAX : (int)n, 0);
}
static int sock_nonblock(sock_t s) { u_long on = 1; return ioctlsocket(s, FIONBIO, &on); }
static void sock_close(sock_t s) { closesocket(s); }
/* Pending overlapped operations complete (with an error) when the socket
   closes; the reactor waits for them before freeing the connection. */
static void sock_close_polled(poll_t ep, sock_t s) {
    (void)ep;
    closesocket(s);
}
/* Bytes handed to the kernel that the peer hasn't acknowledged yet (Linux's
   SIOCOUTQ), i.e. tx_total minus what was acknowledged. BytesOut counts
   retransmitted bytes too, including zero-window probes against a peer that
   has stopped reading, so those must not look like progress:
   acknowledged = BytesOut - BytesInFlight - BytesRetrans. -1 if unavailable. */
static int sock_outq(sock_t s, uint64_t tx_total) {
    DWORD ver = 0, got = 0;
    TCP_INFO_v0 ti;
    if (WSAIoctl(s, SIO_TCP_INFO, &ver, sizeof ver, &ti, sizeof ti, &got, NULL, NULL) != 0)
        return -1;
    int64_t acked = (int64_t)ti.BytesOut - (int64_t)ti.BytesInFlight - (int64_t)ti.BytesRetrans;
    int64_t q = (int64_t)tx_total - acked;
    return q < 0 ? 0 : q > INT_MAX ? INT_MAX : (int)q;
}

static int online_cpus(void) { return (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); }
static void pin_thread(pthread_t t, int cpu) {
    if (cpu < 64) SetThreadAffinityMask(pthread_gethandle(t), (DWORD_PTR)1 << cpu);
}
static void net_error(const char* what) {
    int e = WSAGetLastError();
    if (!e) { perror(what); return; }
    char msg[256] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)e, 0,
                   msg, sizeof msg, NULL);
    fprintf(stderr, "%s: winsock error %d: %s\n", what, e, msg);
}

/* Shutdown on Ctrl+C, Ctrl+Break or console close. */
static HANDLE g_stop_event;
static BOOL WINAPI on_console_ctrl(DWORD type) {
    (void)type;
    SetEvent(g_stop_event);
    return TRUE;
}
static void stop_signals_init(void) {
    g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);
}
static void stop_signals_wait(void) { WaitForSingleObject(g_stop_event, INFINITE); }

#else  /* Linux */
typedef int sock_t;
typedef int poll_t;
#define BAD_SOCK     (-1)
#define BAD_POLL     (-1)
#define poll_close   close
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))

static bool would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
static ssize_t sock_recv(sock_t s, void* buf, size_t n) { return recv(s, buf, n, 0); }
static ssize_t sock_send(sock_t s, const void* buf, size_t n) { return send(s, buf, n, MSG_NOSIGNAL); }
static void sock_close(sock_t s) { close(s); }
static sock_t sock_accept(sock_t l, struct sockaddr* sa, socklen_t* len) {
    sock_t s = accept4(l, sa, len, SOCK_NONBLOCK);
    int one = 1;
    if (s != BAD_SOCK) setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return s;
}
static void sock_close_polled(poll_t ep, sock_t s) {
    (void)ep;
    close(s);                       /* also removes it from the epoll set */
}
static int sock_outq(sock_t s, uint64_t tx_total) {
    (void)tx_total;
    int kq = 0;
    return ioctl(s, SIOCOUTQ, &kq) < 0 ? -1 : kq;
}

static sock_t notify_open(void) { return eventfd(0, EFD_NONBLOCK); }
static void notify_signal(sock_t fd) {
    uint64_t one = 1;
    if (write(fd, &one, sizeof one) < 0) { /* counter can't overflow here */ }
}
static void notify_drain(sock_t fd) {
    uint64_t v;
    if (read(fd, &v, sizeof v) < 0) { /* EAGAIN: nothing signalled */ }
}

static int online_cpus(void) { return (int)sysconf(_SC_NPROCESSORS_ONLN); }
static void pin_thread(pthread_t t, int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(t, sizeof set, &set);
}
static void net_error(const char* what) { perror(what); }

/* Block termination signals in every thread; main receives them via sigwait. */
static sigset_t g_stop_sigs;
static void stop_signals_init(void) {
    sigemptyset(&g_stop_sigs);
    sigaddset(&g_stop_sigs, SIGINT);
    sigaddset(&g_stop_sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &g_stop_sigs, NULL);
}
static void stop_signals_wait(void) {
    int sig;
    sigwait(&g_stop_sigs, &sig);
}
#endif

/* First occurrence of needle in hay (memmem isn't available everywhere). */
static const void* mem_find(const void* hay, size_t n, const void* needle, size_t m) {
    const char* h = hay;
    if (m == 0) return hay;
    for (size_t i = 0; i + m <= n; ++i)
        if (h[i] == *(const char*)needle && memcmp(h + i, needle, m) == 0) return h + i;
    return NULL;
}
