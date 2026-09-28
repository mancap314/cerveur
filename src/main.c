/*
 * src/main.c - command line and http_server_main().
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* main                                                                     */
/* ======================================================================== */

static bool add_trusted(const char* list) {
    const char* p = list;
    while (*p) {
        const char* comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        if (n) {
            if (g_ntrusted == MAX_TRUSTED || !cidr_parse(p, n, &g_trusted[g_ntrusted])) {
                fprintf(stderr, "bad --trust-proxy entry: %.*s\n", (int)n, p);
                return false;
            }
            ++g_ntrusted;
        }
        p += n + (comma ? 1 : 0);
    }
    return true;
}

static void usage(const char* prog) {
    fprintf(stderr,
        "usage: %s [options] [port] [threads]\n"
        "  --bind=ADDR          listen address (default 0.0.0.0; 127.0.0.1 behind a local proxy)\n"
        "  --keepalive=MS       idle keep-alive between requests (default %d, min %d)\n"
        "  --trust-proxy=LIST   proxies allowed to set X-Forwarded-* / send PROXY headers,\n"
        "                       e.g. 127.0.0.1,::1,10.0.0.0/8\n"
        "  --proxy-protocol     expect a PROXY v1/v2 header on every connection\n",
        prog, DEFAULT_KEEPALIVE_MS, TIMEOUT_MS);
}

int http_server_main(int argc, char* argv[], const http_route* routes) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { fprintf(stderr, "WSAStartup failed\n"); return 1; }
    iocp_init();
#endif
    static const struct option opts[] = {
        {"bind",           required_argument, 0, 'b'},
        {"keepalive",      required_argument, 0, 'k'},
        {"trust-proxy",    required_argument, 0, 't'},
        {"proxy-protocol", no_argument,       0, 'p'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };
    for (int ch; (ch = getopt_long(argc, argv, "", opts, NULL)) != -1; ) {
        switch (ch) {
        case 'b': g_bind = optarg; break;
        case 'k': g_keepalive_ms = atoi(optarg); break;
        case 't': if (!add_trusted(optarg)) return 2; break;
        case 'p': g_proxy_protocol = true; break;
        default:  usage(argv[0]); return ch == 'h' ? 0 : 2;
        }
    }
    if (g_keepalive_ms < TIMEOUT_MS) g_keepalive_ms = TIMEOUT_MS;   /* checked at that granularity */
    /* PROXY protocol without --trust-proxy: trust a local proxy only. Exactly
       the addresses it connects from, not all of 127/8: anything in the
       trusted set may also vouch for X-Forwarded-For entries. */
    if (g_proxy_protocol && g_ntrusted == 0) add_trusted("127.0.0.1,::1");

    int port = optind < argc ? atoi(argv[optind]) : 8080;
    int ncpu = online_cpus();
    int nthreads = optind + 1 < argc ? atoi(argv[optind + 1]) : (ncpu > 0 ? ncpu : 1);
    if (nthreads < 1) nthreads = 1;

    stop_signals_init();        /* before starting threads, so they inherit the signal mask */

    llhttp_settings_init(&g_parser_settings);
    g_parser_settings.on_url = on_url;
    g_parser_settings.on_header_field = on_header_field;
    g_parser_settings.on_header_value = on_header_value;
    g_parser_settings.on_headers_complete = on_headers_complete;
    g_parser_settings.on_body = on_body;
    g_parser_settings.on_message_complete = on_message_complete;
    g_routes = routes;

    g_nreactors = nthreads;
    g_reactors = calloc((size_t)nthreads, sizeof *g_reactors);
    if (!g_reactors) { perror("calloc"); return 1; }

    /* Open all listeners before starting threads, so a bind error fails fast. */
    for (int i = 0; i < nthreads; ++i) {
        struct reactor* r = &g_reactors[i];
        r->id = i;
        r->port = port;
        if (reactor_open(r) < 0) { net_error("reactor setup (socket/bind/listen)"); return 1; }
    }

    for (int i = 0; i < nthreads; ++i) {
        struct reactor* r = &g_reactors[i];
        if (pthread_create(&r->thread, NULL, reactor_run, r) != 0) {
            perror("pthread_create");
            return 1;
        }
        if (nthreads <= ncpu) pin_thread(r->thread, i);   /* reactor i on CPU i */
    }

    printf("listening on %s port %d with %d reactor thread(s)%s%s, %d trusted prox%s\n",
           g_bind, port, nthreads, nthreads > 1 ? ", rebalancing on" : "",
           g_proxy_protocol ? ", PROXY protocol" : "", g_ntrusted, g_ntrusted == 1 ? "y" : "ies");
    fflush(stdout);

    stop_signals_wait();

    int active = 0;
    for (int i = 0; i < nthreads; ++i)
        active += atomic_load(&g_reactors[i].active);
    printf("\nshutting down, closing %d connection(s)...\n", active);

    for (int i = 0; i < nthreads; ++i)
        reactor_notify(&g_reactors[i], NOTE_STOP);
    for (int i = 0; i < nthreads; ++i)
        pthread_join(g_reactors[i].thread, NULL);
    for (int i = 0; i < nthreads; ++i) {             /* close after join: others wrote to them */
        struct reactor* r = &g_reactors[i];
#ifndef _WIN32
        sock_close(r->wakefd);
        sock_close(r->inboxfd);
        sock_close(r->psfd);
#endif
        pthread_mutex_destroy(&r->inbox_lock);
        /* wake-ups posted after a reactor stopped: just drop their references */
        for (int k = 0; k < r->nwq; ++k) ps_sub_unref(r->wq[k]);
        free(r->wq);
        free(r->wq_spare);
        pthread_mutex_destroy(&r->wq_lock);
    }

    long mig = 0;
    for (int i = 0; i < nthreads; ++i) mig += atomic_load(&g_reactors[i].migrated_out);
    printf("bye (%ld migration(s) performed)\n", mig);
#ifdef _WIN32
    WSACleanup();                                    /* (each reactor closed its own port) */
#endif
    free(g_reactors);
    return 0;
}

#ifndef SERVER_NO_MAIN
int main(int argc, char* argv[]) { return http_server_main(argc, argv, app_routes); }
#endif
