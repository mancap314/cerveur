/*
 * src/pubsub.c - publish/subscribe between connections, across threads.
 *
 * Part of server.c, which includes the files in src/ in order; not compiled
 * on its own. SPDX-License-Identifier: MIT
 */
/* ======================================================================== */
/* Pub/sub between connections                                              */
/* ======================================================================== */
/*
 * Threading model:
 *   - The topic registry (topic -> subscribers) is global, behind a rwlock:
 *     publishers take it shared, (un)subscribers exclusive.
 *   - Each subscription has a mailbox (ring of message pointers) behind its
 *     own mutex. A publisher appends to every subscriber's mailbox, then
 *     wakes the subscriber's current owner reactor by pushing the
 *     subscription onto that reactor's wake queue (coalesced with an atomic
 *     wake_pending flag, and an eventfd write only when the queue was empty).
 *   - Messages are immutable and reference-counted: one allocation per
 *     publish, shared by all subscribers on all threads.
 *   - Migration: the owner is an atomic pointer, switched when the
 *     connection is handed to another reactor. A wake-up that lands on the
 *     old owner is forwarded to the new one, and the new owner resumes a
 *     subscribed connection on arrival, so mail is never lost or duplicated.
 *   - Queue entries and the registry hold references to the subscription,
 *     so it outlives any in-flight wake-up after its connection has closed.
 */

struct ps_msg {
    _Atomic int refs;
    int opcode;
    size_t len;
    const char* topic;         /* stored after the payload */
    char data[];
};

struct ps_sub {
    _Atomic int refs;
    _Atomic(struct reactor*) owner;
    _Atomic bool alive;
    _Atomic bool wake_pending;
    pthread_mutex_t mu;        /* guards the mailbox and lagged */
    struct ps_msg** q;         /* ring buffer, grows with the backlog up to PS_QUEUE */
    int qcap, qhead, qlen;
    unsigned lagged;
    /* owner thread only: */
    struct conn* conn;
    struct ps_msg* held;       /* message returned by ps_recv(), released by ps_ready() */
    char* topics[PS_MAX_TOPICS];
    int ntopics;
};

struct ps_topic {
    char* name;
    struct ps_sub** subs;
    int n, cap;
    struct ps_topic* next;
};

static pthread_rwlock_t g_ps_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct ps_topic* g_ps_table[PS_BUCKETS];

static void ps_msg_unref(struct ps_msg* m) {
    if (atomic_fetch_sub_explicit(&m->refs, 1, memory_order_acq_rel) == 1) free(m);
}

static void ps_sub_unref(struct ps_sub* s) {
    if (atomic_fetch_sub_explicit(&s->refs, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_destroy(&s->mu);
        free(s->q);
        free(s);
    }
}

/* Append to a mailbox (caller holds s->mu). Grows the ring while below
   PS_QUEUE; at the limit (or out of memory) drops the oldest message. */
static void ps_enqueue(struct ps_sub* s, struct ps_msg* m) {
    if (s->qlen == s->qcap && s->qcap < PS_QUEUE) {
        int cap = s->qcap ? s->qcap * 2 : 16;
        struct ps_msg** q = malloc((size_t)cap * sizeof *q);
        if (q) {                                    /* unwrap into the new ring */
            for (int i = 0; i < s->qlen; ++i) q[i] = s->q[(s->qhead + i) % s->qcap];
            free(s->q);
            s->q = q;
            s->qcap = cap;
            s->qhead = 0;
        }
    }
    if (s->qlen == s->qcap) {
        if (s->qcap == 0) { ps_msg_unref(m); s->lagged++; return; }   /* no memory at all */
        ps_msg_unref(s->q[s->qhead]);               /* full: drop the oldest */
        s->qhead = (s->qhead + 1) % s->qcap;
        s->qlen--;
        s->lagged++;
    }
    s->q[(s->qhead + s->qlen) % s->qcap] = m;
    s->qlen++;
}

static struct ps_msg* ps_dequeue(struct ps_sub* s) {  /* caller holds s->mu */
    if (!s->qlen) return NULL;
    struct ps_msg* m = s->q[s->qhead];
    s->qhead = (s->qhead + 1) % s->qcap;
    s->qlen--;
    return m;
}

static unsigned ps_hash(const char* s) {
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char)*s++) * 16777619u;
    return h % PS_BUCKETS;
}

/* Registry lookup; caller holds g_ps_lock. */
static struct ps_topic* ps_find(const char* topic, struct ps_topic*** link) {
    struct ps_topic** pp = &g_ps_table[ps_hash(topic)];
    while (*pp && strcmp((*pp)->name, topic) != 0) pp = &(*pp)->next;
    if (link) *link = pp;
    return *pp;
}

/* Queue a wake-up for s on reactor r. Takes over one reference to s. */
static void ps_post_wake(struct reactor* r, struct ps_sub* s) {
    pthread_mutex_lock(&r->wq_lock);
    if (r->nwq == r->wq_cap) {
        int cap = r->wq_cap ? r->wq_cap * 2 : 64;
        struct ps_sub** q = realloc(r->wq, (size_t)cap * sizeof *q);
        if (!q) {                                   /* can't queue: drop the wake-up */
            pthread_mutex_unlock(&r->wq_lock);
            atomic_store(&s->wake_pending, false);
            ps_sub_unref(s);
            return;
        }
        r->wq = q;
        r->wq_cap = cap;
    }
    bool was_empty = r->nwq == 0;
    r->wq[r->nwq++] = s;
    pthread_mutex_unlock(&r->wq_lock);
    /* Our own reactor drains its queue before sleeping, so no syscall needed. */
    if (was_empty && r != tls_reactor)
        reactor_notify(r, NOTE_PS);
}

static void ps_wake(struct ps_sub* s) {
    if (atomic_exchange(&s->wake_pending, true)) return;   /* one already on its way */
    atomic_fetch_add(&s->refs, 1);
    ps_post_wake(atomic_load(&s->owner), s);
}

int ps_publish(const char* topic, int opcode, const void* data, size_t len) {
    size_t tlen = strlen(topic);
    struct ps_msg* m = malloc(sizeof *m + len + tlen + 1);
    if (!m) return 0;
    atomic_init(&m->refs, 1);                       /* the publisher's reference */
    m->opcode = opcode;
    m->len = len;
    if (len) memcpy(m->data, data, len);
    memcpy(m->data + len, topic, tlen + 1);
    m->topic = m->data + len;

    int n = 0;
    pthread_rwlock_rdlock(&g_ps_lock);
    struct ps_topic* t = ps_find(topic, NULL);
    for (int i = 0; t && i < t->n; ++i) {
        struct ps_sub* s = t->subs[i];
        atomic_fetch_add_explicit(&m->refs, 1, memory_order_relaxed);
        pthread_mutex_lock(&s->mu);
        ps_enqueue(s, m);
        pthread_mutex_unlock(&s->mu);
        ps_wake(s);
        ++n;
    }
    pthread_rwlock_unlock(&g_ps_lock);
    ps_msg_unref(m);
    return n;
}

bool ps_subscribe(http_ctx* x, const char* topic) {
    struct conn* c = x->c;
    struct ps_sub* s = c->sub;
    if (!s) {
        s = calloc(1, sizeof *s);
        if (!s) return false;
        atomic_init(&s->refs, 1);                   /* the connection's reference */
        atomic_init(&s->owner, c->r);
        atomic_init(&s->alive, true);
        atomic_init(&s->wake_pending, false);
        pthread_mutex_init(&s->mu, NULL);
        s->conn = c;
        c->sub = s;
    }
    for (int i = 0; i < s->ntopics; ++i)
        if (strcmp(s->topics[i], topic) == 0) return true;
    if (s->ntopics == PS_MAX_TOPICS) return false;
    char* name = strdup(topic);
    if (!name) return false;

    bool ok = false;
    pthread_rwlock_wrlock(&g_ps_lock);
    struct ps_topic** link;                         /* where the topic is, or would go */
    struct ps_topic* t = ps_find(topic, &link);
    if (!t) {                                       /* first subscriber: create the topic */
        t = calloc(1, sizeof *t);
        if (t && !(t->name = strdup(topic))) { free(t); t = NULL; }
        if (t) *link = t;
    }
    if (t) {
        if (t->n == t->cap) {
            int cap = t->cap ? t->cap * 2 : 8;
            struct ps_sub** a = realloc(t->subs, (size_t)cap * sizeof *a);
            if (a) { t->subs = a; t->cap = cap; }
        }
        if (t->n < t->cap) {
            t->subs[t->n++] = s;
            atomic_fetch_add(&s->refs, 1);          /* the registry's reference */
            ok = true;
        } else if (t->n == 0) {                     /* out of memory: don't leave it empty */
            *link = t->next;
            free(t->subs);
            free(t->name);
            free(t);
        }
    }
    pthread_rwlock_unlock(&g_ps_lock);
    if (!ok) { free(name); return false; }
    s->topics[s->ntopics++] = name;
    return true;
}

/* Remove s from one topic's subscriber list (caller holds the write lock). */
static void ps_detach(struct ps_sub* s, const char* topic) {
    struct ps_topic** link;
    struct ps_topic* t = ps_find(topic, &link);
    if (!t) return;
    for (int i = 0; i < t->n; ++i) {
        if (t->subs[i] != s) continue;
        t->subs[i] = t->subs[--t->n];
        ps_sub_unref(s);                            /* drop the registry's reference */
        break;
    }
    if (t->n == 0) {                                /* last subscriber: forget the topic */
        *link = t->next;
        free(t->subs);
        free(t->name);
        free(t);
    }
}

void ps_unsubscribe(http_ctx* x, const char* topic) {
    struct ps_sub* s = x->c->sub;
    if (!s) return;
    for (int i = 0; i < s->ntopics; ++i) {
        if (strcmp(s->topics[i], topic) != 0) continue;
        pthread_rwlock_wrlock(&g_ps_lock);
        ps_detach(s, topic);
        pthread_rwlock_unlock(&g_ps_lock);
        free(s->topics[i]);
        s->topics[i] = s->topics[--s->ntopics];
        return;
    }
}

/* End the subscription (handler finished or connection closing). */
static void ps_release(struct conn* c) {
    struct ps_sub* s = c->sub;
    if (!s) return;
    if (s->ntopics) {
        pthread_rwlock_wrlock(&g_ps_lock);
        for (int i = 0; i < s->ntopics; ++i) ps_detach(s, s->topics[i]);
        pthread_rwlock_unlock(&g_ps_lock);
        for (int i = 0; i < s->ntopics; ++i) free(s->topics[i]);
        s->ntopics = 0;
    }
    atomic_store(&s->alive, false);                 /* in-flight wake-ups will be ignored */
    pthread_mutex_lock(&s->mu);
    for (struct ps_msg* m; (m = ps_dequeue(s)); ) ps_msg_unref(m);
    pthread_mutex_unlock(&s->mu);
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }
    s->conn = NULL;
    c->sub = NULL;
    ps_sub_unref(s);                                /* drop the connection's reference */
}

bool ps_ready(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return false;
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }   /* done with the previous one */
    pthread_mutex_lock(&s->mu);
    bool has = s->qlen > 0;
    pthread_mutex_unlock(&s->mu);
    return has;
}

ps_message ps_recv(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return (ps_message){"", 0, "", 0};
    if (s->held) { ps_msg_unref(s->held); s->held = NULL; }
    pthread_mutex_lock(&s->mu);
    struct ps_msg* m = ps_dequeue(s);
    pthread_mutex_unlock(&s->mu);
    if (!m) return (ps_message){"", 0, "", 0};
    s->held = m;
    return (ps_message){m->topic, m->opcode, m->data, m->len};
}

unsigned ps_lagged(http_ctx* x) {
    struct ps_sub* s = x->c->sub;
    if (!s) return 0;
    pthread_mutex_lock(&s->mu);
    unsigned n = s->lagged;
    s->lagged = 0;
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* Does this connection's handler have live subscriptions to wait on? */
static bool ps_listening(const struct conn* c) { return c->sub && c->sub->ntopics > 0; }
