/*
 * proxy-login — ultralight HTTP Basic-Auth shim for the MikroTik RouterOS
 * built-in Web-Proxy.
 *
 * Design goals (see README):
 *   - Mandatory HTTP Basic authentication in front of /ip/proxy.
 *   - Never forward the client's Proxy-Authorization to the upstream.
 *   - Tiny ROM and RAM footprint, yet scale to many concurrent users.
 *
 * Architecture: a single non-blocking epoll(7) event loop per worker thread
 * (workers share the listening socket via SO_REUSEPORT). This replaces the
 * previous thread-per-connection model whose 64 KiB stacks dominated RAM use
 * and whose unbounded thread creation was a trivial memory-exhaustion vector
 * on low-RAM devices.
 *
 * Licensed under MIT.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef PROXY_VERSION
#define PROXY_VERSION "v0.0.1"
#endif

/* ---- Tunables (compile-time; a few overridable via env) ------------------ */
#define HEADER_MAX_SIZE   8192u   /* largest accepted request-header block   */
#define RELAY_BUF_SIZE    8192u   /* per-direction relay buffer (x2 per conn) */
#define CRED_MAX          256u    /* longest "user:pass" we will compare      */
#define USER_MAX          128u    /* longest single username / password       */
#define DEFAULT_MAX_CONN  512     /* process-wide concurrent connection cap   */
#define DEFAULT_WORKERS   0       /* 0 => auto (= online CPUs, capped)         */
#define WORKER_CAP        8
#define HEADER_TIMEOUT_MS 10000   /* deadline to send a full request header   */
#define IDLE_TIMEOUT_MS   120000  /* idle relay timeout                       */
#define CONNECT_TIMEOUT_MS 10000  /* upstream connect deadline                */
#define SWEEP_INTERVAL_MS 1000    /* timeout-sweep cadence                    */
#define WORKER_STACK      (64 * 1024)

/* Brute-force throttle: small fixed-size LRU of offending source IPs. */
#define BF_SLOTS          256
#define BF_MAX_FAILURES   10      /* failures within window before throttle   */
#define BF_WINDOW_SEC     60
#define BF_BLOCK_SEC      60

/* ---- Credentials --------------------------------------------------------- */
typedef struct {
    char user[USER_MAX];
    char pass[USER_MAX];
} credential_t;

typedef struct user_table {
    credential_t *creds;
    size_t        count;
} user_table_t;

/* ---- Global configuration ------------------------------------------------ */
typedef struct {
    char   upstream_host[128];
    char   app_version[64];
    char   users_file[512];
    int    upstream_port;
    int    listen_port;
    int    max_conn;
    int    workers;
    int    header_timeout_ms;
    int    idle_timeout_ms;
} proxy_config_t;

static proxy_config_t g_config;
static volatile sig_atomic_t g_running = 1;

/* User table is swapped under a reader/writer lock on reload. Auth is not on
 * the per-packet path (only once per connection), so an rdlock there is cheap,
 * and the rwlock lets the (single, rare) reloader free the old table safely. */
static user_table_t *g_users = NULL;
static pthread_rwlock_t g_users_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static time_t g_users_file_mtime = 0;

static atomic_int g_conn_count = 0;

/* Brute-force table (shared, mutex-guarded; tiny and rarely contended). */
typedef struct {
    uint32_t ip;           /* IPv4 in network order; 0 == empty slot         */
    uint16_t failures;
    time_t   first_fail;
    time_t   blocked_until;
    time_t   last_seen;
} bf_entry_t;
static bf_entry_t g_bf[BF_SLOTS];
static pthread_mutex_t g_bf_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- Logging (thread-safe, single write()) ------------------------------- */
static void log_msg(const char *fmt, ...) {
    char line[512];
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    size_t p = strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    (void)p;

    int n = snprintf(line, sizeof(line), "[%s] ", ts);
    if (n < 0) return;
    if ((size_t)n >= sizeof(line)) n = (int)sizeof(line) - 1;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0) m = 0;
    size_t total = (size_t)n + (size_t)m;
    if (total >= sizeof(line) - 1) total = sizeof(line) - 2;
    line[total++] = '\n';

    ssize_t w = write(STDERR_FILENO, line, total);
    (void)w;
}

/* ---- Small helpers ------------------------------------------------------- */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; i + 1 < dst_size && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

/* strtol-based strict port parser: returns -1 on any garbage. */
static int parse_port(const char *s) {
    if (!s || !*s) return -1;
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    if (v < 1 || v > 65535) return -1;
    return (int)v;
}

static void set_sock_opts(int fd) {
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* ---- Base64 -------------------------------------------------------------- */
static const signed char b64_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* Decode token into dst (always NUL-terminated). Returns decoded length or -1
 * on malformed input. dst_len must be >= 1. */
static int base64_decode(const char *src, size_t src_len, char *dst, size_t dst_len) {
    if (dst_len == 0) return -1;
    size_t o = 0;
    size_t i = 0;
    while (i < src_len) {
        while (i < src_len && (unsigned char)src[i] <= ' ') i++;
        if (i >= src_len || src[i] == '=') break;

        unsigned int val = 0;
        int count = 0;
        for (int j = 0; j < 4; j++) {
            if (i < src_len && src[i] != '=') {
                signed char c = b64_table[(unsigned char)src[i++]];
                if (c < 0) return -1;
                val = (val << 6) | (unsigned int)c;
                count++;
            } else if (i < src_len && src[i] == '=') {
                val <<= 6;
                i++;
            }
        }
        if (count >= 2 && o + 1 < dst_len) dst[o++] = (char)((val >> 16) & 0xFF);
        if (count >= 3 && o + 1 < dst_len) dst[o++] = (char)((val >> 8) & 0xFF);
        if (count >= 4 && o + 1 < dst_len) dst[o++] = (char)(val & 0xFF);
    }
    dst[o] = '\0';
    return (int)o;
}

/* ---- Constant-time comparison ------------------------------------------- */
/* Compares two NUL-terminated strings without early-out on length/content. */
static int ct_equal(const char *a, size_t alen, const char *b, size_t blen) {
    volatile unsigned char diff = (unsigned char)((alen ^ blen) != 0);
    size_t m = alen > blen ? alen : blen;
    for (size_t i = 0; i < m; i++) {
        unsigned char ca = (i < alen) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < blen) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}

/* ---- User table ---------------------------------------------------------- */
static void user_table_free(user_table_t *t) {
    if (!t) return;
    if (t->creds) {
        /* Wipe secrets from memory before releasing. */
        memset(t->creds, 0, t->count * sizeof(credential_t));
        free(t->creds);
    }
    free(t);
}

/* Append "user:pass" to the growing table. Returns 0 on success. */
static int table_push(credential_t **arr, size_t *n, size_t *cap,
                      const char *user, const char *pass) {
    if (!user || !*user) return 0;            /* skip empty usernames        */
    if (strlen(user) >= USER_MAX || strlen(pass) >= USER_MAX) {
        log_msg("[CONFIG] Skipping user '%.16s...': credential too long (max %u)",
                user, USER_MAX - 1);
        return 0;
    }
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 8;
        credential_t *p = realloc(*arr, ncap * sizeof(credential_t));
        if (!p) return -1;
        *arr = p;
        *cap = ncap;
    }
    safe_strcpy((*arr)[*n].user, user, USER_MAX);
    safe_strcpy((*arr)[*n].pass, pass, USER_MAX);
    (*n)++;
    return 0;
}

/* Parse "user:pass" records separated by ',', ';', '\n' or whitespace. The
 * input string is consumed destructively. */
static int parse_user_list(char *s, credential_t **arr, size_t *n, size_t *cap) {
    char *save = NULL;
    for (char *tok = strtok_r(s, ",;\r\n", &save); tok;
         tok = strtok_r(NULL, ",;\r\n", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        /* Trim trailing whitespace of the whole record (formatting spaces in a
         * comma/space-separated list). Literal edge spaces need PROXY_USER. */
        char *te = tok + strlen(tok);
        while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) *--te = '\0';
        if (*tok == '\0' || *tok == '#') continue;
        char *colon = strchr(tok, ':');
        if (!colon) {
            log_msg("[CONFIG] Ignoring malformed credential (no ':')");
            continue;
        }
        *colon = '\0';
        /* trim trailing whitespace on username */
        char *ue = colon;
        while (ue > tok && (ue[-1] == ' ' || ue[-1] == '\t')) *--ue = '\0';
        if (table_push(arr, n, cap, tok, colon + 1) != 0) return -1;
    }
    return 0;
}

/* Build a fresh user table from env (PROXY_USER/PASS, PROXY_USERS) and the
 * optional users file. Returns a new table, or NULL on OOM / no users. */
static user_table_t *build_user_table(void) {
    credential_t *arr = NULL;
    size_t n = 0, cap = 0;

    const char *u = getenv("PROXY_USER");
    const char *p = getenv("PROXY_PASS");
    if (u && *u && p) {
        if (table_push(&arr, &n, &cap, u, p) != 0) goto oom;
    }

    const char *list = getenv("PROXY_USERS");
    if (list && *list) {
        char *copy = strdup(list);
        if (!copy) goto oom;
        int rc = parse_user_list(copy, &arr, &n, &cap);
        memset(copy, 0, strlen(list));
        free(copy);
        if (rc != 0) goto oom;
    }

    if (g_config.users_file[0]) {
        FILE *f = fopen(g_config.users_file, "re");
        if (f) {
            char ln[2 * USER_MAX + 8];
            while (fgets(ln, sizeof(ln), f)) {
                char *nl = strpbrk(ln, "\r\n");
                if (nl) *nl = '\0';
                char *t = ln;
                while (*t == ' ' || *t == '\t') t++;
                if (*t == '\0' || *t == '#') continue;
                char *colon = strchr(t, ':');
                if (!colon) continue;
                *colon = '\0';
                char *ue = colon;
                while (ue > t && (ue[-1] == ' ' || ue[-1] == '\t')) *--ue = '\0';
                if (table_push(&arr, &n, &cap, t, colon + 1) != 0) {
                    memset(ln, 0, sizeof(ln));
                    fclose(f);
                    goto oom;
                }
            }
            memset(ln, 0, sizeof(ln));
            fclose(f);
        } else {
            log_msg("[CONFIG] Cannot open PROXY_USERS_FILE '%s': %s",
                    g_config.users_file, strerror(errno));
        }
    }

    if (n == 0) {
        free(arr);
        return NULL;
    }
    user_table_t *t = calloc(1, sizeof(*t));
    if (!t) goto oom;
    t->creds = arr;
    t->count = n;
    return t;

oom:
    if (arr) { memset(arr, 0, cap * sizeof(credential_t)); free(arr); }
    return NULL;
}

/* Reload the users file if its mtime changed. Called from the accept path at a
 * coarse cadence so new users appear without a restart. */
static void maybe_reload_users(void) {
    if (!g_config.users_file[0]) return;
    struct stat st;
    if (stat(g_config.users_file, &st) != 0) return;
    if (st.st_mtime == g_users_file_mtime) return;

    /* Build the new table outside the lock (fopen/getenv), then swap briefly
     * under the write lock so no reader can be mid-lookup on the old table. */
    user_table_t *nt = build_user_table();
    if (!nt) return;
    pthread_rwlock_wrlock(&g_users_rwlock);
    user_table_t *old = g_users;
    g_users = nt;
    g_users_file_mtime = st.st_mtime;
    pthread_rwlock_unlock(&g_users_rwlock);
    user_table_free(old);
    log_msg("[CONFIG] Reloaded credentials (%zu users)", nt->count);
}

/* Returns 1 if "user:pass" (decoded) matches any configured credential.
 * Walks the whole table in constant time to avoid user enumeration. */
static int credentials_valid(const char *decoded, size_t dlen) {
    const char *colon = memchr(decoded, ':', dlen);
    size_t ulen, plen;
    const char *user, *pass;
    if (colon) {
        user = decoded; ulen = (size_t)(colon - decoded);
        pass = colon + 1; plen = dlen - ulen - 1;
    } else {
        user = decoded; ulen = dlen;
        pass = decoded + dlen; plen = 0;
    }

    pthread_rwlock_rdlock(&g_users_rwlock);
    user_table_t *t = g_users;
    volatile int ok = 0;
    if (t) {
        for (size_t i = 0; i < t->count; i++) {
            int um = ct_equal(user, ulen, t->creds[i].user, strlen(t->creds[i].user));
            int pm = ct_equal(pass, plen, t->creds[i].pass, strlen(t->creds[i].pass));
            ok |= (um & pm);
        }
    }
    pthread_rwlock_unlock(&g_users_rwlock);
    return ok;
}

/* ---- Brute-force throttle ------------------------------------------------ */
/* Returns 1 if the IP is currently blocked. */
static int bf_is_blocked(uint32_t ip, time_t now) {
    int blocked = 0;
    pthread_mutex_lock(&g_bf_lock);
    for (int i = 0; i < BF_SLOTS; i++) {
        if (g_bf[i].ip == ip && g_bf[i].ip != 0) {
            if (g_bf[i].blocked_until > now) blocked = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_bf_lock);
    return blocked;
}

static void bf_record_failure(uint32_t ip, time_t now, const char *ipstr) {
    pthread_mutex_lock(&g_bf_lock);
    int free_slot = -1, oldest = 0;
    time_t oldest_seen = g_bf[0].last_seen;
    for (int i = 0; i < BF_SLOTS; i++) {
        if (g_bf[i].ip == ip && g_bf[i].ip != 0) {
            if (now - g_bf[i].first_fail > BF_WINDOW_SEC) {
                g_bf[i].failures = 0;
                g_bf[i].first_fail = now;
            }
            g_bf[i].failures++;
            g_bf[i].last_seen = now;
            if (g_bf[i].failures >= BF_MAX_FAILURES && g_bf[i].blocked_until <= now) {
                g_bf[i].blocked_until = now + BF_BLOCK_SEC;
                log_msg("[AUTH-BAN] %s: %u failures, throttled for %ds",
                        ipstr, g_bf[i].failures, BF_BLOCK_SEC);
            }
            pthread_mutex_unlock(&g_bf_lock);
            return;
        }
        if (g_bf[i].ip == 0 && free_slot < 0) free_slot = i;
        if (g_bf[i].last_seen < oldest_seen) { oldest_seen = g_bf[i].last_seen; oldest = i; }
    }
    int slot = (free_slot >= 0) ? free_slot : oldest;
    g_bf[slot].ip = ip;
    g_bf[slot].failures = 1;
    g_bf[slot].first_fail = now;
    g_bf[slot].last_seen = now;
    g_bf[slot].blocked_until = 0;
    pthread_mutex_unlock(&g_bf_lock);
}

static void bf_record_success(uint32_t ip) {
    pthread_mutex_lock(&g_bf_lock);
    for (int i = 0; i < BF_SLOTS; i++) {
        if (g_bf[i].ip == ip && g_bf[i].ip != 0) {
            g_bf[i].failures = 0;
            g_bf[i].blocked_until = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_bf_lock);
}

/* ---- Header parsing / stripping ----------------------------------------- */
/* Find a header line (at a line boundary, case-insensitive). key includes the
 * trailing ':'. Returns pointer to start of line or NULL. */
static char *find_header_line(char *buf, char *end, const char *key, size_t klen) {
    char *p = buf;
    while (p < end) {
        if ((p == buf || p[-1] == '\n') &&
            (size_t)(end - p) >= klen &&
            strncasecmp(p, key, klen) == 0) {
            return p;
        }
        char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        p = nl + 1;
    }
    return NULL;
}

/* Remove every occurrence of a header (hop-by-hop) from the head block.
 * head_len is updated. */
static void strip_header(char *buf, size_t *head_len, const char *key, size_t klen) {
    char *end = buf + *head_len;
    char *line;
    while ((line = find_header_line(buf, end, key, klen)) != NULL) {
        char *nl = memchr(line, '\n', (size_t)(end - line));
        char *next = nl ? nl + 1 : end;
        size_t rest = (size_t)(end - next);
        memmove(line, next, rest);
        end -= (size_t)(next - line);
        *head_len -= (size_t)(next - line);
    }
}

/* Validate Proxy-Authorization present in [buf,head_len). Returns:
 *   1  -> credentials valid
 *   0  -> missing/invalid (respond 407)
 * On success the caller strips the hop-by-hop headers. */
static int check_auth(char *buf, size_t head_len) {
    char *end = buf + head_len;
    char *line = find_header_line(buf, end, "Proxy-Authorization:", 20);
    if (!line) return 0;

    char *v = line + 20;
    char *le = memchr(v, '\n', (size_t)(end - v));
    if (!le) le = end;
    while (v < le && (*v == ' ' || *v == '\t')) v++;
    if ((size_t)(le - v) < 6 || strncasecmp(v, "Basic ", 6) != 0) return 0;
    v += 6;
    while (v < le && (*v == ' ' || *v == '\t')) v++;
    /* token ends at CR/LF/whitespace */
    char *te = v;
    while (te < le && *te != '\r' && *te != '\n' && *te != ' ' && *te != '\t') te++;

    char decoded[CRED_MAX];
    int dl = base64_decode(v, (size_t)(te - v), decoded, sizeof(decoded));
    if (dl <= 0) { memset(decoded, 0, sizeof(decoded)); return 0; }

    int ok = credentials_valid(decoded, (size_t)dl);
    memset(decoded, 0, sizeof(decoded));
    return ok;
}

/* ---- Connection state machine ------------------------------------------- */
typedef enum {
    ST_HEADER,       /* reading request headers from client                  */
    ST_CONNECTING,   /* non-blocking connect() to upstream in flight         */
    ST_RELAY         /* full-duplex relay                                    */
} conn_state_t;

typedef struct connection connection_t;

/* epoll data points at one of these so the handler knows the role. */
typedef struct {
    connection_t *conn;
    int is_client;   /* 1 => client fd, 0 => upstream fd                     */
} ep_ref_t;

struct connection {
    int client_fd;
    int upstream_fd;
    conn_state_t state;

    ep_ref_t client_ref;
    ep_ref_t upstream_ref;

    /* Header accumulation (also reused as client->upstream relay buffer). */
    char  *hbuf;
    size_t hbuf_len;

    /* Relay buffers. c2u carries client->upstream, u2c upstream->client. */
    char  *c2u; size_t c2u_len, c2u_off;
    char  *u2c; size_t u2c_len, u2c_off;
    int    client_read_closed;
    int    upstream_read_closed;

    int64_t deadline_ms;

    uint32_t ip_be;
    char ip[INET_ADDRSTRLEN];
    int  port;

    size_t reg_idx;      /* index into the worker's live-connection registry */
    int    registered;
    int    dead;         /* retired this batch; freed after the dispatch loop */
};

/* Per-worker registry of live connections, used only for the deadline sweep. */
typedef struct {
    connection_t **items;
    size_t count, cap;
} conn_list_t;
static __thread conn_list_t *t_live = NULL;
/* Retired-but-not-yet-freed connections. A single epoll_wait batch can carry
 * events for both fds of one connection; if the first frees it, the second
 * would dereference freed memory. So conn_close only *retires* (closes fds,
 * nulls the back-pointers), and the connection is freed after the batch. */
static __thread conn_list_t *t_zombies = NULL;

/* Forward decls */
static void conn_close(int epfd, connection_t *c);
static int  conn_update_epoll(int epfd, connection_t *c);

static void cl_add(conn_list_t *l, connection_t *c) {
    if (l->count == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        connection_t **p = realloc(l->items, nc * sizeof(*p));
        if (!p) return;              /* best-effort: sweep just won't see it  */
        l->items = p; l->cap = nc;
    }
    c->reg_idx = l->count;
    c->registered = 1;
    l->items[l->count++] = c;
}

static void cl_remove(conn_list_t *l, connection_t *c) {
    if (!c->registered || l->count == 0) return;
    size_t idx = c->reg_idx;
    if (idx >= l->count || l->items[idx] != c) return;
    connection_t *last = l->items[--l->count];
    l->items[idx] = last;
    last->reg_idx = idx;
    c->registered = 0;
}

static const char RESP_407[] =
    "HTTP/1.1 407 Proxy Authentication Required\r\n"
    "Proxy-Authenticate: Basic realm=\"MikroTik Web Proxy\"\r\n"
    "Connection: close\r\n"
    "Content-Length: 0\r\n\r\n";
static const char RESP_400[] =
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
static const char RESP_502[] =
    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
static const char RESP_503[] =
    "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/* Best-effort non-blocking write of a short control response, then close. We
 * never block the event loop waiting for a slow reader; the response is small
 * enough to fit the socket buffer in practice, and if it does not the client
 * simply receives a reset. */
static void send_simple_and_close(int epfd, connection_t *c, const char *resp) {
    size_t total = strlen(resp), sent = 0;
    for (int tries = 0; tries < 4 && sent < total; tries++) {
        ssize_t w = send(c->client_fd, resp + sent, total - sent,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        break;
    }
    conn_close(epfd, c);
}

/* Create and start a non-blocking connect() to the upstream proxy. */
static int start_upstream_connect(connection_t *c) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    set_sock_opts(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_config.upstream_port);
    if (inet_pton(AF_INET, g_config.upstream_host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    c->upstream_fd = fd;
    return 0;
}

/* Recompute and apply epoll interest masks for both fds. */
static int conn_update_epoll(int epfd, connection_t *c) {
    struct epoll_event ev;

    if (c->state == ST_HEADER) {
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = &c->client_ref;
        return epoll_ctl(epfd, EPOLL_CTL_MOD, c->client_fd, &ev);
    }
    if (c->state == ST_CONNECTING) {
        /* Watch upstream for connect completion; keep only hangup detection on
         * the client so a client close aborts the pending connect. */
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLRDHUP;
        ev.data.ptr = &c->client_ref;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->client_fd, &ev) < 0) return -1;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLOUT;
        ev.data.ptr = &c->upstream_ref;
        return epoll_ctl(epfd, EPOLL_CTL_MOD, c->upstream_fd, &ev);
    }

    /* ST_RELAY: interest derives from buffer occupancy. Two rules keep the
     * level-triggered loop from busy-spinning:
     *   - read interest (EPOLLIN|EPOLLRDHUP) is enabled only when there is room
     *     in the receiving buffer, so a half-close (RDHUP) we cannot consume yet
     *     does not re-fire every wait; it re-enables when the buffer drains.
     *   - a fully-hung-up peer is retired (fd closed) by handle_relay, so its
     *     always-delivered EPOLLHUP stops.
     * EPOLLHUP/EPOLLERR are reported regardless of the mask, so closes are still
     * detected. */
    if (c->upstream_fd < 0) {
        /* Upstream retired: only flush remaining u2c to the client. */
        uint32_t cev = (c->u2c_len - c->u2c_off > 0) ? EPOLLOUT : 0;
        memset(&ev, 0, sizeof(ev));
        ev.events = cev; ev.data.ptr = &c->client_ref;
        return epoll_ctl(epfd, EPOLL_CTL_MOD, c->client_fd, &ev);
    }

    uint32_t cev = 0, uev = 0;
    if (!c->client_read_closed && c->c2u_len < RELAY_BUF_SIZE)
        cev |= EPOLLIN | EPOLLRDHUP;
    if (c->u2c_len - c->u2c_off > 0) cev |= EPOLLOUT;
    if (!c->upstream_read_closed && c->u2c_len < RELAY_BUF_SIZE)
        uev |= EPOLLIN | EPOLLRDHUP;
    if (c->c2u_len - c->c2u_off > 0) uev |= EPOLLOUT;

    memset(&ev, 0, sizeof(ev));
    ev.events = cev; ev.data.ptr = &c->client_ref;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->client_fd, &ev) < 0) return -1;
    memset(&ev, 0, sizeof(ev));
    ev.events = uev; ev.data.ptr = &c->upstream_ref;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->upstream_fd, &ev) < 0) return -1;
    return 0;
}

/* Retire a connection: close its fds, remove it from epoll and the live
 * registry, and null the epoll back-pointers so any already-dequeued event for
 * this connection in the current batch is recognised as stale and skipped. The
 * memory is reclaimed later by conn_reap(), never inline, to avoid a
 * use-after-free on a sibling event in the same epoll_wait batch. */
static void conn_close(int epfd, connection_t *c) {
    if (!c || c->dead) return;
    if (t_live) cl_remove(t_live, c);
    if (c->client_fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->client_fd, NULL);
        close(c->client_fd);
        c->client_fd = -1;
    }
    if (c->upstream_fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->upstream_fd, NULL);
        close(c->upstream_fd);
        c->upstream_fd = -1;
    }
    c->client_ref.conn = NULL;      /* stale events in this batch see NULL     */
    c->upstream_ref.conn = NULL;
    c->dead = 1;
    atomic_fetch_sub(&g_conn_count, 1);
    if (t_zombies) {
        cl_add(t_zombies, c);       /* freed after the dispatch loop           */
    } else {
        /* No deferral context (shouldn't happen on the worker path): free now. */
        free(c->hbuf); free(c->c2u); free(c->u2c); free(c);
    }
}

/* Free all retired connections. Safe to call only when no live epoll event
 * still references them (i.e. between batches, and after the sweep). */
static void conn_reap(void) {
    if (!t_zombies) return;
    for (size_t i = 0; i < t_zombies->count; i++) {
        connection_t *c = t_zombies->items[i];
        free(c->hbuf);
        free(c->c2u);
        free(c->u2c);
        free(c);
    }
    t_zombies->count = 0;
}

/* Transition from header phase into relay once upstream is connected. Moves
 * leftover client bytes (stripped head + pipelined body) into c2u. */
static int enter_relay(int epfd, connection_t *c) {
    c->c2u = malloc(RELAY_BUF_SIZE);
    c->u2c = malloc(RELAY_BUF_SIZE);
    if (!c->c2u || !c->u2c) { conn_close(epfd, c); return -1; }

    size_t n = c->hbuf_len;
    if (n > RELAY_BUF_SIZE) n = RELAY_BUF_SIZE;  /* head always <= buf size */
    memcpy(c->c2u, c->hbuf, n);
    c->c2u_len = n;
    c->c2u_off = 0;
    /* Wipe and release the header buffer (it held the base64 credentials). */
    memset(c->hbuf, 0, c->hbuf_len);
    free(c->hbuf);
    c->hbuf = NULL;
    c->hbuf_len = 0;

    c->state = ST_RELAY;
    c->deadline_ms = now_ms() + g_config.idle_timeout_ms;
    return conn_update_epoll(epfd, c);
}

/* Handle readable/writable events during header accumulation. */
static void handle_header(int epfd, connection_t *c) {
    for (;;) {
        if (c->hbuf_len >= HEADER_MAX_SIZE) {
            send_simple_and_close(epfd, c, RESP_400);
            return;
        }
        ssize_t n = recv(c->client_fd, c->hbuf + c->hbuf_len,
                         HEADER_MAX_SIZE - c->hbuf_len, 0);
        if (n > 0) {
            c->hbuf_len += (size_t)n;
            /* look for end of headers */
            if (c->hbuf_len >= 4) {
                /* search only the fresh region plus 3-byte overlap */
                char *hdr_end = memmem(c->hbuf, c->hbuf_len, "\r\n\r\n", 4);
                if (hdr_end) {
                    size_t head_len = (size_t)(hdr_end - c->hbuf) + 4;
                    time_t now = time(NULL);
                    if (bf_is_blocked(c->ip_be, now)) {
                        send_simple_and_close(epfd, c, RESP_407);
                        return;
                    }
                    if (!check_auth(c->hbuf, head_len)) {
                        bf_record_failure(c->ip_be, now, c->ip);
                        log_msg("[AUTH-DENY] %s: invalid or missing credentials", c->ip);
                        send_simple_and_close(epfd, c, RESP_407);
                        return;
                    }
                    bf_record_success(c->ip_be);
                    /* Strip hop-by-hop auth headers from the whole head. */
                    size_t new_head = head_len;
                    strip_header(c->hbuf, &new_head, "Proxy-Authorization:", 20);
                    strip_header(c->hbuf, &new_head, "Proxy-Connection:", 17);
                    /* shift any pipelined bytes after the head down to meet it */
                    size_t tail = c->hbuf_len - head_len;
                    if (tail) memmove(c->hbuf + new_head, c->hbuf + head_len, tail);
                    c->hbuf_len = new_head + tail;

                    if (start_upstream_connect(c) != 0) {
                        send_simple_and_close(epfd, c, RESP_502);
                        return;
                    }
                    c->state = ST_CONNECTING;
                    c->deadline_ms = now_ms() + CONNECT_TIMEOUT_MS;
                    struct epoll_event ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.events = EPOLLOUT;
                    ev.data.ptr = &c->upstream_ref;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->upstream_fd, &ev) < 0 ||
                        conn_update_epoll(epfd, c) < 0) {
                        conn_close(epfd, c);
                    }
                    return;
                }
            }
            continue;
        }
        if (n == 0) { conn_close(epfd, c); return; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        if (errno == EINTR) continue;
        conn_close(epfd, c);
        return;
    }
}

/* Upstream connect completion. */
static void handle_connecting(int epfd, connection_t *c) {
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(c->upstream_fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
        log_msg("[UPSTREAM] %s: connect to %s:%d failed: %s", c->ip,
                g_config.upstream_host, g_config.upstream_port,
                err ? strerror(err) : "error");
        send_simple_and_close(epfd, c, RESP_502);
        return;
    }
    enter_relay(epfd, c);
}

/* Pump one direction: read from src into buf, write buf to dst. Returns 0 to
 * continue, -1 if the connection was closed. */
static int relay_io(int epfd, connection_t *c, int readable, int writable,
                    int src_fd, int dst_fd,
                    char *buf, size_t *len, size_t *off,
                    int *src_read_closed) {
    /* Drain pending output first to make room. */
    if (writable && *len - *off > 0) {
        while (*len - *off > 0) {
            ssize_t w = send(dst_fd, buf + *off, *len - *off, MSG_NOSIGNAL);
            if (w > 0) {
                *off += (size_t)w;
                if (*off == *len) { *off = 0; *len = 0; }
            } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else if (w < 0 && errno == EINTR) {
                continue;
            } else {
                conn_close(epfd, c);
                return -1;
            }
        }
    }

    if (readable && !*src_read_closed && *len < RELAY_BUF_SIZE) {
        for (;;) {
            ssize_t r = recv(src_fd, buf + *len, RELAY_BUF_SIZE - *len, 0);
            if (r > 0) {
                *len += (size_t)r;
                /* try to forward immediately */
                while (*len - *off > 0) {
                    ssize_t w = send(dst_fd, buf + *off, *len - *off, MSG_NOSIGNAL);
                    if (w > 0) {
                        *off += (size_t)w;
                        if (*off == *len) { *off = 0; *len = 0; }
                    } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    } else if (w < 0 && errno == EINTR) {
                        continue;
                    } else {
                        conn_close(epfd, c);
                        return -1;
                    }
                }
                if (*len >= RELAY_BUF_SIZE) break;   /* buffer full, wait      */
            } else if (r == 0) {
                *src_read_closed = 1;
                /* Propagate half-close once our buffer to dst is flushed. */
                if (*len - *off == 0) shutdown(dst_fd, SHUT_WR);
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno == EINTR) {
                continue;
            } else {
                conn_close(epfd, c);
                return -1;
            }
        }
    }

    /* If source closed and everything is flushed, send FIN downstream. */
    if (*src_read_closed && *len - *off == 0) shutdown(dst_fd, SHUT_WR);

    return 0;
}

static void handle_relay(int epfd, connection_t *c, ep_ref_t *ref, uint32_t events) {
    /* A hard socket error is unrecoverable for the whole relay. */
    if (events & EPOLLERR) { conn_close(epfd, c); return; }

    int is_client = ref->is_client;
    int readable  = (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0;
    int writable  = (events & EPOLLOUT) != 0;

    if (is_client) {
        /* client readable -> read into c2u, forward to upstream (if alive) */
        if (c->upstream_fd >= 0 &&
            relay_io(epfd, c, readable, 0,
                     c->client_fd, c->upstream_fd,
                     c->c2u, &c->c2u_len, &c->c2u_off, &c->client_read_closed) < 0) return;
        /* client writable -> drain u2c to client */
        if (relay_io(epfd, c, 0, writable,
                     c->upstream_fd, c->client_fd,
                     c->u2c, &c->u2c_len, &c->u2c_off, &c->upstream_read_closed) < 0) return;
    } else {
        /* upstream readable -> read into u2c, forward to client */
        if (relay_io(epfd, c, readable, 0,
                     c->upstream_fd, c->client_fd,
                     c->u2c, &c->u2c_len, &c->u2c_off, &c->upstream_read_closed) < 0) return;
        /* upstream writable -> drain c2u to upstream */
        if (c->upstream_fd >= 0 &&
            relay_io(epfd, c, 0, writable,
                     c->client_fd, c->upstream_fd,
                     c->c2u, &c->c2u_len, &c->c2u_off, &c->client_read_closed) < 0) return;
    }

    /* A full hangup (both directions) means the peer is gone for good. Under
     * level-triggered epoll EPOLLHUP is re-delivered every wait, so we retire
     * the fd now that the pump above has drained what it could. */
    if (events & EPOLLHUP) {
        if (is_client) { conn_close(epfd, c); return; }   /* client abandoned */
        c->upstream_read_closed = 1;
        c->c2u_len = c->c2u_off = 0;                       /* undeliverable    */
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->upstream_fd, NULL);
        close(c->upstream_fd);
        c->upstream_fd = -1;
    }

    /* Teardown. */
    if (c->upstream_fd < 0) {
        if ((c->u2c_len - c->u2c_off) == 0) { conn_close(epfd, c); return; }
    } else if (c->client_read_closed && c->upstream_read_closed &&
               (c->c2u_len - c->c2u_off) == 0 && (c->u2c_len - c->u2c_off) == 0) {
        conn_close(epfd, c);
        return;
    }

    /* Extend the idle deadline only on real data readiness, so a wedged peer
     * (bare HUP/RDHUP with no progress) is still reaped by the sweep. */
    if (events & (EPOLLIN | EPOLLOUT))
        c->deadline_ms = now_ms() + g_config.idle_timeout_ms;

    if (conn_update_epoll(epfd, c) < 0) conn_close(epfd, c);
}

/* ---- Worker --------------------------------------------------------------*/
typedef struct {
    int listen_fd;
    int id;
} worker_arg_t;

static void accept_new(int epfd, int listen_fd) {
    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int fd = accept4(listen_fd, (struct sockaddr *)&ca, &cl,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE) {
                /* fd exhaustion: pause briefly to avoid a busy spin */
                return;
            }
            return;
        }

        if (atomic_fetch_add(&g_conn_count, 1) >= g_config.max_conn) {
            atomic_fetch_sub(&g_conn_count, 1);
            /* Over capacity: best-effort 503 then drop. */
            send(fd, RESP_503, strlen(RESP_503), MSG_NOSIGNAL | MSG_DONTWAIT);
            close(fd);
            continue;
        }

        set_sock_opts(fd);
        connection_t *c = calloc(1, sizeof(*c));
        if (!c) { close(fd); atomic_fetch_sub(&g_conn_count, 1); continue; }
        c->hbuf = malloc(HEADER_MAX_SIZE);
        if (!c->hbuf) { close(fd); free(c); atomic_fetch_sub(&g_conn_count, 1); continue; }
        c->client_fd = fd;
        c->upstream_fd = -1;
        c->state = ST_HEADER;
        c->client_ref.conn = c;   c->client_ref.is_client = 1;
        c->upstream_ref.conn = c; c->upstream_ref.is_client = 0;
        c->ip_be = ca.sin_addr.s_addr;
        inet_ntop(AF_INET, &ca.sin_addr, c->ip, sizeof(c->ip));
        c->port = ntohs(ca.sin_port);
        c->deadline_ms = now_ms() + g_config.header_timeout_ms;

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = &c->client_ref;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            conn_close(epfd, c);
            continue;
        }
        cl_add(t_live, c);
    }
}

/* Close any connection that has blown its phase deadline (header/connect/idle).
 * Walks the worker-local registry; swap-remove keeps it O(active). */
static void sweep_deadlines(int epfd) {
    if (!t_live) return;
    int64_t now = now_ms();
    for (size_t i = 0; i < t_live->count; ) {
        connection_t *c = t_live->items[i];
        if (now >= c->deadline_ms) {
            if (c->state == ST_HEADER)
                log_msg("[TIMEOUT] %s: header deadline exceeded", c->ip);
            conn_close(epfd, c);   /* swap-removes index i; do not advance */
        } else {
            i++;
        }
    }
}

static void *worker_main(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    int listen_fd = wa->listen_fd;

    conn_list_t live = {0};
    conn_list_t zombies = {0};
    t_live = &live;
    t_zombies = &zombies;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { log_msg("[FATAL] epoll_create1: %s", strerror(errno)); return NULL; }

    struct epoll_event lev;
    memset(&lev, 0, sizeof(lev));
    lev.events = EPOLLIN;
    lev.data.ptr = NULL;   /* NULL marks the listening socket */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev) < 0) {
        log_msg("[FATAL] epoll_ctl(listen): %s", strerror(errno));
        close(epfd);
        return NULL;
    }

    enum { MAXEV = 128 };
    struct epoll_event *evs = calloc(MAXEV, sizeof(*evs));
    if (!evs) { close(epfd); return NULL; }

    int64_t next_sweep = now_ms() + SWEEP_INTERVAL_MS;

    while (g_running) {
        int timeout = (int)(next_sweep - now_ms());
        if (timeout < 0) timeout = 0;
        int nev = epoll_wait(epfd, evs, MAXEV, timeout);
        if (nev < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nev; i++) {
            ep_ref_t *ref = (ep_ref_t *)evs[i].data.ptr;
            if (ref == NULL) {
                if (wa->id == 0) maybe_reload_users();
                accept_new(epfd, listen_fd);
                continue;
            }
            connection_t *c = ref->conn;
            /* A sibling event earlier in this same batch may have retired this
             * connection (conn_close nulls ref->conn). Skip the stale event. */
            if (c == NULL || c->dead) continue;
            uint32_t e = evs[i].events;

            if (c->state == ST_HEADER) {
                if (e & (EPOLLERR | EPOLLHUP)) { conn_close(epfd, c); continue; }
                handle_header(epfd, c);
            } else if (c->state == ST_CONNECTING) {
                if (ref->is_client) {
                    /* Only hangup/error can reach the client side here. */
                    if (e & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) conn_close(epfd, c);
                    continue;
                }
                handle_connecting(epfd, c);
            } else {
                handle_relay(epfd, c, ref, e);
            }
        }

        /* All events in this batch are processed: now it is safe to free the
         * connections retired during it. */
        conn_reap();

        if (now_ms() >= next_sweep) {
            sweep_deadlines(epfd);
            conn_reap();
            next_sweep = now_ms() + SWEEP_INTERVAL_MS;
        }
    }

    /* Shutdown: free any connections still in flight so no memory/fds leak. */
    while (live.count > 0) conn_close(epfd, live.items[0]);
    conn_reap();

    free(evs);
    free(live.items);
    free(zombies.items);
    close(epfd);
    t_live = NULL;
    t_zombies = NULL;
    return NULL;
}

/* ---- Signals ------------------------------------------------------------- */
static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* ---- Config -------------------------------------------------------------- */
static int load_config(void) {
    memset(&g_config, 0, sizeof(g_config));

    const char *host  = getenv("UPSTREAM_HOST");
    const char *uport = getenv("UPSTREAM_PORT");
    const char *lport = getenv("LISTEN_PORT");
    const char *ver   = getenv("PROXY_VER");
    const char *ufile = getenv("PROXY_USERS_FILE");
    const char *mconn = getenv("MAX_CONN");
    const char *wenv  = getenv("WORKERS");

    if (!host || !*host) {
        log_msg("[FATAL] UPSTREAM_HOST is required");
        return -1;
    }
    struct in_addr tmp;
    if (inet_pton(AF_INET, host, &tmp) != 1) {
        log_msg("[FATAL] UPSTREAM_HOST must be an IPv4 address (got '%s')", host);
        return -1;
    }
    safe_strcpy(g_config.upstream_host, host, sizeof(g_config.upstream_host));

    g_config.upstream_port = parse_port(uport);
    if (g_config.upstream_port < 0) {
        log_msg("[FATAL] UPSTREAM_PORT invalid (got '%s')", uport ? uport : "(null)");
        return -1;
    }
    g_config.listen_port = (lport && *lport) ? parse_port(lport) : 8080;
    if (g_config.listen_port < 0) {
        log_msg("[FATAL] LISTEN_PORT invalid (got '%s')", lport);
        return -1;
    }

    if (ufile && *ufile) safe_strcpy(g_config.users_file, ufile, sizeof(g_config.users_file));

    g_config.max_conn = DEFAULT_MAX_CONN;
    if (mconn && *mconn) {
        char *end = NULL; long v = strtol(mconn, &end, 10);
        if (end != mconn && *end == '\0' && v >= 1 && v <= 1000000) g_config.max_conn = (int)v;
    }

    g_config.workers = DEFAULT_WORKERS;
    if (wenv && *wenv) {
        char *end = NULL; long v = strtol(wenv, &end, 10);
        if (end != wenv && *end == '\0' && v >= 1 && v <= WORKER_CAP) g_config.workers = (int)v;
    }
    if (g_config.workers == 0) {
        long nc = sysconf(_SC_NPROCESSORS_ONLN);
        if (nc < 1) nc = 1;
        if (nc > WORKER_CAP) nc = WORKER_CAP;
        g_config.workers = (int)nc;
    }

    /* Optional timeout overrides (milliseconds). */
    g_config.header_timeout_ms = HEADER_TIMEOUT_MS;
    g_config.idle_timeout_ms   = IDLE_TIMEOUT_MS;
    {
        const char *ht = getenv("HEADER_TIMEOUT_MS");
        const char *it = getenv("IDLE_TIMEOUT_MS");
        char *e; long v;
        if (ht && *ht) { v = strtol(ht, &e, 10); if (*e=='\0' && v>=100 && v<=600000) g_config.header_timeout_ms=(int)v; }
        if (it && *it) { v = strtol(it, &e, 10); if (*e=='\0' && v>=1000 && v<=3600000) g_config.idle_timeout_ms=(int)v; }
    }

    if (ver && *ver) safe_strcpy(g_config.app_version, ver, sizeof(g_config.app_version));
    else safe_strcpy(g_config.app_version, PROXY_VERSION, sizeof(g_config.app_version));

    /* Build the user table. */
    user_table_t *t = build_user_table();
    if (!t) {
        log_msg("[FATAL] No credentials configured. Set PROXY_USER/PROXY_PASS, "
                "PROXY_USERS, or PROXY_USERS_FILE.");
        return -1;
    }
    g_users = t;
    if (g_config.users_file[0]) {
        struct stat st;
        if (stat(g_config.users_file, &st) == 0) g_users_file_mtime = st.st_mtime;
    }

    /* Scrub credential-bearing env vars so they do not leak to the upstream
     * environment or to /proc for other container processes. */
    unsetenv("PROXY_PASS");
    unsetenv("PROXY_USERS");

    log_msg("[CONFIG] %zu user(s), upstream %s:%d, listen :%d, workers %d, max_conn %d",
            t->count, g_config.upstream_host, g_config.upstream_port,
            g_config.listen_port, g_config.workers, g_config.max_conn);
    return 0;
}

static int make_listen_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_config.listen_port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 1024) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

#ifndef PROXY_NO_MAIN
int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (load_config() != 0) return 1;

    log_msg("=================================================");
    log_msg("MikroTik Auth-Proxy Shim %s (built-in %s)",
            g_config.app_version, PROXY_VERSION);
    log_msg("=================================================");

    /* One listening socket per worker (SO_REUSEPORT distributes accepts). If
     * SO_REUSEPORT is unavailable we fall back to a single shared socket. */
    int n = g_config.workers;
    int *lfds = calloc((size_t)n, sizeof(int));
    pthread_t *tids = calloc((size_t)n, sizeof(pthread_t));
    worker_arg_t *wargs = calloc((size_t)n, sizeof(worker_arg_t));
    if (!lfds || !tids || !wargs) { log_msg("[FATAL] OOM"); return 1; }

    int shared_fd = -1;
    int reuseport_ok = 1;
    for (int i = 0; i < n; i++) {
        int fd = make_listen_socket();
        if (fd < 0) {
            if (i == 0) { log_msg("[FATAL] cannot bind :%d: %s",
                                  g_config.listen_port, strerror(errno)); return 1; }
            reuseport_ok = 0;
            break;
        }
        lfds[i] = fd;
        if (i == 0) shared_fd = fd;
    }
    if (!reuseport_ok) {
        for (int i = 1; i < n; i++) if (lfds[i] > 0) { close(lfds[i]); lfds[i] = 0; }
        for (int i = 0; i < n; i++) lfds[i] = shared_fd;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, WORKER_STACK);

    log_msg("[OK] listening on :%d with %d worker(s)", g_config.listen_port, n);

    int started = 0;
    for (int i = 0; i < n; i++) {
        wargs[i].listen_fd = lfds[i];
        wargs[i].id = i;
        if (pthread_create(&tids[i], &attr, worker_main, &wargs[i]) == 0) started++;
        else tids[i] = 0;
    }
    pthread_attr_destroy(&attr);

    if (started == 0) { log_msg("[FATAL] no workers started"); return 1; }

    for (int i = 0; i < n; i++) if (tids[i]) pthread_join(tids[i], NULL);

    if (reuseport_ok) { for (int i = 0; i < n; i++) if (lfds[i] > 0) close(lfds[i]); }
    else if (shared_fd >= 0) close(shared_fd);

    user_table_free(g_users);
    free(lfds); free(tids); free(wargs);
    log_msg("[OK] shut down cleanly");
    return 0;
}
#endif /* PROXY_NO_MAIN */
