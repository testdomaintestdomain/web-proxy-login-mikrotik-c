/* Unit tests for the pure/internal functions of proxy_login.c.
 * We include the translation unit directly (with its main() compiled out) so
 * the file-static functions are reachable without exporting them. */
#define PROXY_NO_MAIN
#include "../src/proxy_login.c"

#include <assert.h>

static int g_failures = 0;
static int g_checks = 0;
#define CHECK(cond, ...) do {                                      \
    g_checks++;                                                    \
    if (!(cond)) { g_failures++;                                   \
        fprintf(stdout, "  [FAIL] %s:%d: ", __FILE__, __LINE__);   \
        fprintf(stdout, __VA_ARGS__); fputc('\n', stdout); }       \
} while (0)

/* ---- base64 ---- */
static void test_base64(void) {
    char out[CRED_MAX];
    int n;

    n = base64_decode("bXl1c2VyOm15cGFzcw==", 20, out, sizeof(out)); /* myuser:mypass */
    CHECK(n == 13 && memcmp(out, "myuser:mypass", 13) == 0, "basic decode got n=%d '%s'", n, out);

    n = base64_decode("YQ==", 4, out, sizeof(out)); /* "a" */
    CHECK(n == 1 && out[0] == 'a', "single byte n=%d", n);

    n = base64_decode("", 0, out, sizeof(out));
    CHECK(n == 0, "empty n=%d", n);

    n = base64_decode("@@@!", 4, out, sizeof(out));
    CHECK(n == -1, "invalid chars should fail, n=%d", n);

    /* decode must never overflow a tiny buffer */
    char small[4];
    n = base64_decode("QUFBQUFBQUFBQUFB", 16, small, sizeof(small)); /* 12 'A' */
    CHECK(n >= 0 && (size_t)n <= sizeof(small) - 1 && small[sizeof(small)-1] == '\0',
          "bounded decode n=%d", n);

    /* embedded NUL in decoded output is preserved by length, string stops early */
    n = base64_decode("AABB", 4, out, sizeof(out));
    CHECK(n == 3, "decode with nul byte n=%d", n);
}

/* ---- constant-time compare ---- */
static void test_ct_equal(void) {
    CHECK(ct_equal("abc", 3, "abc", 3) == 1, "equal");
    CHECK(ct_equal("abc", 3, "abd", 3) == 0, "last differs");
    CHECK(ct_equal("abc", 3, "ab", 2) == 0, "len differs");
    CHECK(ct_equal("", 0, "", 0) == 1, "empty equal");
    CHECK(ct_equal("abc", 3, "", 0) == 0, "one empty");
}

/* ---- port parsing ---- */
static void test_parse_port(void) {
    CHECK(parse_port("8080") == 8080, "8080");
    CHECK(parse_port("1") == 1, "1");
    CHECK(parse_port("65535") == 65535, "max");
    CHECK(parse_port("0") == -1, "zero invalid");
    CHECK(parse_port("65536") == -1, "overflow range");
    CHECK(parse_port("-1") == -1, "negative");
    CHECK(parse_port("80x") == -1, "trailing junk");
    CHECK(parse_port("") == -1, "empty");
    CHECK(parse_port(NULL) == -1, "null");
    CHECK(parse_port("99999999999999999999") == -1, "ERANGE");
}

/* ---- user list parsing ---- */
static void test_user_list(void) {
    credential_t *arr = NULL; size_t n = 0, cap = 0;
    char list[] = "u1:p1,u2:p2;u3:p3\nu4:p4  ,  :skipempty , nocolon ";
    int rc = parse_user_list(list, &arr, &n, &cap);
    CHECK(rc == 0, "parse rc=%d", rc);
    CHECK(n == 4, "expected 4 users got %zu", n);
    if (n >= 4) {
        CHECK(strcmp(arr[0].user, "u1") == 0 && strcmp(arr[0].pass, "p1") == 0, "u1");
        CHECK(strcmp(arr[3].user, "u4") == 0 && strcmp(arr[3].pass, "p4") == 0, "u4 trimmed");
    }
    free(arr);
}

/* ---- header strip ---- */
static void test_strip_header(void) {
    char buf[512];
    const char *req =
        "GET http://x/ HTTP/1.1\r\n"
        "Host: x\r\n"
        "Proxy-Authorization: Basic Zm9v\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Accept: */*\r\n\r\n";
    size_t len = strlen(req);
    memcpy(buf, req, len);
    strip_header(buf, &len, "Proxy-Authorization:", 20);
    strip_header(buf, &len, "Proxy-Connection:", 17);
    buf[len] = '\0';
    CHECK(strstr(buf, "Proxy-Authorization") == NULL, "auth header removed");
    CHECK(strstr(buf, "Proxy-Connection") == NULL, "proxy-conn removed");
    CHECK(strstr(buf, "Host: x") != NULL, "host kept");
    CHECK(strstr(buf, "Accept: */*") != NULL, "accept kept");
    CHECK(strstr(buf, "GET http://x/ HTTP/1.1") != NULL, "request line kept");

    /* duplicate Proxy-Authorization: ALL must be removed */
    char buf2[512];
    const char *req2 =
        "GET / HTTP/1.1\r\n"
        "Proxy-Authorization: Basic AAA\r\n"
        "X: 1\r\n"
        "Proxy-Authorization: Basic BBB\r\n\r\n";
    size_t l2 = strlen(req2); memcpy(buf2, req2, l2);
    strip_header(buf2, &l2, "Proxy-Authorization:", 20);
    buf2[l2] = '\0';
    CHECK(strstr(buf2, "Proxy-Authorization") == NULL, "both auth headers removed");
    CHECK(strstr(buf2, "X: 1") != NULL, "middle header kept");
}

/* ---- auth check (uses the global user table) ---- */
static void install_users(credential_t *c, size_t n) {
    static user_table_t t;
    t.creds = c; t.count = n;
    g_users = &t;
}
static void test_check_auth(void) {
    static credential_t creds[2];
    safe_strcpy(creds[0].user, "alice", USER_MAX);
    safe_strcpy(creds[0].pass, "secret1", USER_MAX);
    safe_strcpy(creds[1].user, "bob", USER_MAX);
    safe_strcpy(creds[1].pass, "secret2", USER_MAX);
    install_users(creds, 2);

    /* alice:secret1 -> YWxpY2U6c2VjcmV0MQ== */
    char ok[512];
    int l = snprintf(ok, sizeof(ok),
        "GET http://x/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0MQ==\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 1, "valid alice");

    /* bob:secret2 -> Ym9iOnNlY3JldDI= */
    l = snprintf(ok, sizeof(ok),
        "GET / HTTP/1.1\r\nProxy-Authorization: Basic Ym9iOnNlY3JldDI=\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 1, "valid bob (2nd user)");

    /* wrong pass: alice:wrong -> YWxpY2U6d3Jvbmc= */
    l = snprintf(ok, sizeof(ok),
        "GET / HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 0, "wrong pass rejected");

    /* no header */
    l = snprintf(ok, sizeof(ok), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 0, "missing header rejected");

    /* bearer scheme */
    l = snprintf(ok, sizeof(ok),
        "GET / HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 0, "bearer rejected");

    /* case-insensitive header name + extra spaces */
    l = snprintf(ok, sizeof(ok),
        "GET / HTTP/1.1\r\nproxy-authorization:   Basic   YWxpY2U6c2VjcmV0MQ==\r\n\r\n");
    CHECK(check_auth(ok, (size_t)l) == 1, "case-insensitive + spaces");

    g_users = NULL;
}

/* ---- deferred free (use-after-free guard in the epoll dispatch) ---- */
/* conn_close must NOT free the connection inline: a single epoll_wait batch can
 * carry events for both of its fds, so freeing on the first would dangle the
 * second. It must retire (null the back-pointers, mark dead, queue) and let
 * conn_reap() free later. If this is ever reverted to an inline free, reading
 * c->dead below becomes a use-after-free that ASan catches. */
static void test_deferred_free(void) {
    conn_list_t live = {0};
    conn_list_t zombies = {0};
    t_live = &live;
    t_zombies = &zombies;

    connection_t *c = calloc(1, sizeof(*c));
    CHECK(c != NULL, "alloc conn");
    if (!c) return;
    c->client_fd = -1;                 /* no real fds -> conn_close won't close */
    c->upstream_fd = -1;
    c->client_ref.conn = c;   c->client_ref.is_client = 1;
    c->upstream_ref.conn = c; c->upstream_ref.is_client = 0;
    cl_add(&live, c);
    atomic_store(&g_conn_count, 1);

    conn_close(-1, c);                 /* epfd unused since both fds are -1     */

    CHECK(c->dead == 1, "conn marked dead (not freed inline)");
    CHECK(c->client_ref.conn == NULL, "client back-ptr nulled");
    CHECK(c->upstream_ref.conn == NULL, "upstream back-ptr nulled");
    CHECK(live.count == 0, "removed from live registry");
    CHECK(zombies.count == 1, "queued for deferred reap");
    CHECK(atomic_load(&g_conn_count) == 0, "conn count decremented");

    conn_close(-1, c);                 /* idempotent: dead guard prevents double */
    CHECK(zombies.count == 1, "double close is a no-op");

    conn_reap();                       /* frees c (ASan/valgrind verify) */
    CHECK(zombies.count == 0, "reap drains the zombie list");

    free(live.items);
    free(zombies.items);
    t_live = NULL;
    t_zombies = NULL;
}

int main(void) {
    printf("== proxy_login unit tests ==\n");
    test_base64();
    test_ct_equal();
    test_parse_port();
    test_user_list();
    test_strip_header();
    test_check_auth();
    test_deferred_free();
    printf("checks: %d, failures: %d\n", g_checks, g_failures);
    if (g_failures == 0) { printf("ALL UNIT TESTS PASSED\n"); return 0; }
    printf("UNIT TESTS FAILED\n");
    return 1;
}
