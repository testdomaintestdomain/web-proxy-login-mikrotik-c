/* Coverage-guided fuzz harness for proxy_login's untrusted-input parsers:
 * base64_decode, find_header_line, check_auth and strip_header — exactly the
 * code that touches bytes an unauthenticated client controls.
 *
 * Build with libFuzzer:
 *   clang -DPROXY_NO_MAIN -fsanitize=fuzzer,address,undefined \
 *         tests/fuzz_parse.c -pthread -o fuzz_parse
 * Build standalone (no libFuzzer; reads files/stdin as corpus):
 *   cc -DPROXY_NO_MAIN -DSTANDALONE_FUZZ tests/fuzz_parse.c -pthread -o fuzz_parse
 */
#ifndef PROXY_NO_MAIN
#define PROXY_NO_MAIN
#endif
#include "../src/proxy_login.c"

static void ensure_users(void) {
    static int done = 0;
    static credential_t creds[2];
    static user_table_t t;
    if (done) return;
    safe_strcpy(creds[0].user, "alice", USER_MAX);
    safe_strcpy(creds[0].pass, "s3cret", USER_MAX);
    safe_strcpy(creds[1].user, "bob", USER_MAX);
    safe_strcpy(creds[1].pass, "bobpass", USER_MAX);
    t.creds = creds;
    t.count = 2;
    g_users = &t;
    done = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_users();

    /* 1) base64 decoder on the raw bytes. */
    {
        char dst[CRED_MAX];
        base64_decode((const char *)data, size, dst, sizeof(dst));
    }

    /* 2) header parsing + stripping on a bounded copy (as the server does). */
    size_t n = size < HEADER_MAX_SIZE ? size : HEADER_MAX_SIZE;
    char *buf = malloc(HEADER_MAX_SIZE);
    if (!buf) return 0;
    memcpy(buf, data, n);

    /* check_auth expects a head block; it scans up to the given length. */
    (void)check_auth(buf, n);

    size_t hl = n;
    strip_header(buf, &hl, "Proxy-Authorization:", 20);
    strip_header(buf, &hl, "Proxy-Connection:", 17);

    /* find_header_line on an arbitrary key to exercise boundary scans. */
    (void)find_header_line(buf, buf + hl, "Host:", 5);

    free(buf);
    return 0;
}

#ifdef STANDALONE_FUZZ
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) {
        /* read stdin */
        static uint8_t b[1 << 20];
        size_t r = fread(b, 1, sizeof(b), stdin);
        LLVMFuzzerTestOneInput(b, r);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        static uint8_t b[1 << 20];
        size_t r = fread(b, 1, sizeof(b), f);
        fclose(f);
        LLVMFuzzerTestOneInput(b, r);
    }
    return 0;
}
#endif
