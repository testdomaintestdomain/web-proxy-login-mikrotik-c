#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

#ifndef PROXY_VERSION
#define PROXY_VERSION "v0.0.1"
#endif

#define BUFFER_SIZE     16384
#define HEADER_MAX_SIZE 8192
#define IO_TIMEOUT_SEC  30
#define STACK_SIZE      (64 * 1024)

typedef struct {
    char auth_user[128];
    char auth_pass[128];
    char upstream_host[128];
    char app_version[64];
    int  upstream_port;
    int  listen_port;
} proxy_config_t;

static proxy_config_t g_config;
static volatile sig_atomic_t g_running = 1;
static int g_server_fd = -1;

static inline void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    snprintf(dst, dst_size, "%s", src);
}

static void log_info(const char *fmt, ...) {
    char time_buf[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    flockfile(stderr);
    fprintf(stderr, "[%s] ", time_buf);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    funlockfile(stderr);
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

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

static int base64_decode(const char *src, char *dst, size_t dst_len) {
    size_t src_len = strlen(src);
    size_t o = 0;
    for (size_t i = 0; i < src_len;) {
        while (i < src_len && ((unsigned char)src[i] <= ' ')) i++;
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
        if (count >= 2 && o < dst_len - 1) dst[o++] = (char)((val >> 16) & 0xFF);
        if (count >= 3 && o < dst_len - 1) dst[o++] = (char)((val >> 8) & 0xFF);
        if (count >= 4 && o < dst_len - 1) dst[o++] = (char)(val & 0xFF);
    }
    dst[o] = '\0';
    return (int)o;
}

static int safe_const_compare(const char *s1, const char *s2) {
    size_t l1 = strlen(s1);
    size_t l2 = strlen(s2);
    volatile unsigned char result = (l1 ^ l2);
    size_t max_len = l1 > l2 ? l1 : l2;
    for (size_t i = 0; i < max_len; i++) {
        unsigned char c1 = (i < l1) ? (unsigned char)s1[i] : 0;
        unsigned char c2 = (i < l2) ? (unsigned char)s2[i] : 0;
        result |= (c1 ^ c2);
    }
    return (result == 0);
}

static const char *find_header(const char *buf, const char *key) {
    size_t klen = strlen(key);
    const char *p = buf;
    while (*p) {
        if ((p == buf || *(p - 1) == '\n') && strncasecmp(p, key, klen) == 0) {
            return p;
        }
        p = strchr(p, '\n');
        if (!p) break;
        p++;
    }
    return NULL;
}

static void set_socket_timeouts(int fd) {
    struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static int verify_and_strip_auth(char *headers, size_t *header_len, const char *client_ip) {
    const char *hdr_start = find_header(headers, "Proxy-Authorization:");
    if (!hdr_start) {
        log_info("[AUTH-DENY] Client %s: Missing 'Proxy-Authorization' header", client_ip);
        return 0;
    }

    const char *token_start = hdr_start + strlen("Proxy-Authorization:");
    while (*token_start == ' ' || *token_start == '\t') token_start++;

    if (strncasecmp(token_start, "Basic ", 6) != 0) {
        log_info("[AUTH-DENY] Client %s: Unsupported scheme (Only Basic supported)", client_ip);
        return 0;
    }
    token_start += 6;
    while (*token_start == ' ' || *token_start == '\t') token_start++;

    char b64_token[256] = {0};
    size_t i = 0;
    while (*token_start && *token_start != '\r' && *token_start != '\n' && i < sizeof(b64_token) - 1) {
        b64_token[i++] = *token_start++;
    }
    b64_token[i] = '\0';

    char decoded[300] = {0};
    if (base64_decode(b64_token, decoded, sizeof(decoded)) <= 0) {
        log_info("[AUTH-DENY] Client %s: Malformed Base64 token", client_ip);
        return 0;
    }

    char expected[300];
    snprintf(expected, sizeof(expected), "%s:%s", g_config.auth_user, g_config.auth_pass);
    if (!safe_const_compare(decoded, expected)) {
        log_info("[AUTH-DENY] Client %s: Invalid credentials", client_ip);
        return 0;
    }

    /* Удаление Proxy-Authorization перед upstream */
    const char *hdr_end = strstr(hdr_start, "\r\n");
    if (hdr_end) {
        hdr_end += 2;
        size_t move_len = (*header_len) - (size_t)(hdr_end - headers);
        memmove((char *)hdr_start, hdr_end, move_len + 1);
        *header_len -= (size_t)(hdr_end - hdr_start);
    }
    return 1;
}

static int send_407(int client_fd) {
    const char *resp = 
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Proxy-Authenticate: Basic realm=\"MikroTik Web Proxy\"\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n";
    return (send(client_fd, resp, strlen(resp), 0) > 0);
}

static int connect_upstream(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    set_socket_timeouts(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_config.upstream_port);

    if (inet_pton(AF_INET, g_config.upstream_host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const char *data, size_t total) {
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = send(fd, data + sent, total - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void forward_bidirectional(int fd1, int fd2, const char *initial_buf, size_t initial_len) {
    if (initial_len > 0) {
        if (send_all(fd2, initial_buf, initial_len) < 0) return;
    }

    struct pollfd fds[2];
    char *buf = malloc(BUFFER_SIZE);
    if (!buf) return;

    fds[0].fd = fd1; fds[0].events = POLLIN;
    fds[1].fd = fd2; fds[1].events = POLLIN;

    while (g_running) {
        int ret = poll(fds, 2, IO_TIMEOUT_SEC * 1000);
        if (ret <= 0) break;

        if (fds[0].revents & POLLIN) {
            ssize_t n = recv(fd1, buf, BUFFER_SIZE, 0);
            if (n <= 0) break;
            if (send_all(fd2, buf, (size_t)n) < 0) break;
        }
        if (fds[1].revents & POLLIN) {
            ssize_t n = recv(fd2, buf, BUFFER_SIZE, 0);
            if (n <= 0) break;
            if (send_all(fd1, buf, (size_t)n) < 0) break;
        }
        if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;
        }
    }
    free(buf);
}

typedef struct {
    int fd;
    char ip[INET_ADDRSTRLEN];
    int port;
} client_context_t;

static void *handle_client(void *arg) {
    client_context_t *ctx = (client_context_t *)arg;
    int client_fd = ctx->fd;
    set_socket_timeouts(client_fd);

    char *header_buf = malloc(HEADER_MAX_SIZE);
    if (!header_buf) {
        close(client_fd);
        free(ctx);
        return NULL;
    }

    size_t total_read = 0;
    int header_complete = 0;
    while (total_read < HEADER_MAX_SIZE - 1 && g_running) {
        ssize_t n = recv(client_fd, header_buf + total_read, HEADER_MAX_SIZE - 1 - total_read, 0);
        if (n <= 0) goto cleanup;
        total_read += n;
        header_buf[total_read] = '\0';
        if (strstr(header_buf, "\r\n\r\n")) {
            header_complete = 1;
            break;
        }
    }

    if (!header_complete || !verify_and_strip_auth(header_buf, &total_read, ctx->ip)) {
        send_407(client_fd);
        goto cleanup;
    }

    int upstream_fd = connect_upstream();
    if (upstream_fd < 0) {
        const char *err502 = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
        send(client_fd, err502, strlen(err502), 0);
        goto cleanup;
    }

    forward_bidirectional(client_fd, upstream_fd, header_buf, total_read);
    close(upstream_fd);

cleanup:
    free(header_buf);
    close(client_fd);
    free(ctx);
    return NULL;
}

static int load_and_validate_config(void) {
    memset(&g_config, 0, sizeof(proxy_config_t));
    const char *env_user  = getenv("PROXY_USER");
    const char *env_pass  = getenv("PROXY_PASS");
    const char *env_host  = getenv("UPSTREAM_HOST");
    const char *env_uport = getenv("UPSTREAM_PORT");
    const char *env_lport = getenv("LISTEN_PORT");
    const char *env_ver   = getenv("PROXY_VER");

    /* Обязательные учетные данные: без них запуск небезопасен */
    if (!env_user || !env_pass || !env_host || !env_uport) {
        log_info("[FATAL] Missing required environment variables (PROXY_USER, PROXY_PASS, UPSTREAM_HOST, UPSTREAM_PORT)!");
        return -1;
    }

    safe_strcpy(g_config.auth_user, env_user, sizeof(g_config.auth_user));
    safe_strcpy(g_config.auth_pass, env_pass, sizeof(g_config.auth_pass));
    safe_strcpy(g_config.upstream_host, env_host, sizeof(g_config.upstream_host));
    g_config.upstream_port = atoi(env_uport);
    g_config.listen_port = (env_lport && env_lport[0] != '\0') ? atoi(env_lport) : 8080;

    /* Логика версионирования: если PROXY_VER не передан, используем вшитую константу */
    if (env_ver && env_ver[0] != '\0') {
        safe_strcpy(g_config.app_version, env_ver, sizeof(g_config.app_version));
    } else {
        safe_strcpy(g_config.app_version, PROXY_VERSION, sizeof(g_config.app_version));
    }

    if (g_config.upstream_port <= 0 || g_config.upstream_port > 65535 ||
        g_config.listen_port <= 0 || g_config.listen_port > 65535) {
        log_info("[FATAL] Invalid port configuration!");
        return -1;
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (load_and_validate_config() != 0) return 1;

    log_info("=================================================");
    log_info("Starting MikroTik Auth-Proxy Shim %s", g_config.app_version);
    log_info("Binary built-in version : %s", PROXY_VERSION);
    log_info("Environment PROXY_VER   : %s", getenv("PROXY_VER") ? getenv("PROXY_VER") : "(not specified - running on built-in)");
    log_info("=================================================");

    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) return 1;

    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_config.listen_port);

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(g_server_fd, 512) < 0) {
        close(g_server_fd);
        return 1;
    }

    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&thread_attr, STACK_SIZE);

    log_info("[OK] Ready and listening on port %d", g_config.listen_port);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR || !g_running) break;
            continue;
        }

        client_context_t *ctx = malloc(sizeof(client_context_t));
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->fd = client_fd;
        inet_ntop(AF_INET, &client_addr.sin_addr, ctx->ip, sizeof(ctx->ip));
        ctx->port = ntohs(client_addr.sin_port);

        pthread_t tid;
        if (pthread_create(&tid, &thread_attr, handle_client, ctx) != 0) {
            close(client_fd);
            free(ctx);
        }
    }

    pthread_attr_destroy(&thread_attr);
    if (g_server_fd >= 0) close(g_server_fd);
    return 0;
}