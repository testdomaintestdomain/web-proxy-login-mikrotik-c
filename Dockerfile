ARG BASE=alpine:latest
FROM ${BASE} AS builder

ARG VERSION=dev

RUN if command -v apk >/dev/null; then \
        apk add --no-cache gcc musl-dev make; \
    else \
        apt-get update && apt-get install -y --no-install-recommends gcc musl-tools musl-dev make && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src
COPY ./src/proxy_login.c .

# Сборка ультралегкого статического бинарника под musl с внедрением версии
RUN mkdir -p /out/etc && \
    CC=$(command -v musl-gcc || echo gcc) && \
    $CC -std=c11 -Os -static -Wall -Wextra -pthread \
        -DPROXY_VERSION="\"${VERSION}\"" \
        -ffunction-sections -fdata-sections -Wl,--gc-sections -flto \
        proxy_login.c -o /out/proxy_login && \
    strip -s -R .comment -R .note /out/proxy_login && \
    chmod 0755 /out/proxy_login && \
    chmod 0755 /out/etc && \
    touch /out/etc/resolv.conf && \
    chmod 0644 /out/etc/resolv.conf

FROM scratch
COPY --from=builder /out/proxy_login /proxy_login
COPY --from=builder /out/etc /etc
EXPOSE 8080
ENTRYPOINT ["/proxy_login"]