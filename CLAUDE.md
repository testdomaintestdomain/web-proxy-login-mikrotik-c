# Repo guide for Claude Code

Ultralight C11 HTTP Basic-auth shim placed in front of the MikroTik RouterOS
built-in Web-Proxy. Ships as a `FROM scratch` container (static musl binary +
an empty `/etc/resolv.conf`). Design priorities, in order: **security**, **tiny
ROM/RAM footprint**, **many concurrent users**.

## Layout

- `src/proxy_login.c` — the entire program (single translation unit). A
  non-blocking `epoll` event loop per worker thread; workers share the listen
  socket via `SO_REUSEPORT`. `main()` is wrapped in `#ifndef PROXY_NO_MAIN` so
  tests can `#include` the file and reach the file-static functions.
- `tests/unit_test.c` — unit tests for the pure parsers (include the .c直接).
- `tests/integration_test.py` — end-to-end: mock upstream + real sockets.
- `tests/fuzz_parse.c` — libFuzzer harness for the untrusted-input parsers.
- `tests/*.sh` — optional black-box scripts against a running container.
- `Makefile` — the harness entry point (see below).
- `docs/index.html` — standalone web configurator (generates RouterOS scripts).
- `build.sh` + `scripts/mkdockertar-c.sh` — multi-arch release artifacts.

## Harness (always use the Makefile)

```
make            # release static musl binary -> builds/proxy-login
make unit       # C unit tests (ASan+UBSan)
make integration       # end-to-end (ASan+UBSan)
make integration-tsan  # end-to-end under ThreadSanitizer
make valgrind          # end-to-end under Valgrind memcheck (0 errors/leaks)
make fuzz FUZZ_TIME=30 # libFuzzer over the parsers
make lint       # cppcheck + shellcheck
make size       # enforce the 128 KiB ROM budget
make ci         # the full gate (run this before committing C changes)
```

The toolchain (`musl-tools cppcheck shellcheck valgrind clang libclang-rt-18-dev`)
is installed automatically in cloud sessions by `.claude/hooks/session-start.sh`.

## Rules of thumb

- Any change to `src/proxy_login.c` must pass `make ci` (all sanitizers clean,
  Valgrind 0 errors, fuzzer no crashes, size under budget).
- Never log or forward credentials. `Proxy-Authorization` must never reach the
  upstream — `make integration` asserts this.
- Keep per-connection memory small; the event-loop model is deliberate. Do not
  reintroduce thread-per-connection.
- The configurator must RouterOS-escape every user-supplied value (`escapeRos`)
  and HTML-escape anything injected into the DOM.
