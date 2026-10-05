# proxy-login — build and verification harness.
#
#   make              release static binary (musl) -> builds/proxy-login
#   make dev          ASan+UBSan instrumented build
#   make tsan         ThreadSanitizer build
#   make unit         run C unit tests (ASan+UBSan)
#   make integration  run end-to-end Python tests (ASan build)
#   make integration-tsan   end-to-end under ThreadSanitizer
#   make valgrind     end-to-end under Valgrind memcheck
#   make fuzz         short libFuzzer run over the parsers (FUZZ_TIME=30)
#   make lint         cppcheck + shellcheck static analysis
#   make size         enforce the ROM size budget (SIZE_BUDGET bytes)
#   make ci           the full gate: lint unit integration tsan valgrind fuzz size
#   make clean

CC        ?= gcc
MUSL      ?= musl-gcc
CLANG     ?= clang
SRC       := src/proxy_login.c
OUT       := builds
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

WARN      := -std=c11 -Wall -Wextra -Wshadow -Wpointer-arith -Wwrite-strings \
             -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls
REL_FLAGS := -Os -static -pthread -ffunction-sections -fdata-sections \
             -Wl,--gc-sections -flto -DPROXY_VERSION='"$(VERSION)"'
SAN       := -fsanitize=address,undefined -fno-omit-frame-pointer
DBG       := -g -O1 -pthread

FUZZ_TIME   ?= 30
# 128 KiB hard ceiling for the stripped release binary.
SIZE_BUDGET ?= 131072

.PHONY: all build dev tsan unit integration integration-tsan valgrind fuzz \
        lint size leakcheck ci clean

all: build

build: $(OUT)
	$(MUSL) $(WARN) $(REL_FLAGS) $(SRC) -o $(OUT)/proxy-login
	strip -s -R .comment -R .note $(OUT)/proxy-login
	@echo "built $(OUT)/proxy-login ($$(stat -c%s $(OUT)/proxy-login) bytes, version $(VERSION))"

dev: $(OUT)
	$(CC) $(WARN) $(DBG) $(SAN) $(SRC) -o $(OUT)/proxy-login-dev

tsan: $(OUT)
	$(CC) $(WARN) $(DBG) -fsanitize=thread $(SRC) -o $(OUT)/proxy-login-tsan

unit: $(OUT)
	$(CC) $(WARN) $(DBG) $(SAN) tests/unit_test.c -o $(OUT)/unit_test
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 $(OUT)/unit_test

integration: dev
	PROXY_SANITIZED=1 python3 tests/integration_test.py $(OUT)/proxy-login-dev

integration-tsan: tsan
	TSAN_OPTIONS=halt_on_error=1 RELAX_RES=1 PROXY_SANITIZED=1 \
		python3 tests/integration_test.py $(OUT)/proxy-login-tsan

# Release-build end-to-end: no sanitizer, so memory returns to the OS and the
# strict RSS-stability assertion becomes a real per-connection leak check.
leakcheck: build
	python3 tests/integration_test.py $(OUT)/proxy-login

valgrind: $(OUT)
	$(CC) $(WARN) $(DBG) $(SRC) -o $(OUT)/proxy-login-plain
	PROXY_WRAP="valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=definite --track-fds=yes" \
		RELAX_RES=1 python3 tests/integration_test.py $(OUT)/proxy-login-plain

fuzz: $(OUT)
	$(CLANG) -std=c11 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
		-pthread tests/fuzz_parse.c -o $(OUT)/fuzz_parse
	mkdir -p $(OUT)/corpus
	printf 'GET http://x/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n\r\n' > $(OUT)/corpus/seed1
	printf 'CONNECT x:443 HTTP/1.1\r\nProxy-Authorization: Basic Ym9iOmJvYnBhc3M=\r\n\r\n' > $(OUT)/corpus/seed2
	ASAN_OPTIONS=abort_on_error=1 $(OUT)/fuzz_parse -max_total_time=$(FUZZ_TIME) \
		-max_len=9000 -print_final_stats=1 $(OUT)/corpus

lint:
	cppcheck --enable=warning,performance,portability --error-exitcode=1 \
		--inline-suppr --suppress=missingIncludeSystem --std=c11 $(SRC)
	LC_ALL=C.UTF-8 shellcheck -S warning build.sh scripts/*.sh tests/*.sh .claude/hooks/*.sh

size: build
	@sz=$$(stat -c%s $(OUT)/proxy-login); \
	echo "stripped size: $$sz bytes (budget $(SIZE_BUDGET))"; \
	if [ $$sz -gt $(SIZE_BUDGET) ]; then \
		echo "SIZE BUDGET EXCEEDED"; exit 1; \
	fi

ci: lint unit integration integration-tsan valgrind fuzz leakcheck size
	@echo "=============================="
	@echo " ALL CI CHECKS PASSED"
	@echo "=============================="

$(OUT):
	mkdir -p $(OUT)

clean:
	rm -rf $(OUT)
