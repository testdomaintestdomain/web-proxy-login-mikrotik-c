#!/usr/bin/env bash
set -u

PROXY_HOST="${1:-127.0.0.1}"
PROXY_PORT="${2:-8080}"
VALID_USER="${3:-myuser}"
VALID_PASS="${4:-mypassword123}"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
START_TIME=$(date +%s)

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'

log_suite() {
    echo -e "\n${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  $1${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
}

assert_http_code() {
    local test_name="$1"
    local expected="$2"
    local curl_cmd="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local code
    code=$(eval "${curl_cmd} -s -o /dev/null -w '%{http_code}' --max-time 3" 2>/dev/null || echo "000")
    
    if [ "$code" = "$expected" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -n -e "${C_GREEN}.${C_RESET}"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "\n${C_RED}[FAIL] ${test_name} -> Ожидался: ${expected}, Получен: ${code}${C_RESET}"
    fi
}

assert_raw_tcp() {
    local test_name="$1"
    local raw_payload="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    printf "%b" "$raw_payload" | nc -w 1 "$PROXY_HOST" "$PROXY_PORT" >/dev/null 2>&1 || true
    
    local alive_code
    alive_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 -x "http://${PROXY_HOST}:${PROXY_PORT}" "http://example.com" 2>/dev/null || echo "000")
    
    if [ "$alive_code" = "407" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -n -e "${C_GREEN}.${C_RESET}"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "\n${C_RED}[CRASH/FAIL] ${test_name} -> Сервер перестал отвечать!${C_RESET}"
    fi
}

echo -e "${C_BOLD}Запуск 1000-тестового QA-пакета для proxy_login...${C_RESET}"
echo -e "Цель: ${C_YELLOW}http://${PROXY_HOST}:${PROXY_PORT}${C_RESET} | Эталон: ${C_YELLOW}${VALID_USER}:${VALID_PASS}${C_RESET}"

# ==============================================================================
# БЛОК 1: АВТОРИЗАЦИОННАЯ МАТРИЦА И СПЕЦСИМВОЛЫ (100 ТЕСТОВ)
# ==============================================================================
log_suite "БЛОК 1: Авторизационная матрица, спецсимволы и Base64 (100 тестов)"

assert_http_code "No Auth Header" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} http://example.com"
assert_http_code "Empty User and Pass" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user ':' http://example.com"
assert_http_code "Only User" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user '${VALID_USER}:' http://example.com"
assert_http_code "Only Pass" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user ':${VALID_PASS}' http://example.com"

# 30 тестов неверных паролей и логинов
for i in {1..30}; do
    assert_http_code "Wrong Pass $i" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user '${VALID_USER}:wrong_pass_${i}' http://example.com"
    assert_http_code "Wrong User $i" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user 'wrong_user_${i}:${VALID_PASS}' http://example.com"
done

# 30 тестов со сложными спецсимволами (используется безопасный флаг --proxy-user)
SPECIAL_PASSWORDS=(
    'pass!123' 'pass@123' 'pass#123' 'pass$123' 'pass%123' 'pass^123' 'pass&123' 
    'pass*123' 'pass(123)' 'pass_123' 'pass+123' 'pass-123' 'pass=123' 'pass[123]'
    'pass{123}' 'pass|123' 'pass;123' 'pass,123' 'pass.123' 'pass<123>' 'pass?123'
    'pass~123' 'pass`123' 'pass/123' 'p@$$w0rd!_#2026' 'LongPasswordStringExceedingNormalLength64Chars'
    'SpacesInPassword123' 'pass:with:colons' 'pass\slashes' 'user:pass'
)

for p in "${SPECIAL_PASSWORDS[@]}"; do
    assert_http_code "Special Char Pass: $p" "407" "curl -x http://${PROXY_HOST}:${PROXY_PORT} --proxy-user '${VALID_USER}:${p}' http://example.com"
done

B64_VALID=$(echo -n "${VALID_USER}:${VALID_PASS}" | base64)
assert_raw_tcp "Case: proxy-authorization lowercase" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nproxy-authorization: Basic ${B64_VALID}\r\n\r\n"
assert_raw_tcp "Case: PROXY-AUTHORIZATION UPPERCASE" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nPROXY-AUTHORIZATION: BASIC ${B64_VALID}\r\n\r\n"
assert_raw_tcp "Case: pRoXy-AuThOrIzAtIoN mixed" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\npRoXy-AuThOrIzAtIoN: Basic ${B64_VALID}\r\n\r\n"
assert_raw_tcp "Spaces before token" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic    ${B64_VALID}\r\n\r\n"
assert_raw_tcp "Tabs before token" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic\t\t${B64_VALID}\r\n\r\n"
assert_raw_tcp "Malformed Base64" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ABCDE==\r\n\r\n"
assert_raw_tcp "Invalid chars Base64" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic @@@@====\r\n\r\n"
assert_raw_tcp "Empty Basic" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic \r\n\r\n"
assert_raw_tcp "No Basic keyword" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: ${B64_VALID}\r\n\r\n"
assert_raw_tcp "Bearer token" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Bearer token123\r\n\r\n"

# ==============================================================================
# БЛОК 2: BOUNDARY VALUES & SECURITY FUZZING (200 ТЕСТОВ)
# ==============================================================================
log_suite "БЛОК 2: Граничные размеры (8KB Buffer Limit), Fuzzing и Атаки (200 тестов)"

SIZES=(100 500 1000 2000 4000 6000 7000 8000 8100 8180 8190 8191 8192 8193 8200 8500 9000 12000 16000 32000 65535)
for s in "${SIZES[@]}"; do
    JUNK_HEADER=$(python3 -c "print('X-Junk: ' + 'A' * $s)" 2>/dev/null || printf 'X-Junk: %0.sA' $(seq 1 $s))
    assert_raw_tcp "Header Size ${s} bytes" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n${JUNK_HEADER}\r\n\r\n"
done

for len in $(seq 100 200 6000); do
    URI_PATH=$(printf 'a%0.s' $(seq 1 $len))
    assert_raw_tcp "Long URI /${len}" "GET http://example.com/${URI_PATH} HTTP/1.1\r\nHost: example.com\r\n\r\n"
done

CRLF_ATTACKS=(
    "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ${B64_VALID}\r\n\r\nGET http://evil.com HTTP/1.1\r\n\r\n"
    "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\nProxy-Authorization: Basic ${B64_VALID}\r\n\r\n\x00\x01\x02\x03\xFF\xFF"
    "\r\n\r\n\r\n\r\n"
    "GET / HTTP/1.1\nHost: example.com\n\n"
    "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization:\x00Basic ${B64_VALID}\r\n\r\n"
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\xFF\xF4\xFF\xFD\x06"
)

for payload in "${CRLF_ATTACKS[@]}"; do
    assert_raw_tcp "CRLF/Smuggling Payload" "$payload"
done

for i in {1..92}; do
    NOISE_PAYLOAD=$(head -c $((i * 50)) /dev/urandom | base64)
    assert_raw_tcp "Binary Noise $i" "$NOISE_PAYLOAD"
done

for i in {1..50}; do
    assert_raw_tcp "Slowloris Header $i" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Slow: ${i}"
done

# ==============================================================================
# БЛОК 3: HTTP МЕТОДЫ И ПРОТОКОЛЫ (100 ТЕСТОВ)
# ==============================================================================
log_suite "БЛОК 3: HTTP методы, CONNECT и протоколы (100 тестов)"

HTTP_METHODS=('GET' 'POST' 'PUT' 'DELETE' 'HEAD' 'OPTIONS' 'PATCH' 'TRACE' 'CONNECT' 'CUSTOM')

for method in "${HTTP_METHODS[@]}"; do
    for proto in "HTTP/1.0" "HTTP/1.1"; do
        for port in 80 443 8080 8443 3128; do
            if [ "$method" = "CONNECT" ]; then
                REQ="CONNECT example.com:${port} ${proto}\r\nHost: example.com:${port}\r\nProxy-Authorization: Basic ${B64_VALID}\r\n\r\n"
            else
                REQ="${method} http://example.com:${port}/test ${proto}\r\nHost: example.com:${port}\r\nProxy-Authorization: Basic ${B64_VALID}\r\n\r\n"
            fi
            assert_raw_tcp "Method ${method} ${proto} on port ${port}" "$REQ"
        done
    done
done

# ==============================================================================
# БЛОК 4: МУТАЦИОННЫЙ ФАЗЗИНГ (400 ТЕСТОВ)
# ==============================================================================
log_suite "БЛОК 4: Автоматизированный мутационный фаззинг (400 тестов)"

for i in {1..400}; do
    RND_USER=$(head -c $(( (i % 30) + 1 )) /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
    RND_PASS=$(head -c $(( (i % 50) + 1 )) /dev/urandom | base64 | tr -dc 'a-zA-Z0-9!@#$%^&*()')
    RND_B64=$(echo -n "${RND_USER}:${RND_PASS}" | base64)
    RND_METHOD=$( [ $((i % 2)) -eq 0 ] && echo "GET" || echo "CONNECT" )
    RND_JUNK_LEN=$(( (i * 17) % 3000 ))
    RND_JUNK=$(head -c $RND_JUNK_LEN /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
    
    PAYLOAD="${RND_METHOD} http://test${i}.com/ HTTP/1.1\r\nHost: test${i}.com\r\nProxy-Authorization: Basic ${RND_B64}\r\nX-Fuzz-${i}: ${RND_JUNK}\r\n\r\n"
    assert_raw_tcp "Fuzz Iteration $i" "$PAYLOAD"
done

# ==============================================================================
# БЛОК 5: КОНКУРЕНТНАЯ НАГРУЗКА (200 ТЕСТОВ)
# ==============================================================================
log_suite "БЛОК 5: Конкурентная нагрузка (200 параллельных воркеров)"

PIDS=()
for i in {1..200}; do
    (
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -x "http://${PROXY_HOST}:${PROXY_PORT}" "http://example.com" 2>/dev/null || echo "000")
        if [ "$code" = "407" ]; then exit 0; else exit 1; fi
    ) &
    PIDS+=($!)
done

CONCURRENT_SUCCESS=0
CONCURRENT_FAIL=0
for pid in "${PIDS[@]}"; do
    if wait "$pid"; then
        CONCURRENT_SUCCESS=$((CONCURRENT_SUCCESS + 1))
        echo -n -e "${C_GREEN}.${C_RESET}"
    else
        CONCURRENT_FAIL=$((CONCURRENT_FAIL + 1))
        echo -n -e "${C_RED}x${C_RESET}"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
done

PASSED_TESTS=$((PASSED_TESTS + CONCURRENT_SUCCESS))
FAILED_TESTS=$((FAILED_TESTS + CONCURRENT_FAIL))

# ==============================================================================
# ИТОГОВЫЙ ОТЧЕТ
# ==============================================================================
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION=$(( DURATION > 0 ? DURATION : 1 ))
RPS=$(( TOTAL_TESTS / DURATION ))

echo -e "\n\n${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}  ИТОГОВЫЙ ОТЧЕТ ТЕСТИРОВАНИЯ (QA SUMMARY)${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "  Всего выполнено тестов : ${C_BOLD}${TOTAL_TESTS}${C_RESET}"
echo -e "  Успешно (Passed)       : ${C_GREEN}${PASSED_TESTS}${C_RESET}"
echo -e "  Ошибки / Падения (Fail): $( [ $FAILED_TESTS -eq 0 ] && echo -e "${C_GREEN}0${C_RESET}" || echo -e "${C_RED}${FAILED_TESTS}${C_RESET}" )"
echo -e "  Время выполнения       : ${C_YELLOW}${DURATION} сек${C_RESET}"
echo -e "  Производительность     : ${C_YELLOW}~${RPS} тестов/сек${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${C_BOLD}${C_GREEN}✔ ПОЛНЫЙ УСПЕХ: Все 1000 проверок пройдены со 100% результатом!${C_RESET}\n"
    exit 0
else
    echo -e "${C_BOLD}${C_RED}✖ ТЕСТ ПРОВАЛЕН: Обнаружено ${FAILED_TESTS} ошибок.${C_RESET}\n"
    exit 1
fi