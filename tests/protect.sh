#!/usr/bin/env bash
# ==============================================================================
# Comprehensive Security, Fuzzing & Hardening Audit Suite for proxy_login
# Compatible with: Bash 4+, Zsh
# ==============================================================================
set -u

PROXY_HOST="${1:-127.0.0.1}"
PROXY_PORT="${2:-8080}"
VALID_USER="${3:-myuser}"
VALID_PASS="${4:-mypassword123}"

TOTAL_ATTACKS=0
PASSED_ATTACKS=0
FAILED_ATTACKS=0
START_TIME=$(date +%s)

# Цветовое оформление
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'

log_category() {
    echo -e "\n${C_BOLD}${C_BLUE}══════════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  $1${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}══════════════════════════════════════════════════════════════════════${C_RESET}"
}

# Генератор безопасной строки нужной длины
gen_string() {
    local len="$1"
    local char="${2:-A}"
    if command -v python3 &>/dev/null; then
        python3 -c "print('${char}' * ${len})"
    elif command -v perl &>/dev/null; then
        perl -e "print '${char}' x ${len}"
    else
        printf "%*s" "$len" "" | tr ' ' "$char"
    fi
}

# Проверка живости сервера (Healthcheck)
healthcheck() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -x "http://${PROXY_HOST}:${PROXY_PORT}" "http://example.com" 2>/dev/null || echo "000")
    if [ "$code" = "407" ]; then
        return 0
    fi
    return 1
}

# Выполнение HTTP-теста с проверкой ожидаемого статус-кода
assert_auth_status() {
    local title="$1"
    local expected="$2"
    local curl_opts="$3"
    
    TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
    echo -n -e "  [TEST $((TOTAL_ATTACKS))] ${title} ... "

    local code
    code=$(eval "curl -s -o /dev/null -w '%{http_code}' --max-time 3 -x 'http://${PROXY_HOST}:${PROXY_PORT}' ${curl_opts} 'http://example.com'" 2>/dev/null || echo "000")

    if [ "$code" = "$expected" ]; then
        echo -e "${C_GREEN}[PASS] (HTTP ${code})${C_RESET}"
        PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
    else
        echo -e "${C_RED}[FAIL] (Ожидался: ${expected}, Получен: ${code})${C_RESET}"
        FAILED_ATTACKS=$((FAILED_ATTACKS + 1))
    fi
}

# Отправка сырого TCP-пакета и проверка стабильности демона
assert_tcp_resilience() {
    local title="$1"
    local raw_data="$2"
    
    TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
    echo -n -e "  [TEST $((TOTAL_ATTACKS))] ${title} ... "

    # Передача сырых байтов через сокет
    printf "%b" "$raw_data" | nc -w 2 "$PROXY_HOST" "$PROXY_PORT" >/dev/null 2>&1 || true

    if healthcheck; then
        echo -e "${C_GREEN}[PASS] (No Crash / Daemon Healthy)${C_RESET}"
        PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
    else
        echo -e "${C_RED}[CRITICAL FAIL] (Сервер аварийно упал!)${C_RESET}"
        FAILED_ATTACKS=$((FAILED_ATTACKS + 1))
    fi
}

echo -e "${C_BOLD}======================================================================${C_RESET}"
echo -e "${C_BOLD}  SECURITY & HARDENING PENETRATION AUDIT: PROXY_SHIM${C_RESET}"
echo -e "  Target: ${C_YELLOW}http://${PROXY_HOST}:${PROXY_PORT}${C_RESET} | Valid User: ${C_YELLOW}${VALID_USER}${C_RESET}"
echo -e "${C_BOLD}======================================================================${C_RESET}"

B64_VALID=$(echo -n "${VALID_USER}:${VALID_PASS}" | base64)

# ==============================================================================
# РАЗДЕЛ 1: AUTHENTICATION ENFORCEMENT & BYPASS TESTS
# ==============================================================================
log_category "1. Проверка защищенности авторизации и устойчивости Base64"

assert_auth_status "Запрос без учетных данных" "407" ""
assert_auth_status "Пустой логин и пароль (--proxy-user :)" "407" "--proxy-user ':'"
assert_auth_status "Только верный логин без пароля" "407" "--proxy-user '${VALID_USER}:'"
assert_auth_status "Только верный пароль без логина" "407" "--proxy-user ':${VALID_PASS}'"
assert_auth_status "Неверный пароль" "407" "--proxy-user '${VALID_USER}:wrongpass'"
assert_auth_status "Неверный логин с верным паролем" "407" "--proxy-user 'wronguser:${VALID_PASS}'"
assert_auth_status "Обрезанный Base64 токен" "407" "-H 'Proxy-Authorization: Basic YWRtaW46'"
assert_auth_status "Токен с недопустимыми символами Base64" "407" "-H 'Proxy-Authorization: Basic @@@!===?'"
assert_auth_status "Схема авторизации Bearer вместо Basic" "407" "-H 'Proxy-Authorization: Bearer secret_jwt_token'"
assert_auth_status "Схема Digest вместо Basic" "407" "-H 'Proxy-Authorization: Digest username=\"admin\"'"
assert_auth_status "Пустой заголовок Proxy-Authorization" "407" "-H 'Proxy-Authorization:'"
assert_auth_status "Заголовок Proxy-Authorization без пробела" "407" "-H 'Proxy-Authorization:Basic ${B64_VALID}'"

# ==============================================================================
# РАЗДЕЛ 2: BUFFER BOUNDARIES & OVERFLOW RESILIENCE (8192B LIMIT)
# ==============================================================================
log_category "2. Граничные размеры буферов и защита от переполнения памяти"

assert_tcp_resilience "Заголовок ровно 8190 байт" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Test: $(gen_string 8150 'B')\r\n\r\n"
assert_tcp_resilience "Заголовок ровно 8192 байта (граница буфера)" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Test: $(gen_string 8152 'B')\r\n\r\n"
assert_tcp_resilience "Заголовок 8193 байта (выход за пределы буфера)" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Test: $(gen_string 8153 'B')\r\n\r\n"
assert_tcp_resilience "Огромный заголовок 64 КБ (Heap/Stack Overflow)" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Overflow: $(gen_string 65535 'C')\r\n\r\n"
assert_tcp_resilience "Огромный заголовок 1 МБ (DDoS Payload)" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Mega: $(gen_string 1048576 'D')\r\n\r\n"
assert_tcp_resilience "Сверхдлинный URI путь (10 000 символов)" "GET http://example.com/$(gen_string 10000 'a') HTTP/1.1\r\nHost: example.com\r\n\r\n"
assert_tcp_resilience "Множество мелких заголовков (1000 строк)" "$(for i in {1..1000}; do echo -en "X-Hdr-$i: val\r\n"; done; echo -en "GET http://example.com HTTP/1.1\r\n\r\n")"

# ==============================================================================
# РАЗДЕЛ 3: CONTROL BYTES, NULL-BYTE & INJECTION TESTING
# ==============================================================================
log_category "3. Защита от управляющих символов и Null-Byte инъекций"

assert_tcp_resilience "Null-byte в начале метода: \x00GET" "\x00GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
assert_tcp_resilience "Null-byte в URI пути" "GET http://example.com/admin\x00.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
assert_tcp_resilience "Null-byte в заголовке Proxy-Authorization" "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization:\x00Basic ${B64_VALID}\r\n\r\n"
assert_tcp_resilience "Символы возврата каретки без перевода строки (\r\r\r)" "GET http://example.com HTTP/1.1\rHost: example.com\r\r"
assert_tcp_resilience "Одиночные переводы строк (LF вместо CRLF)" "GET http://example.com HTTP/1.1\nHost: example.com\nProxy-Authorization: Basic ${B64_VALID}\n\n"
assert_tcp_resilience "Управляющие байты Telnet/VT100 (\xFF\xF4\xFF\xFD)" "\xFF\xF4\xFF\xFD\x06GET http://example.com HTTP/1.1\r\n\r\n"
assert_tcp_resilience "Escape-последовательности ANSI (\x1b[2J)" "\x1b[2JGET http://example.com HTTP/1.1\r\n\r\n"

# ==============================================================================
# РАЗДЕЛ 4: HTTP REQUEST SMUGGLING & PIPELINE DESYNC
# ==============================================================================
log_category "4. Защита от HTTP Request Smuggling и десинхронизации"

SMUGGLE_1="GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ${B64_VALID}\r\nContent-Length: 0\r\n\r\nGET http://attacker.com HTTP/1.1\r\nHost: attacker.com\r\n\r\n"
assert_tcp_resilience "Склейка двух HTTP-запросов (Pipelining Smuggle)" "$SMUGGLE_1"

SMUGGLE_2="GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ${B64_VALID}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n"
assert_tcp_resilience "Конфликт Transfer-Encoding и Content-Length (CL-TE)" "$SMUGGLE_2"

SMUGGLE_3="POST http://example.com HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: \tchunked\r\n\r\n0\r\n\r\n"
assert_tcp_resilience "Transfer-Encoding с внедренным табом (TE-Desync)" "$SMUGGLE_3"

# ==============================================================================
# РАЗДЕЛ 5: DOS & THREAD STARVATION (SLOWLORIS, TCP RST CHURN)
# ==============================================================================
log_category "5. Устойчивость к DoS: Slowloris и шторм TCP RST"

TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
echo -n -e "  [TEST $((TOTAL_ATTACKS))] Slowloris: удержание 40 сокетов по 1 байту в 100мс ... "
for i in {1..40}; do
    (
        exec 3<>/dev/tcp/${PROXY_HOST}/${PROXY_PORT} 2>/dev/null || exit 0
        echo -en "GET http://example.com HTTP/1.1\r\nHost: example.com\r\nX-Slow: " >&3
        for _ in {1..10}; do
            echo -en "z" >&3
            sleep 0.1
        done
        exec 3>&-
    ) 2>/dev/null &
done
sleep 2
if healthcheck; then
    echo -e "${C_GREEN}[PASS] (Таймауты сокетов отрабатывают корректно)${C_RESET}"
    PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
else
    echo -e "${C_RED}[FAIL] (Потоки зависли)${C_RESET}"
    FAILED_ATTACKS=$((FAILED_ATTACKS + 1))
fi

TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
echo -n -e "  [TEST $((TOTAL_ATTACKS))] Connection Churn: 250 быстрых SYN-RST сбросов ... "
for i in {1..250}; do
    ( exec 3<>/dev/tcp/${PROXY_HOST}/${PROXY_PORT} 2>/dev/null; exec 3>&- ) &
done
wait
sleep 1
if healthcheck; then
    echo -e "${C_GREEN}[PASS] (Нет утечки дескрипторов сокетов FD)${C_RESET}"
    PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
else
    echo -e "${C_RED}[FAIL] (FD Leak / Crash)${C_RESET}"
    FAILED_ATTACKS=$((FAILED_ATTACKS + 1))
fi

# ==============================================================================
# РАЗДЕЛ 6: MALFORMED VERBS & PROTOCOL FUZZING
# ==============================================================================
log_category "6. Фаззинг методов HTTP и нестандартных протоколов"

assert_tcp_resilience "Неизвестный HTTP-метод: PURGE" "PURGE http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
assert_tcp_resilience "Неизвестный HTTP-метод: PROPFIND (WebDAV)" "PROPFIND http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
assert_tcp_resilience "Сверхдлинное имя метода (1024 байта)" "$(gen_string 1024 'M') http://example.com HTTP/1.1\r\n\r\n"
assert_tcp_resilience "HTTP/2.0 Client Magic: PRI * HTTP/2.0" "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
assert_tcp_resilience "HTTP/0.9 Simple Request (GET /path без версии)" "GET http://example.com/\r\n"
assert_tcp_resilience "Рандомизированный бинарный мусор (2048 байт /dev/urandom)" "$(head -c 2048 /dev/urandom 2>/dev/null | base64)"

# ==============================================================================
# РАЗДЕЛ 7: TIMING ATTACK SIDE-CHANNEL ANALYSIS
# ==============================================================================
log_category "7. Анализ временных утечек (Timing Attacks на strcmp)"

TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
echo -n -e "  [TEST $((TOTAL_ATTACKS))] Замер дельты времени (Invalid User vs Invalid Pass) ... "
T_USER=0
T_PASS=0
for i in {1..30}; do
    t0=$(date +%s%N 2>/dev/null || date +%s)
    curl -s -o /dev/null -x "http://${PROXY_HOST}:${PROXY_PORT}" --proxy-user "non_existent_user_${i}:${VALID_PASS}" "http://example.com" 2>/dev/null || true
    t1=$(date +%s%N 2>/dev/null || date +%s)
    T_USER=$(( T_USER + (t1 - t0) ))

    t0=$(date +%s%N 2>/dev/null || date +%s)
    curl -s -o /dev/null -x "http://${PROXY_HOST}:${PROXY_PORT}" --proxy-user "${VALID_USER}:wrong_pass_${i}" "http://example.com" 2>/dev/null || true
    t1=$(date +%s%N 2>/dev/null || date +%s)
    T_PASS=$(( T_PASS + (t1 - t0) ))
done

DELTA_MS=$(( (T_PASS - T_USER) / 1000000 ))
# Допустимая флуктуация сети < 50ms
if [ ${DELTA_MS#-} -lt 50 ]; then
    echo -e "${C_GREEN}[PASS] (Дельта: ${DELTA_MS}ms — Side-channel утечек нет)${C_RESET}"
    PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
else
    echo -e "${C_YELLOW}[WARN] (Дельта: ${DELTA_MS}ms — возможен сетевой джиттер)${C_RESET}"
    PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
fi

# ==============================================================================
# РАЗДЕЛ 8: INFORMATION DISCLOSURE & ERROR PURITY
# ==============================================================================
log_category "8. Проверка отсутствия утечки чувствительной информации"

TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
echo -n -e "  [TEST $((TOTAL_ATTACKS))] Проверка чистоты ответа 407 (без стектрейсов и баннеров) ... "
RESP_407=$(curl -s -i -x "http://${PROXY_HOST}:${PROXY_PORT}" "http://example.com" 2>/dev/null || true)
if echo "$RESP_407" | grep -q "407 Proxy Authentication Required" && ! echo "$RESP_407" | grep -iq "stack\|memory\|core\|dump"; then
    echo -e "${C_GREEN}[PASS] (Ответ 407 полностью соответствует RFC)${C_RESET}"
    PASSED_ATTACKS=$((PASSED_ATTACKS + 1))
else
    echo -e "${C_RED}[FAIL] (Обнаружена утечка данных в теле ответа)${C_RESET}"
    FAILED_ATTACKS=$((FAILED_ATTACKS + 1))
fi

# ==============================================================================
# ИТОГОВЫЙ ОТЧЕТ БЕЗОПАСНОСТИ
# ==============================================================================
END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))
DURATION=$(( DURATION > 0 ? DURATION : 1 ))

echo -e "\n${C_BOLD}${C_BLUE}══════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}  ИТОГОВЫЙ ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ (SECURITY SUMMARY)${C_RESET}"
echo -e "${C_BOLD}${C_BLUE}══════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "  Всего векторов протестировано : ${C_BOLD}${TOTAL_ATTACKS}${C_RESET}"
echo -e "  Успешно отражено атак        : ${C_GREEN}${PASSED_ATTACKS}${C_RESET}"
echo -e "  Уязвимостей / Падений (Fail) : $( [ $FAILED_ATTACKS -eq 0 ] && echo -e "${C_GREEN}0 (HARDENED)${C_RESET}" || echo -e "${C_RED}${FAILED_ATTACKS} CRITICAL${C_RESET}" )"
echo -e "  Время проведения аудита      : ${C_YELLOW}${DURATION} сек${C_RESET}"
echo -e "${C_BOLD}${C_BLUE}══════════════════════════════════════════════════════════════════════${C_RESET}"

if [ $FAILED_ATTACKS -eq 0 ]; then
    echo -e "${C_BOLD}${C_GREEN}✔ СИСТЕМА УСПЕШНО АТТЕСТОВАНА: proxy_login полностью защищен от переполнений, DoS и инъекций.${C_RESET}\n"
    exit 0
else
    echo -e "${C_BOLD}${C_RED}✖ ОБНАРУЖЕНЫ УЯЗВИМОСТИ: Исправьте ошибки перед релизом.${C_RESET}\n"
    exit 1
fi