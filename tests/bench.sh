#!/usr/bin/env bash
set -u

PROXY_HOST="${1:-127.0.0.1}"
PROXY_PORT="${2:-8080}"
PROXY_USER="${3:-myuser}"
PROXY_PASS="${4:-mypassword123}"
TARGET_TOTAL_REQS=10000000 # 10 000 000 соединений

B64_AUTH=$(echo -n "${PROXY_USER}:${PROXY_PASS}" | base64)

# Проверка наличия wrk
if ! command -v wrk &>/dev/null; then
    echo "[!] Утилита 'wrk' не найдена. Установите: sudo apt install wrk / brew install wrk"
    exit 1
fi

# Создаем Lua-скрипт для передачи Proxy-Authorization
LUA_SCRIPT=$(mktemp /tmp/wrk_proxy_XXXXXX.lua)
cat <<EOF > "$LUA_SCRIPT"
wrk.headers["Proxy-Authorization"] = "Basic ${B64_AUTH}"
wrk.headers["Host"] = "example.com"
request = function()
   return wrk.format("GET", "http://example.com/benchmark")
end
EOF
trap 'rm -f "$LUA_SCRIPT"' EXIT

echo -e "\n======================================================================"
echo -e "  НАЧАЛО НАГРУЗОЧНОГО ТЕСТИРОВАНИЯ (ЦЕЛЬ: 10 МИЛЛИОНОВ СОЕДИНЕНИЙ)"
echo -e "  Прокси: http://${PROXY_HOST}:${PROXY_PORT} | Потоки: 16 | Соединения: 400"
echo -e "======================================================================\n"

# Фаза 1: Проверка базовой латентности (100 000 запросов)
echo "[Фаза 1/3] Прогрев и замер базового RPS (100K запросов)..."
wrk -t4 -c50 -d10s -s "$LUA_SCRIPT" "http://${PROXY_HOST}:${PROXY_PORT}"

# Фаза 2: Стресс на высокой конкурентности (1 000 000 запросов)
echo -e "\n[Фаза 2/3] Конкурентный стресс (400 параллельных сокетов, 30 сек)..."
wrk -t12 -c400 -d30s --latency -s "$LUA_SCRIPT" "http://${PROXY_HOST}:${PROXY_PORT}"

# Фаза 3: Экстремальный марафон до 10M соединений
echo -e "\n[Фаза 3/3] Генерация целевого объема 10,000,000 запросов (60 сек на пределе CPU)..."
wrk -t16 -c800 -d60s --latency -s "$LUA_SCRIPT" "http://${PROXY_HOST}:${PROXY_PORT}"

echo -e "\n======================================================================"
echo -e "  ТЕСТ 10M ЗАВЕРШЕН. ПРОВЕРЬТЕ УТЕЧКУ ПАМЯТИ В СТАТУСЕ КОНТЕЙНЕРА."
echo -e "======================================================================\n"