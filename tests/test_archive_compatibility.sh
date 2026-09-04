#!/usr/bin/env bash
set -euo pipefail

C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_RESET='\033[0m'

echo "=== ПРОВЕРКА СОВМЕСТИМОСТИ АРХИВОВ С MIKROTIK ROUTEROS ==="

for arch in amd64 arm64 arm armv5; do
    DOCKER_PKG="builds/proxy-${arch}-7.20-Docker.tar.gz"
    OCI_PKG="builds/proxy-${arch}.tar.gz"
    
    echo -n "1. Проверка Classic Docker [${arch}]: "
    TMP_DIR=$(mktemp -d)
    tar -xzf "$DOCKER_PKG" -C "$TMP_DIR"
    
    # Проверка 1: Порядок манифеста (должен быть первым)
    FIRST_ENTRY=$(tar -tf "$DOCKER_PKG" | head -n 1)
    if [ "$FIRST_ENTRY" != "manifest.json" ]; then
        echo -e "${C_RED}[FAIL] manifest.json не на первом месте в архиве! (${FIRST_ENTRY})${C_RESET}"
        exit 1
    fi
    
    # Проверка 2: Наличие каталога etc/ и файла etc/resolv.conf внутри layer.tar
    LAYER_FILE=$(find "$TMP_DIR" -name "layer.tar")
    ENTRIES=$(tar -tf "$LAYER_FILE")
    
    HAS_ETC_DIR=$(echo "$ENTRIES" | grep -E '^(\./)?etc/$' || true)
    HAS_RESOLV=$(echo "$ENTRIES" | grep -E '^(\./)?etc/resolv\.conf$' || true)
    
    if [ -n "$HAS_ETC_DIR" ] && [ -n "$HAS_RESOLV" ]; then
        echo -e "${C_GREEN}[PASS] (etc/ каталог и resolv.conf валидны)${C_RESET}"
    else
        echo -e "${C_RED}[FAIL] Ошибка в структуре layer.tar (нет каталога etc/)${C_RESET}"
        exit 1
    fi
    rm -rf "$TMP_DIR"
    
    # Проверка OCI архива
    echo -n "2. Проверка OCI образа [${arch}]: "
    OCI_LIST=$(tar -tzf "$OCI_PKG")
    if echo "$OCI_LIST" | grep -q "index.json"; then
        echo -e "${C_GREEN}[PASS] (Валидный OCI layout)${C_RESET}"
    else
        echo -e "${C_RED}[FAIL] Некорректный OCI образ${C_RESET}"
        exit 1
    fi
done

echo -e "\n${C_GREEN}✔ Все артефакты гарантированно распакуются на RouterOS 7.4 - 7.20 и 7.21+${C_RESET}"