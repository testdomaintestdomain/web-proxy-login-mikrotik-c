#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(pwd)"
OUT_DIR="$ROOT_DIR/builds"
IMAGE="proxy-login"

# Автоматическое определение версии из Git
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "v1.2.0")}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

C_RESET='\033[0m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'

echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}  СБОРКА ОБРАЗОВ [Версия: ${VERSION}] ДЛЯ MIKROTIK (7.4 - 7.21+)${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}\n"

docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null 2>&1 || true

if ! docker buildx inspect mikrotik_builder >/dev/null 2>&1; then
    docker buildx create --name mikrotik_builder --driver docker-container --bootstrap --use >/dev/null
else
    docker buildx use mikrotik_builder >/dev/null
fi

TARGETS=(
    "amd64:linux/amd64:amd64::alpine:latest"
    "arm64:linux/arm64:arm64::alpine:latest"
    "arm:linux/arm/v7:arm:7:alpine:latest"
    "armv5:linux/arm/v5:arm:5:arm32v5/debian:bookworm-slim"
)

# 1. Бинарники
echo -e "[1/4] Компиляция musl ELF с внедрением версии ${VERSION}..."
for target in "${TARGETS[@]}"; do
    IFS=':' read -r FILE_TAG PLATFORM GOARCH GOARM BASE_IMG <<< "$target"
    echo -n -e "  ▶ ${C_YELLOW}${FILE_TAG}${C_RESET} ... "
    
    WORK=$(mktemp -d)
    docker buildx build \
        --platform "$PLATFORM" \
        --build-arg BASE="$BASE_IMG" \
        --build-arg VERSION="$VERSION" \
        --provenance=false --sbom=false \
        --output "type=local,dest=$WORK/out" \
        . >/dev/null
    
    cp "$WORK/out/proxy_login" "$OUT_DIR/${IMAGE}-linux-${FILE_TAG}"
    rm -rf "$WORK"
    echo -e "${C_GREEN}[OK] -> $(du -h "$OUT_DIR/${IMAGE}-linux-${FILE_TAG}" | cut -f1)${C_RESET}"
done

# 2. OCI образы (RouterOS 7.21+)
echo -e "\n[2/4] Сборка OCI tar.gz контейнеров..."
for target in "${TARGETS[@]}"; do
    IFS=':' read -r FILE_TAG PLATFORM GOARCH GOARM BASE_IMG <<< "$target"
    echo -n -e "  ▶ OCI ${C_YELLOW}${FILE_TAG}${C_RESET} ... "
    
    OCI_TAR="$OUT_DIR/${IMAGE}-${FILE_TAG}.tar"
    docker buildx build \
        --platform "$PLATFORM" \
        --build-arg BASE="$BASE_IMG" \
        --build-arg VERSION="$VERSION" \
        --provenance=false --sbom=false \
        --output "type=oci,dest=${OCI_TAR}" \
        -t "${IMAGE}:${VERSION}-${FILE_TAG}" . >/dev/null
    
    gzip -f "$OCI_TAR"
    echo -e "${C_GREEN}[OK]${C_RESET}"
done

# 3. Classic Docker образы (RouterOS 7.4 - 7.20)
echo -e "\n[3/4] Сборка Classic Docker контейнеров..."
for target in "${TARGETS[@]}"; do
    IFS=':' read -r FILE_TAG PLATFORM GOARCH GOARM BASE_IMG <<< "$target"
    echo -n -e "  ▶ Classic Docker ${C_YELLOW}${FILE_TAG}${C_RESET} ... "
    
    DOCKER_TAR_GZ="$OUT_DIR/${IMAGE}-${FILE_TAG}-7.20-Docker.tar.gz"
    BIN_SRC="$OUT_DIR/${IMAGE}-linux-${FILE_TAG}"
    
    ./scripts/mkdockertar-c.sh "linux" "$GOARCH" "$GOARM" "${IMAGE}:${VERSION}-${FILE_TAG}" "$DOCKER_TAR_GZ" "$BIN_SRC"
    echo -e "${C_GREEN}[OK]${C_RESET}"
done

# 4. Генерация контрольных сумм .sha256
echo -e "\n[4/4] Генерация контрольных сумм .sha256..."
(
    cd "$OUT_DIR"
    for file in *; do
        if [ -f "$file" ] && [[ "$file" != *.sha256 ]]; then
            sha256sum "$file" > "${file}.sha256"
        fi
    done
)

echo -e "\n${C_BOLD}${C_GREEN}✔ Сборка завершена. Все артефакты маркированы версией ${VERSION}${C_RESET}\n"
ls -lh "$OUT_DIR"