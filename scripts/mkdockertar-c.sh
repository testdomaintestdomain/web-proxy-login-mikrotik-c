#!/usr/bin/env bash
# Сборка совместимого архива для RouterOS 7.4 - 7.20 с корректным каталогом /etc
set -euo pipefail

GOOS="$1"
GOARCH="$2"
GOARM="$3"
TAG="$4"
OUTPUT="$5"
BIN_SRC="$6"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 1. Формирование корневой файловой системы контейнера
LAYER_ROOT="$WORK/layer_root"
mkdir -p "$LAYER_ROOT/etc"
cp "$BIN_SRC" "$LAYER_ROOT/proxy_login"
chmod 0755 "$LAYER_ROOT/proxy_login"
chmod 0755 "$LAYER_ROOT/etc"
touch "$LAYER_ROOT/etc/resolv.conf"
chmod 0644 "$LAYER_ROOT/etc/resolv.conf"

# 2. Создание layer.tar (упаковываем каталог с точкой '.', чтобы 'etc/' был в архиве)
tar --format=ustar -cf "$WORK/layer.tar" -C "$LAYER_ROOT" .
LAYER_SHA=$(sha256sum "$WORK/layer.tar" | cut -d' ' -f1)

LAYER_DIR="$WORK/out/$LAYER_SHA"
mkdir -p "$LAYER_DIR"
mv "$WORK/layer.tar" "$LAYER_DIR/layer.tar"
echo '1.0' > "$LAYER_DIR/VERSION"
printf '{"id":"%s"}' "$LAYER_SHA" > "$LAYER_DIR/json"

# 3. Конфигурация образа config.json
CREATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VARIANT=""
if [ "$GOARCH" = "arm" ] && [ -n "$GOARM" ]; then VARIANT="v$GOARM"; fi

VARIANT_JSON=""
if [ -n "$VARIANT" ]; then
    VARIANT_JSON=",\"variant\":\"$VARIANT\""
fi

CONFIG="{\"architecture\":\"$GOARCH\"$VARIANT_JSON,\"os\":\"$GOOS\",\"created\":\"$CREATED\",\"config\":{\"Entrypoint\":[\"/proxy_login\"]},\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:$LAYER_SHA\"]}}"
printf '%s' "$CONFIG" > "$WORK/config.json"
CONFIG_SHA=$(sha256sum "$WORK/config.json" | cut -d' ' -f1)
mv "$WORK/config.json" "$WORK/out/${CONFIG_SHA}.json"

# 4. Manifest и Repositories
printf '[{"Config":"%s.json","RepoTags":["%s"],"Layers":["%s/layer.tar"]}]' \
    "$CONFIG_SHA" "$TAG" "$LAYER_SHA" > "$WORK/out/manifest.json"

REPO="${TAG%%:*}"
RTAG="${TAG#*:}"
printf '{"%s":{"%s":"%s"}}' "$REPO" "$RTAG" "$CONFIG_SHA" > "$WORK/out/repositories"

# 5. Сборка архива с gzip-сжатием (manifest.json строго первым для последовательного парсера)
ABS_OUTPUT="$(cd "$(dirname "$OUTPUT")" && pwd)/$(basename "$OUTPUT")"
(
    cd "$WORK/out"
    tar --format=ustar -czf "$ABS_OUTPUT" \
        manifest.json \
        "${CONFIG_SHA}.json" \
        repositories \
        "$LAYER_SHA/VERSION" \
        "$LAYER_SHA/json" \
        "$LAYER_SHA/layer.tar"
)