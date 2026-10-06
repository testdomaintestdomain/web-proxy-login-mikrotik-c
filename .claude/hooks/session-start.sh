#!/bin/bash
# SessionStart hook: provisions the audit/test harness toolchain for Claude Code
# cloud sessions (static musl build, sanitizers, libFuzzer, static analysis).
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo -n"; fi

PKGS=()
command -v musl-gcc   >/dev/null 2>&1 || PKGS+=(musl-tools musl-dev)
command -v cppcheck   >/dev/null 2>&1 || PKGS+=(cppcheck)
command -v shellcheck >/dev/null 2>&1 || PKGS+=(shellcheck)
command -v valgrind   >/dev/null 2>&1 || PKGS+=(valgrind)
command -v clang      >/dev/null 2>&1 || PKGS+=(clang)
command -v python3    >/dev/null 2>&1 || PKGS+=(python3)
command -v make       >/dev/null 2>&1 || PKGS+=(make)
# libFuzzer / clang sanitizer runtimes
CLANG_RES="$(clang -print-resource-dir 2>/dev/null || true)"
if [ -z "$CLANG_RES" ] || ! ls "$CLANG_RES"/lib/linux/libclang_rt.fuzzer-*.a >/dev/null 2>&1; then
  CLANG_MAJ="$(clang -dumpversion 2>/dev/null | cut -d. -f1 || true)"
  PKGS+=("libclang-rt-${CLANG_MAJ:-18}-dev")
fi

if [ "${#PKGS[@]}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  # The cached package index can be stale (404 on superseded .debs): refresh and retry.
  if ! $SUDO apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null 2>&1; then
    $SUDO apt-get update -qq >/dev/null 2>&1 || true
    $SUDO apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null
  fi
fi

echo "harness toolchain ready: musl-gcc (gcc $(musl-gcc -dumpversion 2>/dev/null || echo ?)), $(cppcheck --version), shellcheck $(shellcheck --version | sed -n 's/^version: //p'), $(valgrind --version)"
