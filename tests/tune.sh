#!/usr/bin/env bash
# Оптимизация ядра Linux под 100,000+ одновременных соединений
set -e

echo "[SYS] Применение экстремальных сетевых лимитов..."
sudo sysctl -w fs.file-max=2097152 >/dev/null
sudo sysctl -w net.core.somaxconn=65535 >/dev/null
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null
sudo sysctl -w net.ipv4.tcp_fin_timeout=15 >/dev/null
ulimit -n 1048576

echo "✓ Система оптимизирована для генерации 10M+ соединений (ulimit -n = $(ulimit -n))"