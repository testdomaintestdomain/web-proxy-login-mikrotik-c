# MikroTik WebProxy Login Shim (`proxy-login`)

[![C11](https://img.shields.io/badge/C-11-blue.svg)](https://en.cppreference.com/w/c/11)
[![musl](https://img.shields.io/badge/libc-musl-green.svg)](https://musl.libc.org/)
[![Size](https://img.shields.io/badge/binary_size-~83_KB-brightgreen.svg)]()
[![RouterOS](https://img.shields.io/badge/RouterOS-7.4%20--%207.22+-orange.svg)](https://mikrotik.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Ультралегкий высокопроизводительный контейнер на языке Си для **MikroTik RouterOS**, добавляющий обязательную авторизацию по логину и паролю (HTTP Basic Auth) к встроенному сервису `/ip/proxy`.

---

## 💡 Зачем это нужно?

Встроенный прокси-сервер MikroTik RouterOS (`/ip/proxy`) обладает отличной производительностью, кэшированием и фильтрацией URL, но **не имеет встроенной поддержки пользовательской авторизации** (логин/пароль). Если открыть порт веб-прокси наружу или в недоверенную сеть, роутер превратится в Open Relay, подверженный сканированию и злоупотреблениям.

`proxy-login` решает эту проблему:
1. Перехватывает входящие подключения на порту `8080`.
2. Запрашивает авторизацию (`HTTP 407 Proxy Authentication Required`), если клиент не передал учетные данные.
3. Проверяет логин и пароль в защищенном константном времени (Constant-Time memory comparison против атак по времени).
4. **Вырезает заголовок `Proxy-Authorization`** перед отправкой запроса во внутренний Web-Proxy MikroTik (гарантирует отсутствие утечки учетных данных целевым серверам).
5. Проксирует запросы (включая полнодуплексный `CONNECT` туннель для HTTPS) во встроенный `/ip/proxy` MikroTik.

---

## 📑 Содержание

- [Схема работы](#-схема-работы)
- [Требования](#-требования)
- [Быстрый старт (Web-Конфигуратор)](#-быстрый-старт-web-конфигуратор)
- [Ручная установка](#-ручная-установка)
  - [1. Включение режима контейнеров на роутере](#1-включение-режима-контейнеров-на-роутере)
  - [2. Настройка сети (Bridge, VETH, NAT)](#2-настройка-сети-bridge-veth-nat)
  - [3. Настройка встроенного Web-Proxy MikroTik](#3-настройка-встроенного-web-proxy-mikrotik)
  - [4. Запуск контейнера (Реестр GHCR или Файл)](#4-запуск-контейнера)
- [Переменные окружения](#-переменные-окружения)
- [Обновление контейнера](#-обновление-контейнера)
- [Удаление](#-удаление)
- [Устранение неполадок](#-устранение-неполадок)
  - [error: failed to extract](#error-failed-to-extract)
  - [exited with signal 4 (Illegal instruction)](#exited-with-signal-4-illegal-instruction)
  - [HTTP 502 Bad Gateway](#http-502-bad-gateway)
- [Сборка из исходников](#-сборка-из-исходников)
- [Лицензия](#-лицензия)

---

## 🏗 Схема работы

```text
[ Клиент (Браузер / cURL / ПО) ]
              │
      TCP порт 8080
      Proxy-Authorization: Basic <base64>
              ▼
┌──────────────────────────────────────────────────────────┐
│ MikroTik Container: proxy-login (~1-2 МБ RAM, epoll)      │
│ • Проверка учетных данных (407 при ошибке)               │
│ • Вырезание hop-by-hop заголовка Proxy-Authorization     │
│ • Защита от переполнения буфера (8KB Header Limit)       │
└─────────────────────────────┬────────────────────────────┘
                              │ Чистый трафик HTTP / HTTPS CONNECT
                              ▼
┌──────────────────────────────────────────────────────────┐
│ Встроенный MikroTik Web-Proxy (порт 8081, 172.17.0.1)    │
│ • Списки доступа (/ip proxy access)                      │
│ • Контроль доступа и выход во внешнюю сеть               │
└─────────────────────────────┬────────────────────────────┘
                              │
                              ▼
                     [ Интернет / WAN ]
```

---

## ⚙️ Требования

* **MikroTik RouterOS:** версия `7.4` и выше с установленным пакетом `container`.
* **Архитектура процессора:** `amd64 / x86_64`, `arm64`, `arm (v7)`, `armv5` (поддерживаются все линейки от CHR и CCR до hAP ac и hEX).
* **Свободное место на диске:** от **1 МБ** (размер контейнера ~50 КБ).
* **Оперативная память (RAM):** от **2 МБ** свободной памяти в простое. Модель на `epoll` (без потока на соединение) — расход растёт только с числом активных туннелей (~16 КБ на активный туннель), ограничен `MAX_CONN`.

---

---

## 🚀 Быстрый старт (Web-Конфигуратор)

> 🌐 **Онлайн-генератор команд:** [Открыть Web-Конфигуратор](https://testdomaintestdomain.github.io/web-proxy-login-mikrotik-c/)  
> *(Также можно просто открыть файл `web/index.html` локально в любом браузере — генератор на 100% автономен и работает без интернета).*

Конфигуратор позволяет в один клик сгенерировать готовый безопасный скрипт под параметры вашей сети без необходимости ручного ввода десятков команд в терминал RouterOS.

### Пошаговая инструкция:

#### 1. Подготовьте роутер
1. Установите пакет **`container`** с [mikrotik.com/download](https://mikrotik.com/download) под архитектуру вашего роутера через меню **System → Packages**, загрузите файл `.npk` на устройство и перезагрузитесь.
2. Включите поддержку контейнеров в `device-mode`:
   ```routeros
   /system/device-mode/update container=yes fetch=yes

---

## 🛠 Ручная установка

### 1. Включение режима контейнеров на роутере

Установите пакет `container` для вашей версии RouterOS через меню **System → Packages**, загрузите его на роутер и перезагрузитесь. Затем включите поддержку контейнеров в device-mode:

```routeros
/system/device-mode/update container=yes
```
> *Роутер попросит подтверждение физической кнопкой Reset/Mode или циклом перезагрузки.*

---

### 2. Настройка сети (Bridge, VETH, NAT)

Создаем изолированный виртуальный мост, интерфейс VETH для контейнера и правила маршрутизации:

```routeros
# Создание моста для контейнеров
/interface/bridge/add name=dockers-bridge
/ip/address/add address=172.17.0.1/24 interface=dockers-bridge

# Создание виртуального интерфейса контейнера
/interface/veth/add name=veth-proxy address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/port add bridge=dockers-bridge interface=veth-proxy

# DNS и маскарадинг трафика контейнера
/ip/dns/set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 comment="proxy-login-nat"

# Проброс внешнего порта 8080 на контейнер авторизации (172.17.0.2:8080)
/ip/firewall/nat/add chain=dstnat protocol=tcp dst-port=8080 action=dst-nat to-addresses=172.17.0.2 to-ports=8080 comment="proxy-login-dstnat"
/ip/firewall/filter/add chain=forward dst-address=172.17.0.2 action=accept place-before=0 comment="proxy-login-forward"
```

---

### 3. Настройка встроенного Web-Proxy MikroTik

Включаем локальный Web-Proxy на порту `8081`, привязав его к шлюзу контейнера:

```routeros
/ip/proxy/set enabled=yes port=8081 max-cache-size=none
/ip/proxy/access/add action=allow
```

---

### 4. Запуск контейнера

#### Переменные окружения контейнера
Задайте ваши учетные данные (замените `myuser` и `mypassword123` на свои):

```routeros
/container/envs/add list=proxy_envs key=PROXY_USER value="myuser"
/container/envs/add list=proxy_envs key=PROXY_PASS value="mypassword123"
/container/envs/add list=proxy_envs key=UPSTREAM_HOST value="172.17.0.1"
/container/envs/add list=proxy_envs key=UPSTREAM_PORT value="8081"
/container/envs/add list=proxy_envs key=LISTEN_PORT value="8080"
```

#### Вариант А: Установка из реестра GHCR (RouterOS 7.22+)
Самый простой и рекомендуемый способ с возможностью бесшовных автообновлений:

```routeros
# Стандартные архитектуры (amd64, arm64, arm v7):
/container/add remote-image=ghcr.io/testdomaintestdomain/proxy-login:latest \
    name=proxy-login interface=veth-proxy envlist=proxy_envs root-dir=login logging=yes start-on-boot=yes

# Для моделей MikroTik hEX refresh (E50UG) и hEX S 2025 (E60iUGS) на armv5:
/container/add remote-image=ghcr.io/testdomaintestdomain/proxy-login:latest-armv5 \
    name=proxy-login interface=veth-proxy envlist=proxy_envs root-dir=login logging=yes start-on-boot=yes

# Запуск
/container/start [find where name="proxy-login"]
```

#### Вариант Б: Оффлайн-установка через файл архива (Releases)
1. Скачайте нужный архив со страницы [Releases](https://github.com/testdomaintestdomain/web-proxy-login-mikrotik-c/releases):
   * Для **RouterOS 7.21+**: используйте OCI-образы `proxy-login-{arch}.tar.gz`.
   * Для **RouterOS 7.4 – 7.20**: используйте совместимые классические образы `proxy-login-{arch}-7.20-Docker.tar.gz`.
2. Загрузите файл на роутер через Winbox (меню **Files**) или SCP.
3. Добавьте и запустите контейнер:

```routeros
/container/add file=proxy-login-amd64.tar.gz name=proxy-login \
    interface=veth-proxy envlist=proxy_envs root-dir=login logging=yes start-on-boot=yes

/container/start [find where name="proxy-login"]
```

---

### 5. Проверка работы

Выполните тестовые запросы через `curl`:

```bash
# 1. Запрос без пароля — должен вернуть ошибку HTTP 407 (Proxy Authentication Required)
curl -i -x http://192.168.88.1:8080 http://example.com

# 2. Запрос с корректной авторизацией — успешный ответ HTTP 200 OK
curl -i -x http://192.168.88.1:8080 --proxy-user "myuser:mypassword123" http://example.com

# 3. HTTPS CONNECT туннель
curl -i -x http://192.168.88.1:8080 --proxy-user "myuser:mypassword123" https://cloudflare.com
```

---

## 📋 Переменные окружения

| Переменная | Обязательная | По умолчанию | Описание |
| :--- | :---: | :---: | :--- |
| `PROXY_USER` | **Да\*** | — | Имя основного пользователя для HTTP Basic аутентификации |
| `PROXY_PASS` | **Да\*** | — | Пароль основного пользователя |
| `UPSTREAM_HOST` | **Да** | — | IPv4-адрес встроенного Web-Proxy MikroTik (например, `172.17.0.1`) |
| `UPSTREAM_PORT` | **Да** | — | Порт встроенного Web-Proxy MikroTik (например, `8081`) |
| `LISTEN_PORT` | Нет | `8080` | Локальный TCP-порт, на котором контейнер слушает входящие подключения |
| `PROXY_USERS` | Нет | — | Дополнительные учётные записи списком: `user1:pass1,user2:pass2` (разделители `,` `;` или перевод строки). Можно использовать вместо/вместе с `PROXY_USER` |
| `PROXY_USERS_FILE` | Нет | — | Путь к файлу с учётными записями (`user:pass` по строке, `#` — комментарий). Перечитывается автоматически при изменении файла — пользователей можно добавлять без перезапуска |
| `MAX_CONN` | Нет | `512` | Максимум одновременных соединений на весь процесс (защита ОЗУ от исчерпания) |
| `WORKERS` | Нет | *(= число CPU, максимум 8)* | Количество рабочих потоков (`epoll`-циклов). На слабых роутерах оставьте авто (обычно `1`) |
| `HEADER_TIMEOUT_MS` | Нет | `10000` | Дедлайн на приём полного заголовка запроса (анти-slowloris) |
| `IDLE_TIMEOUT_MS` | Нет | `120000` | Таймаут простоя для установленного туннеля |
| `PROXY_VER` | Нет | *(вшитая версия)* | Версия сборки. Если переменная не передана, контейнер работает на внутренней версии бинарника, не вызывая сбоев |

> **\*** Нужен хотя бы один источник учётных данных: либо пара `PROXY_USER`+`PROXY_PASS`, либо `PROXY_USERS`, либо `PROXY_USERS_FILE`. Без единой учётной записи контейнер намеренно не стартует.

### 👥 Много пользователей

Для нескольких учётных записей задайте список в одной переменной:

```routeros
/container/envs/add list=proxy_envs key=PROXY_USERS value="ivan:S3cretPass1,olga:An0therPass2,admin:MasterKey3"
```

Либо смонтируйте файл и укажите путь к нему (удобно для сотен пользователей и для добавления «на лету» — файл перечитывается при изменении):

```routeros
/container/envs/add list=proxy_envs key=PROXY_USERS_FILE value="/etc/proxy_users"
```
```text
# /etc/proxy_users — по одной записи на строку
ivan:S3cretPass1
olga:An0therPass2
```

Проверка каждого логина выполняется в постоянном времени по всей таблице, поэтому время ответа не зависит от того, какой пользователь ошибся — утечки через тайминг нет. Веб-конфигуратор умеет генерировать `PROXY_USERS` автоматически (поле «Дополнительные пользователи»).

---

## 🔄 Обновление контейнера

Для установок из реестра **RouterOS 7.22+** обновление выполняется одной командой:

```routeros
/container/repull [find where name="proxy-login"]
```
RouterOS скачает свежие слои и перезапустит контейнер с сохранением всех настроек и переменных.

---

## 🗑 Удаление

Для полной очистки конфигурации с роутера выполните:

```routeros
/container/stop [find where name="proxy-login"]
:delay 3s
/container/remove [find where name="proxy-login"]
/file/remove [find where name="login"]
/container/envs/remove [find where list="proxy_envs"]
/ip/firewall/nat/remove [find where comment~"proxy-login"]
/ip/firewall/filter/remove [find where comment~"proxy-login"]
/interface/bridge/port/remove [find where interface="veth-proxy"]
/interface/veth/remove [find where name="veth-proxy"]
/ip/address/remove [find where interface="dockers-bridge"]
/interface/bridge/remove [find where name="dockers-bridge"]
/ip/proxy/set enabled=no
```

---

## 🩺 Устранение неполадок

### `error: failed to extract`
* **Причина 1:** Указан путь к корню со слешем (`root-dir=/login`). RouterOS считает это попыткой записи в системную read-only память.
  * **Решение:** Задайте `root-dir=login` или `root-dir=disk1/login`.
* **Причина 2:** Использование неподходящего формата архива.
  * **Решение:** Для RouterOS версии 7.20 и старше используйте архив с суффиксом `-7.20-Docker.tar.gz`.

### `exited with signal 4 (Illegal instruction)`
* **Причина:** Несовместимость архитектуры CPU на моделях **hEX refresh (E50UG)** и **hEX S 2025 (E60iUGS)**. Процессор EN7562CT сообщает архитектуру `arm`, но исполняет только инструкции `armv5`.
  * **Решение:** Запустите контейнер с тегом `:latest-armv5` или скачайте архив `proxy-login-armv5.tar.gz`.

### `HTTP 502 Bad Gateway (MikroTik Web-Proxy Unreachable)`
* **Причина:** Контейнер успешно авторизовал клиента, но не смог подключиться к `UPSTREAM_HOST:UPSTREAM_PORT`.
  * **Решение:** Проверьте статус службы командой `/ip/proxy/print` (должно быть `enabled: yes` и совпадать номер порта). Убедитесь, что IP шлюза (`172.17.0.1`) доступен из интерфейса `dockers-bridge`.

---

## 🔨 Сборка из исходников

### Локальная сборка и проверки (харнесс)

Весь цикл проверок завязан на `Makefile`. Нужны `musl-tools`, `gcc`/`clang`,
`cppcheck`, `shellcheck`, `valgrind`, `python3`:

```bash
make            # релизный статический бинарник musl -> builds/proxy-login
make unit       # модульные тесты парсеров (ASan+UBSan)
make integration       # сквозные тесты (ASan+UBSan, mock-upstream)
make integration-tsan  # сквозные тесты под ThreadSanitizer
make valgrind          # сквозные тесты под Valgrind (0 ошибок/утечек)
make fuzz FUZZ_TIME=30 # фаззинг парсеров через libFuzzer
make lint       # cppcheck + shellcheck
make size       # контроль бюджета ПЗУ (128 КБ)
make ci         # полный гейт: всё перечисленное сразу
```

> В облачных сессиях Claude Code весь инструментарий ставится автоматически
> хуком `.claude/hooks/session-start.sh`. CI (`.github/workflows/ci.yml`)
> прогоняет `make ci` на каждый push/PR, а релиз публикуется только после
> прохождения этого гейта.

### Мульти-арх артефакты (релиз)

Для сборки всех 12 артефактов (бинарники, OCI, Classic Docker под все 4 архитектуры) требуются `Docker` и `buildx`:

```bash
# Клонирование репозитория
git clone https://github.com/testdomaintestdomain/web-proxy-login-mikrotik-c.git
cd web-proxy-login-mikrotik-c

# Сборка всех артефактов и генерация .sha256 сумм
chmod +x build.sh scripts/mkdockertar-c.sh
./build.sh

# Запуск тестов совместимости архивов
bash tests/test_archive_compatibility.sh
```
Скомпилированные файлы появятся в каталоге `builds/`.


#### Абсолютно все сгенерировано через ИИ. Используйте на свои страх и риск