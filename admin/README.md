# Admin-панель

Лёгкая панель на Python stdlib + SQLite. Слушает только `127.0.0.1:8444`,
доступ — через SSH-туннель. VPN-сервер (8443) проксирует публичный
`/sub/<token>` в панель.

## Установка

```bash
cd /opt/short-polling-vpn
python3 -m venv admin-venv
./admin-venv/bin/pip install -r admin/requirements.txt
cp admin/config.example.yaml admin/config.yaml
```

Сгенерировать хеш пароля и вписать в `admin/config.yaml`:

```bash
./admin-venv/bin/python -m admin.panel --hash-password 'мой-пароль'
```

Создать `admin/data/` (БД и cluster-ключ создадутся автоматически):

```bash
mkdir -p admin/data && chmod 700 admin/data
```

## Запуск

```bash
./admin-venv/bin/python -m admin.panel --config admin/config.yaml
```

Панель: `http://127.0.0.1:8444`. Снаружи — только через туннель:

```bash
ssh -L 8444:127.0.0.1:8444 root@177.3.220.12
# затем открыть http://127.0.0.1:8444
```

## systemd

```ini
[Unit]
Description=VPN admin panel
After=network-online.target

[Service]
WorkingDirectory=/opt/short-polling-vpn
ExecStart=/opt/short-polling-vpn/admin-venv/bin/python -m admin.panel --config /opt/short-polling-vpn/admin/config.yaml
Restart=always
RestartSec=2
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now vpn-admin
```

## Публичные подписки

В `admin/config.yaml` задайте `public_base_url` — адрес VPN-сервера
(например, `https://177.3.220.12:8443`). Панель формирует ссылку
`https://SERVER:8443/sub/<token>`.

Чтобы VPN-сервер проксировал её в панель, добавьте в его `config.yaml`:

```yaml
server:
  admin_service_url: "http://127.0.0.1:8444"
```

Тогда `GET /sub/<token>` на 8443 отдаёт JSON подписки из панели.
Ссылка — bearer-секрет, её можно отозвать в карточке пользователя.

## Что уже работает

- вход по паролю, CSRF, сессии;
- создание/включение/отключение/удаление пользователей;
- смена секрета, отзыв подписки;
- список устройств (появляются после первого подключения), отзыв устройства;
- лимит устройств, срок действия, видимые узлы, allowed_hops/exits;
- подписка: JSON, ссылка, QR ссылки (полный JSON QR — только если помещается; нужен `qrcode[pil]`);
- аудит действий;
- секреты в SQLite шифруются cluster-ключом (`admin/data/cluster.key`).

## Репликация между мастерами

Каждый узел имеет Ed25519-ключ (`node_key`). Публичный ключ:

```bash
./admin-venv/bin/python -m admin.panel --config admin/config.yaml --show-node-key
```

Пропишите пиров в `admin/config.yaml` на **каждом** мастере:

```yaml
peers:
  - id: de-1
    url: https://2.27.37.211:8443
    public_key: "публичный ключ de-1"
replication_interval: 60
```

- Изменения подписываются ключом узла и пушатся на пиров (`POST /replicate/ops`).
- Периодически каждый узел тянет пропущенные ops (`GET /replicate/ops?after_hlc=...`).
- VPN-сервер проксирует `/replicate/ops` в панель на localhost (нужен `admin_service_url`).
- Конфликты решаются по HLC + origin; удаление — tombstone на 90 дней.
- Cluster-ключ должен быть одинаковым на всех мастерах: скопируйте `admin/data/cluster.key` (chmod 600).

## Списки RU / split-routing

Списки лежат в `rules_dir` (по умолчанию `admin/data/rules`) и отдаются как
`/rules/<name>` через VPN-сервер.

Обновить из публичных источников:

```bash
./admin-venv/bin/python -m admin.rules --config admin/config.yaml --update
```

Источники задаются в `admin/config.yaml`:

```yaml
rules_sources:
  geoip: "https://www.ipdeny.com/ipblocks/data/countries/ru.zone"
  domains: "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
```

В `subscription.split_routing.rules` можно указать просто имена файлов —
панель сама превратит их в `https://SERVER:8443/rules/<name>`.

## Аутентификация пользователей в VPN

Добавьте в `config.yaml` VPN-сервера:

```yaml
users:
  db_path: "/opt/short-polling-vpn/admin/data/vpn.db"
  cluster_key: "/opt/short-polling-vpn/admin/data/cluster.key"
```

Клиент с подпиской отправляет `X-User`/`X-Device`, сервер проверяет пользователя,
устройство, срок действия и лимит устройств. При отключении пользователя его
сессии закрываются, запросы получают маскировочный ответ. Без `X-User` работает
старый режим с общим PSK.

## Relay-маршруты

На VPN-серверах, которые будут entry/relay:

```yaml
node_id: "fi-1"
relay_secret: "общий-секрет-на-всех-узлах"
peers:
  ru-2: "https://fimdi.ru:8443"
  de-1: "https://2.27.37.211:8443"
```

Клиентский профиль с двумя hop-ами:

```yaml
routes:
  - name: "FI → DE"
    hops:
      - candidates: ["fi-1"]
      - candidates: ["de-1"]
```

Entry проверяет пользователя/маршрут и форвардит запрос; exit обрабатывает кадры.
Payload на entry/relay не расшифровывается. Максимум 3 hop-а.

Клиент выбирает цепочку только из разных узлов (уникальные `node_id` и URL).
Если уникальных узлов меньше числа hop-ов, цепочка сокращается и пишется
предупреждение; если собрать нельзя — соединение отклоняется с явной ошибкой.
Панель `/routes` показывает `ок` / `предупреждение` / `ошибка` и не сохраняет
заведомо невозможные маршруты.

## Текущий деплой (2026-11-14)

- `ru-2` — `157.228.134.211` (`fimdi.ru`, RU), `fi-1` — `177.3.220.12` (FI), `de-1` — `2.27.37.211` (DE).
- На всех трёх: `short-polling-vpn` (8443) и `vpn-admin` (127.0.0.1:8444), автозапуск включён.
- Репликация пользователей между мастерами работает (проверено create/disable/enable).
- Публичные `/sub/<token>`, `/rules/<name>`, `/replicate/ops` — через 8443.
- Android: `URL select` явно помечен как fallback (entry выбирается маршрутом),
  размеры пустых poll-запросов маскируются padding (`client.pad_polls: true`).
- Публичная админка: **https://fimdi.ru:8445** (nginx TLS → 127.0.0.1:8444).
  - Конфиг: `admin/nginx-vpn-admin.conf` → `/etc/nginx/conf.d/vpn-admin.conf`.
  - Открыт только `8445/tcp`; панель по-прежнему слушает localhost.
  - Включены HSTS, CSP, `X-Frame-Options: DENY`, `Secure`-cookie.
  - На `/login` действует rate-limit `10r/m` (burst 5), на остальные страницы — `120r/m`.
- Вход в панель:
  - снаружи: `https://fimdi.ru:8445`;
  - локально через SSH-туннель: `ssh -L 8444:127.0.0.1:8444 root@177.3.220.12`,
    затем `http://127.0.0.1:8444`.
- Пароль администратора задан при деплое; сменить:
  ```bash
  python -m admin.panel --hash-password 'новый-пароль'
  # обновить admin_password_hash в admin/config.yaml на всех мастерах
  systemctl restart vpn-admin
  ```

## Что дальше

- UI импорта подписки в Android (сейчас через Advanced JSON); на desktop
  импорт уже есть — см. `docs/desktop-client.md`;
- фоновое автообновление подписки/правил;
- relay-цепочки entry → exit (Этап 3);
- UI панели для узлов/маршрутов/списков.

## Безопасность

- `admin/config.yaml` и `admin/data/cluster.key` — только root, `chmod 600`.
- Не открывайте 8444 в firewall: только SSH-туннель.
- Ссылка подписки = пароль пользователя; не публикуйте её.
- Резервные копии: `admin/data/vpn.db` + `cluster.key` (без ключа секреты не расшифровать).
