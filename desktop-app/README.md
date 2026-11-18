# FIMDI VPN Desktop

Новый десктопный клиент FIMDI VPN: Electron + React + Vite + Tailwind, с headless-бэкендом на Python и TUN-режимом через sing-box.

## Возможности

- Загрузка подписки по URL (JSON от admin-панели) и список профилей с группировкой по.exit-стране.
- Подключение выбранного профиля с сохранением split-маршрутизации (`ru` / `non_ru` / `private`) из подписки.
- Два режима:
  - **Системный прокси Windows** — HTTP-прокси `127.0.0.1:8891`, настройки Windows сохраняются и восстанавливаются при отключении.
  - **VPN TUN** — sing-box поднимает адаптер `fimdi-tun`, SOCKS5-аутбаунд `127.0.0.1:8890` уходит в наш туннель. Нужны права администратора.
- Статус подключения, внешний IP, аптайм, счётчики трафика, живой журнал.
- Переключение профиля/режима на ходу — бэкенд корректно останавливает старую сессию и поднимает новую.

## Структура

```
desktop-app/
  electron/main.cjs          Главный процесс: жизненный цикл, IPC, запуск бэкенда
  electron/preload.cjs       contextBridge API для рендерера
  src/                       React UI
  backend/vpn_backend.py     JSON API, туннель, прокси, sing-box supervisor
  resources/sing-box/        Бандл sing-box 1.14.3 (exe + libcronet.dll)
  scripts/build-backend.bat  Сборка vpn-backend.exe через PyInstaller
```

Бэкенд переиспользует ядро из корня репозитория: `tunnel.py`, `socks5_server.py`,
`desktop_client.py` (HTTP CONNECT), `subscription.py`, `split_routing.py`.

## Запуск (разработка)

```bat
npm install
npm run dev
```

`npm run dev` поднимает Vite на `127.0.0.1:5173`, затем Electron. Electron сам выбирает свободный
порт для локального API и запускает бэкенд.

## Production build

```bat
scripts\build-backend.bat
npm run dist
```

`electron-builder` соберёт portable `.exe` в `release/`. В состав входят: React-бандл, бэкенд,
ядро `.py` из корня репозитория и `sing-box`. Если `vpn-backend.exe` отсутствует, приложение
пытается запустить `python backend/vpn_backend.py` — тогда Python 3.10+ должен быть в PATH.

Бинарники не хранятся в git. На чистом клоне перед сборкой выполните:

```bat
powershell -ExecutionPolicy Bypass -File scripts\fetch-singbox.ps1
scripts\build-backend.bat
```

## Права администратора и TUN

TUN создаёт сетевой адаптер и меняет таблицу маршрутов. В обычном режиме кнопка TUN показывает
предупреждение; используйте «Перезапустить от администратора». sing-box проверяется командой
`sing-box check` перед запуском; конфиг сохраняется в `%LOCALAPPDATA%\FimdiVPN\sing-box-tun.json`
и удаляется при отключении.

Чтобы polling-запросы не попадали в собственный TUN, в конфиг добавлены:
- `route_exclude_address` с IP узлов подписки и локальными DNS;
- правило `process_name` → `direct` для `python.exe` / `vpn-backend.exe`.

## Порты

| Порт | Назначение |
| ---- | ---------- |
| 8890 | Локальный SOCKS5 (upstream для sing-box и для прокси-режима) |
| 8891 | Локальный HTTP-прокси (CONNECT + обычные HTTP-запросы) |
| динамический | Управляющий JSON API бэкенда (только loopback, только Electron) |

## Подписка

Формат тот же, что и у остальных клиентов проекта. Для профилей из `client_profiles` бэкенд
переводит `route_ru` / `route_non_ru` / `route_private` в `split_routing.actions`. Пустая строка
или `direct` означает прямой выход. Тумблер «Весь трафик» подменяет `ru` и `non_ru` на exit-маршрут
профиля, оставляя приватные сети прямыми.

Если в подписке нет `client_profiles`, каждый узел становится отдельным профилем «весь трафик
через узел».

## Важные замечания

- В проектном списке RU-доменов (`fimdi.ru/rules/ru-domains.txt`) присутствуют, например,
  `ipinfo.io` и `x.com`; для проверки внешнего IP используется `cloudflare.com/cdn-cgi/trace`,
  который там отсутствует. Если сайт из RU-списка — он пойдёт напрямую по дизайну split-routing.
- Не трогать второй xray/x-ui на `ru-2`.
- Push в GitHub — только по явной просьбе.
