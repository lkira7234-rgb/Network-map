# Мониторинг периметра

Серверный монитор раз в N минут сканирует заданные цели и присылает DIFF в Telegram,
Discord или любой вебхук: какие порты открылись, какие закрылись. Работает без открытой
вкладки браузера.

Секреты (URL вебхука, токен бота) задаются **только в окружении сервера**. Они никогда
не передаются в браузер, не возвращаются API и не хранятся в репозитории.

## Переменные окружения

| Переменная | Обязательна | Значение |
| --- | --- | --- |
| `MONITOR_TARGETS` | да | Цели через запятую: `example.com,api.example.com` (до 5) |
| `MONITOR_PORTS` | нет | Порты: `22,80,443,6379` (по умолчанию популярные сервисы, до 200) |
| `MONITOR_INTERVAL_MIN` | нет | Интервал в минутах, минимум 5, по умолчанию 60 |
| `ALERT_WEBHOOK_URL` | нет | Discord/Slack/generic вебхук. Отправляется JSON `{content,text,message}` |
| `ALERT_TELEGRAM_TOKEN` + `ALERT_TELEGRAM_CHAT` | нет | Telegram Bot API: токен бота и `chat_id` |
| `MONITOR_STATE_FILE` | нет | Путь к JSON с прошлым состоянием (по умолчанию `.monitor-state.json`) |
| `MONITOR_TOKEN` | нет | Секрет для внешнего cron-вызова `POST /api/monitor/run` |

Нужен хотя бы один канал (`ALERT_WEBHOOK_URL` или Telegram), иначе DIFF только пишется в лог.

## Discord

1. В канале: **Edit Channel → Integrations → Webhooks → New Webhook**.
2. Скопируй URL и задай его как `ALERT_WEBHOOK_URL`.
3. Нажми «ТЕСТ УВЕДОМЛЕНИЯ» в панели `09 / PERIMETER MONITOR`.

## Telegram

1. Создай бота у [@BotFather](https://t.me/BotFather): `/newbot` → имя → username, получи токен.
2. Открой бота, нажми **Start** (или отправь `/start`) — без этого Telegram не отдаст чат.
3. Задай токен и узнай `chat_id` одной командой (токен читается из окружения и не печатается):

   ```bash
   ALERT_TELEGRAM_TOKEN=123456:ABC-DEF npm run telegram:chat-id
   ```

   Если чатов несколько (личка, группа, канал) — выбери нужный `chat_id`.
4. На сервере задай `ALERT_TELEGRAM_TOKEN` и `ALERT_TELEGRAM_CHAT`, перезапусти сервис.
5. Нажми «ТЕСТ УВЕДОМЛЕНИЯ» в панели `09 / PERIMETER MONITOR`.

Для группы добавь бота в группу и отправь туда сообщение — `chat_id` группы отрицательный.
Если `sendMessage` отвечает `400 chat not found`, значит бот не видел этот чат: напиши в него ещё раз.

## Render

Добавь переменные в **Environment** сервиса и нажми **Save Changes** — без этого Render не
перезапустит процесс. Если панель показывает `enabled: false`, строка `TARGETS / TOKEN / CHAT`
подсказывает, какие переменные процесс реально видит (только наличие, без значений).

Учти: на free-плане сервис засыпает после
15 минут без трафика, поэтому таймер внутри процесса там ненадёжен. Для честного 24/7:

- либо платный инстанс без сна;
- либо внешний cron (GitHub Actions) вызывает `POST /api/monitor/run` с заголовком
  `X-Monitor-Token: $MONITOR_TOKEN` — запрос разбудит сервис и запустит проверку.

Пример `.github/workflows/monitor.yml`:

```yaml
name: perimeter-monitor
on:
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsS -X POST "${{ secrets.MONITOR_URL }}/api/monitor/run" \
            -H "X-Monitor-Token: ${{ secrets.MONITOR_TOKEN }}"
```

`MONITOR_URL` — базовый адрес сервиса, например `https://network-map-3cw5.onrender.com`.

Готовый workflow уже лежит в `.github/workflows/monitor.yml` — включить его можно без правок кода:
добавь в GitHub → Settings → Secrets and variables → Actions секреты `MONITOR_URL` и
`MONITOR_TOKEN`, а такой же `MONITOR_TOKEN` пропиши в Environment Render. Пока секретов нет,
job завершается без ошибок и ничего не шлёт.

### Настройка через Render API (опционально)

Если не хочется кликать в дашборде, переменные можно выставить одной командой.
Всё читается из окружения, ничего не печатается и не сохраняется в репозиторий:

```powershell
$env:RENDER_API_KEY='rnd_...'                 # Account Settings → API Keys
$env:ALERT_TELEGRAM_TOKEN='123456:ABC'
$env:ALERT_TELEGRAM_CHAT='8458549640'
$env:MONITOR_TARGETS='network-map-3cw5.onrender.com'
$env:MONITOR_PORTS='22,80,443,6379'
$env:MONITOR_INTERVAL_MIN='60'
npm run render:monitor
```

Скрипт найдёт сервис по имени (или по `RENDER_SERVICE=srv-...`), запишет переменные
и запустит деплой. API-ключ Render даёт полный доступ к аккаунту — после настройки его
лучше отозвать.

## Как считается DIFF

- Первый запуск запоминает открытые порты и ничего не присылает (это база).
- Дальше сравниваются ключи вида `1.2.3.4:6379/tcp`; при изменении уходит сообщение:

```
⚠️ NETWORK//MAP · example.com
+ 1.2.3.4:6379/tcp (redis)
− 1.2.3.4:22/tcp (ssh)
2026-11-17 10:00 UTC
```

- Состояние хранится в `MONITOR_STATE_FILE`. На Render диск эфемерный — после рестарта
  первый скан снова станет базовым (алерта не будет).
- Серверный скан не расходует лимит браузерных сканов и не считается в `RateLimit-*`.

## API

- `GET /api/monitor` — состояние: цели, последние изменения, включённые каналы. Без секретов.
- `POST /api/monitor/test` — тестовое уведомление (не чаще раза в 10 минут).
- `POST /api/monitor/run` — принудительный запуск, только с `X-Monitor-Token`.

## Ограничения

- Диапазоны портов и UDP не поддерживаются — только TCP-список.
- Traceroute и GEO в мониторинге отключены, чтобы проверка была быстрой и дешёвой.
- Это не замена SIEM: уведомления приходят только пока сервер жив и только по заданным целям.
