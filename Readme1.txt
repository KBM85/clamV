# AV Scan — Сервис проверки файлов на вирусы

Самостоятельная платформа антивирусной проверки загружаемых файлов на базе
ClamAV. Принимает файлы по HTTP API, проверяет (включая содержимое архивов),
возвращает вердикт. Веб-дашборд для мониторинга в реальном времени. Выгрузка
отчётов за период в Excel и CSV.

Без внешних зависимостей кроме Docker. Файлы никуда не уходят — всё работает
локально на вашем сервере.

---

## Требования

- Docker + Docker Compose
- ~512 МБ RAM (clamd загружает базы в память)
- Доступ в интернет (для скачивания/обновления баз сигнатур)

---

## Быстрый старт

```sh
# 1. Клонировать / скопировать файлы проекта
cd /path/to/avscan

# 2. Создать папку для журнала проверок
mkdir -p data && chown 10001:10001 data

# 3. Поднять стек
docker compose up -d --build

# 4. Подождать ~1-2 мин, пока ClamAV скачает базы сигнатур
docker compose ps          # clamav должен стать healthy

# 5. Проверить на тестовом «вирусе» EICAR
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
curl -s -X POST http://localhost:8090/api/v1/scan -F FILES=@eicar.txt
# -> "is_infected": true, "Eicar-Test-Signature"
```

---

## Структура проекта

```
avscan/
├── docker-compose.yml       # стек: clamav + rest-api + gateway
├── clamd.conf               # конфиг ClamAV (лимиты архивов, потоки)
├── gateway/
│   ├── main.go              # код шлюза (API, дашборд, очередь, отчёты)
│   ├── Dockerfile
│   └── go.mod
├── data/
│   └── scans.log            # журнал проверок (создаётся автоматически)
└── README.md
```

---

## Архитектура

```
[Клиент] ──▶ :8090 [gateway] ──▶ :8080 [clamav-rest-api] ──▶ :3310 [clamd]
                │                     benzino77                ClamAV
                │
              :8091
            дашборд
```

| Контейнер | Образ | Назначение |
|-----------|-------|------------|
| **clamav** | `clamav/clamav:1.4` | Антивирусный движок + автообновление баз |
| **clamav-rest-api** | `benzino77/clamav-rest-api:1.6.6` | REST-обёртка над clamd |
| **gateway** | Go (собирается локально) | Очередь, статистика, дашборд, отчёты |

---

## API

### Проверка файла

```
POST /api/v1/scan
Content-Type: multipart/form-data
Поле: FILES
```

```sh
curl -s -X POST http://<host>:8090/api/v1/scan -F FILES=@document.pdf
```

Несколько файлов за раз (до 10, по 100 МБ каждый):
```sh
curl -s -X POST http://<host>:8090/api/v1/scan \
  -F FILES=@a.pdf -F FILES=@b.zip
```

PowerShell (Windows):
```powershell
curl.exe -s -X POST http://<host>:8090/api/v1/scan -F FILES=@C:\path\file.pdf
```

### Ответ

Чистый:
```json
{
  "success": true,
  "data": {
    "result": [
      { "name": "document.pdf", "is_infected": false, "viruses": [] }
    ]
  }
}
```

Заражённый:
```json
{
  "success": true,
  "data": {
    "result": [
      { "name": "malware.exe", "is_infected": true, "viruses": ["Win.Trojan.Agent-123"] }
    ]
  }
}
```

| Поле | Значение | Действие |
|------|----------|----------|
| `is_infected: false` | вирусов нет | пускать файл дальше |
| `is_infected: true` | найден вирус | блокировать, имя в `viruses` |

При сетевой ошибке или отсутствии ответа — считать непроверенным и блокировать.

---

## Дашборд

Открыть в браузере: `http://<host>:8443/`

Обновляется автоматически каждые 2 секунды. Показывает:

- Проверено файлов / обнаружено вирусов / ошибки
- Сканируется сейчас / в очереди (загрузка движка)
- База сигнатур: версия, дата, возраст (зелёный < 48ч, жёлтый < 96ч, красный — устарела)
- Последние 20 загрузок: время, IP клиента, файл, результат
- Топ-10 вирусных сигнатур по частоте
- Выгрузка отчёта за период (Excel / CSV)

### Статистика (JSON)

```sh
curl -s http://<host>:8443/stats
```

---

## Отчёты

### Через дашборд
Блок «Выгрузка отчёта за период» — выбрать даты, нажать Excel или CSV.

### Через API
```sh
curl -s "http://<host>:8443/report?from=2026-06-01&to=2026-06-30&format=xlsx" -o report.xlsx
curl -s "http://<host>:8443/report?from=2026-06-01&format=csv" -o report.csv
```

| Параметр | Формат | Описание |
|----------|--------|----------|
| `from` | `2026-06-01` или `2026-06-01T14:00:00` | Начало периода |
| `to` | аналогично | Конец (по умолчанию — сейчас) |
| `format` | `xlsx` или `csv` | Формат файла (по умолчанию xlsx) |

Колонки: Время, IP, Файл, Результат, Вирусы.

---

## Конфигурация

### Переменные окружения gateway (docker-compose.yml)

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `LISTEN_ADDR` | `:8090` | Порт API |
| `DASH_ADDR` | `:8091` | Порт дашборда |
| `UPSTREAM_URL` | `http://clamav-rest-api:8080` | Адрес benzino77 |
| `CLAMD_ADDR` | `clamav:3310` | Адрес clamd |
| `MAX_CONCURRENT` | `10` | Макс. одновременных сканов |
| `SCAN_TIMEOUT` | `130s` | Таймаут на один скан |
| `LOG_PATH` | `/data/scans.log` | Путь к журналу |

### clamd.conf — лимиты ClamAV

| Параметр | Значение | Описание |
|----------|----------|----------|
| `MaxScanSize` | `419430400` | Макс. объём данных на файл (400 МБ) |
| `MaxFileSize` | `104857600` | Макс. размер файла в архиве (100 МБ) |
| `MaxRecursion` | `16` | Глубина вложенности архивов |
| `MaxFiles` | `10000` | Макс. файлов в архиве |
| `StreamMaxLength` | `104857600` | Макс. размер по INSTREAM |
| `MaxThreads` | `10` | Параллельные сканы |

**Важно:** значения размеров только в **байтах**. Суффикс `M`/`G` вызовет
ошибку, clamd не запустится.

### Переменные clamav

| Переменная | Значение | Описание |
|-----------|----------|----------|
| `FRESHCLAM_CHECKS` | `24` | Обновление баз раз в час (24/сутки — максимум!) |

---

## Порты

| Порт | Что | Доступ |
|------|-----|--------|
| `8090` | API (POST /api/v1/scan) | по умолчанию 127.0.0.1 |
| `8443` | Дашборд (/, /stats, /report) | 0.0.0.0 |
| `8444` | Дашборд (дубль) | 0.0.0.0 |
| `3310` | clamd | только внутри Docker |
| `8080` | benzino77 | только внутри Docker |

При необходимости настройте реверс-прокси (nginx/HAProxy) перед сервисом
для TLS-терминации и access list.

---

## Очередь и нагрузка

Шлюз ограничивает параллельные сканы до `MAX_CONCURRENT` (по умолчанию 10).
Остальные запросы ждут в очереди. На дашборде видно «сканируется сейчас»
и «в очереди».

При переполнении очереди (>1000 ожидающих) сервис возвращает
`503 Service Unavailable` с `Retry-After: 5`.

Масштабирование:
- Вертикально: увеличить `MAX_CONCURRENT` + `MaxThreads`
- Горизонтально: несколько реплик за балансировщиком

---

## Архивы

ClamAV распаковывает и проверяет содержимое архивов автоматически:
zip, rar, 7z, tar, gz, вложенные архивы.

Лимиты от zip-бомб настроены в `clamd.conf` (`MaxScanSize`, `MaxFileSize`,
`MaxRecursion`, `MaxFiles`).

Зашифрованные архивы: clamd не может проверить содержимое — файл пройдёт
как «чистый». Для блокировки запароленных архивов добавьте в `clamd.conf`:
```
AlertEncrypted yes
```

---

## Обновление баз

Автоматически: `freshclam` проверяет обновления раз в час. Базы хранятся
в Docker volume `clamav-db` — переживают перезапуск.

Принудительное обновление:
```sh
docker compose exec clamav freshclam
```

Проверить версию:
```sh
curl -s http://<host>:8443/stats | python3 -m json.tool | grep -A5 database
```

Индикация на дашборде:
- Зелёный: база моложе 48 часов
- Жёлтый: 48–96 часов (скоро устареет)
- Красный: старше 96 часов (freshclam не обновляет — проверьте интернет)

---

## Управление

### Запуск / остановка
```sh
docker compose up -d            # запуск
docker compose down              # остановка
docker compose restart gateway   # перезапуск шлюза
docker compose up -d --build     # пересборка после изменения кода
```

### Автозапуск при перезагрузке
Включен через `restart: always`. Убедитесь, что Docker стартует с ОС:
```sh
sudo systemctl enable docker
```

### Логи
```sh
docker compose logs -f                  # все контейнеры
docker compose logs -f gateway          # только шлюз
docker compose logs -f clamav           # clamd + freshclam
```

### Сброс статистики
```sh
> data/scans.log                   # очистить журнал отчётов
docker compose restart gateway     # обнулить счётчики в памяти
```

### Проверка здоровья
```sh
docker compose ps                    # все healthy / Up?
curl -s http://localhost:8443/stats  # шлюз отвечает?
```

---

## Типичные проблемы

**clamav unhealthy / не стартует**
```sh
docker compose logs clamav
```
- «Incorrect argument format» → в `clamd.conf` размеры должны быть в байтах
- Долго «Socket not found» → базы качаются, подождите 2-3 мин
- «Unable to contact server» → уберите `TCPAddr` из `clamd.conf`

**502 Bad Gateway**
nginx/прокси не достукивается до шлюза:
```sh
ss -tlnp | grep 8090
docker compose ps
curl -s http://localhost:8090/api/v1/scan -F FILES=@eicar.txt
```

**Журнал пустой (отчёты пустые)**
```sh
ls -la data/              # папка есть? владелец 10001?
docker compose logs gateway | grep journal
```
Решение:
```sh
mkdir -p data && chown 10001:10001 data
docker compose restart gateway
```

**Порт недоступен извне**
```sh
nmap -p <port> <host>     # filtered = фаервол режет
sudo ufw allow <port>/tcp
```

---

## Интеграция (псевдокод)

```
ответ = POST /api/v1/scan (файл в поле FILES)

для каждого файла в ответ.data.result:
    если файл.is_infected:
        отклонить загрузку
        показать: "Обнаружен вирус: " + файл.viruses
    иначе:
        сохранить / пустить в работу

при ошибке сети:
    считать файл непроверенным — блокировать
```

---

## Безопасность

- У API **нет аутентификации** — не выставляйте порты напрямую в публичную сеть.
  Используйте реверс-прокси с TLS и access list.
- Дашборд содержит IP-адреса загружающих — ограничьте доступ.
- Порт clamd (3310) **никогда** не выставляйте наружу.
- Файлы проверяются потоком (INSTREAM) — на диск сервера не сохраняются
  (только журнал метаданных, без содержимого файлов).
