# clamav-rest-api stack (benzino77 + official ClamAV)

Ready-to-run virus scanning over a simple HTTP POST. No code to maintain — just
two containers. Synchronous scanning only (the public benzino77 image does
**not** include async/queue or Redis/webhook callbacks — those are a private
add-on from the author). Put any queue/concurrency limiting in the system that
calls this API.

## Ports

- **8080** — the API. This is the only port you expose to callers. The image
  has **no authentication**, so never publish it to the public internet — bind
  it to an internal address and/or put it behind your reverse proxy + firewall.
- **3310** — clamd. Stays internal-only (no `ports:` entry). Do not expose it.

## Start

```sh
docker compose up -d
# Wait ~1-2 min for clamav to download signatures and become healthy:
docker compose ps          # clamav should show "healthy"
docker compose logs -f clamav   # watch signature download if impatient
```

## Test

Clean file:
```sh
echo "hello" > clean.txt
curl -s -X POST http://localhost:8080/api/v1/scan -F FILES=@clean.txt
```

EICAR test "virus" (harmless industry-standard test string):
```sh
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
curl -s -X POST http://localhost:8080/api/v1/scan -F FILES=@eicar.txt
```

Expected (infected):
```json
{ "success": true, "data": { "result": [
  { "name": "eicar.txt", "is_infected": true, "viruses": ["Win.Test.EICAR_HDB-1"] }
]}}
```

Multiple files / an archive in one request:
```sh
curl -s -X POST http://localhost:8080/api/v1/scan -F FILES=@a.pdf -F FILES=@bundle.zip
```

Other endpoints:
```sh
curl http://localhost:8080/api/v1/version        # ClamAV version
curl http://localhost:8080/api/v1/dbsignatures   # is the local DB up to date?
```

## Tuning

- Archive / zip-bomb limits live in `clamd.conf` (`MaxScanSize`, `MaxFileSize`,
  `MaxRecursion`, `MaxFiles`, `StreamMaxLength`). Keep `StreamMaxLength` >=
  `APP_MAX_FILE_SIZE`.
- Concurrency: clamd `MaxThreads` (default 10) caps simultaneous scans. Make
  the caller send no more than ~that many parallel requests, or it will queue/
  stall. This is exactly where your platform-side queue belongs.

## If clamav stays "unhealthy"

```sh
docker compose logs clamav
```
Usually it's still downloading signatures (give it longer) or a typo in
`clamd.conf`. As a fallback you can drop the custom healthcheck block and the
`clamd.conf` mount to confirm the image runs with defaults first, then add the
config back.
