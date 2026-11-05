# Remnawave mini geodata

Small geodata files for the Remnawave/Happ split-routing templates.

## CDN URLs

Use a published version in production, for example `v1.0.5`:

```text
https://cdn.jsdelivr.net/gh/cipheroute/xghqj-whzpq-whqhn@v1.0.5/geosite-mini.dat
https://cdn.jsdelivr.net/gh/cipheroute/xghqj-whzpq-whqhn@v1.0.5/geoip-mini.dat
```

## Happ routing profile

The versioned profile duplicates critical direct domains in `DirectSites`, so
it works immediately even while Happ still has an older geosite file cached.
Copy the only line from this file into the Remnawave Happ Routing field:

```text
https://cdn.jsdelivr.net/gh/cipheroute/xghqj-whzpq-whqhn@v1.0.5/happ-routing-onadd.txt
```

The decoded source profile is stored in `happ-routing.json`.

`geosite-mini.dat` contains the merged custom Russian-domain rules.
`geoip-mini.dat` contains the compact direct/private/whitelist IP rules.

Domains that must be routed directly are tracked in `whitelist-exact.txt`.
Use `full:` for an exact hostname or `domain:` for the hostname and all its
subdomains. Apply the rules to `geosite-mini.dat` with:

```text
node tools/update-geosite-whitelist.mjs geosite-mini.dat whitelist-exact.txt
```

For `github.com`, the updater also replaces the broad `GITHUB` root-domain
entry with a regex that matches subdomains only. This keeps `github.com` in
`WHITELIST` as an exact match while `*.github.com` remains in `GITHUB`.

The files contain no VPN credentials, subscriptions, server addresses, or private keys.

## Сборка geoip

`geoip-mini.dat` пересобирается раз в месяц: workflow
`.github/workflows/geoip-monthly.yml` запускается 2-го числа (и вручную через
«Run workflow»). Тег `DIRECT` собирается заново, `PRIVATE` и `WHITELIST`
переносятся из прошлого файла побайтно. Новых тегов сборка не добавляет и старые
не переименовывает: на них ссылаются шаблоны маршрутизации.

### Источники `DIRECT`

Только IPv4:

- RIPE NCC, `delegated-ripencc-extended-latest`: сети со страной `RU` и статусом
  `allocated` или `assigned`. Файл сверяется с `.md5` от RIPE.
- `geoip:ru` из последнего выпуска
  [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat)
  (`geoip.dat`). Файл сверяется с `geoip.dat.sha256sum` того же выпуска.
- Ручные добавки из `direct-extra.txt`:
  - `ripe:XX` — все сети страны `XX` по RIPE, обновляются с каждой сборкой
    (сейчас `ripe:BY`, Беларусь);
  - CIDR пушей Apple (APNs);
  - прочие CIDR из прошлых версий файла. Их нет ни в RIPE RU, ни у runetfreedom,
    поэтому они помечены «пересмотреть».

IPv6-часть `DIRECT` переносится из прошлого файла без изменений. Новых IPv6
сборщик не добавляет, а строку IPv6 в `direct-extra.txt` не принимает.

Пересекающиеся отрезки сливаются, набор CIDR минимизируется. Сборка
останавливается без записи файла, если:

- файл вырос больше чем на 20 % (его грузят телефоны);
- `DIRECT` потерял больше 10 % адресов;
- в источнике меньше 30 млн адресов RU, то есть он, похоже, битый.

Отчёт пишется в `build-report.txt`: CIDR и адреса по тегам, что добавилось и
что убралось, крупнейшие изменения, размер и sha256.

### Проверка

`tools/check-geoip.mjs` разбирает файл своим кодом, отдельно от сборщика: все
теги на месте, у каждого больше нуля CIDR, адреса корректны, `PRIVATE` и
`WHITELIST` побайтно совпадают с прошлым файлом. С `--xray` проверяет файл
настоящим ядром:

- `xray run -test` с правилами `geoip:direct`, `geoip:private`, `geoip:whitelist`
  (`XRAY_LOCATION_ASSET` указывает на временную папку с файлом);
- конфиг с несуществующим тегом обязан упасть, иначе проверка ничего не доказывает;
- ядро поднимается с SOCKS на 127.0.0.1 и выходами blackhole, наружу ничего не
  уходит. Через него открываются соединения на выборку адресов, а по журналу
  доступа сверяется, в какой выход ядро отправило каждый адрес.

Workflow берёт xray закреплённой версии и сверяет sha256 архива.

### Локальный запуск

```sh
# скачанное — недоверенные данные: отдельная пустая папка, только чтение
CURL_IFACE=en0 tools/fetch-geoip-sources.sh /tmp/geoip-src   # CURL_IFACE — по желанию
cp geoip-mini.dat /tmp/prev-geoip-mini.dat
node tools/build-geoip.mjs --prev /tmp/prev-geoip-mini.dat \
  --ripe /tmp/geoip-src/ripe.txt --runet /tmp/geoip-src/runet-geoip.dat \
  --sources /tmp/geoip-src/sources.txt --extra direct-extra.txt \
  --out geoip-mini.dat --report build-report.txt
node tools/check-geoip.mjs --dat geoip-mini.dat --prev /tmp/prev-geoip-mini.dat \
  --xray /path/to/xray --append build-report.txt
```

### Порядок выкладки

1. Workflow кладёт `geoip-mini.dat`, `geoip-mini.dat.sha256` и `build-report.txt`
   в ветку `geoip-auto` и открывает PR в `main`. Тегов он не ставит и в `main` не
   пишет. Ветку `geoip-auto` он каждый раз пересоздаёт, поэтому свои правки в неё
   не класть. В PR посмотреть отчёт: крупнейшие добавленные и убранные сети.
2. Слить PR.
3. Поставить на коммит слияния новый тег `vX` и запушить его. Существующий тег
   не переставлять: jsDelivr навсегда кэширует файлы версии.
4. Дождаться, пока jsDelivr отдаёт файл по новому тегу и его sha256 совпадает с
   `geoip-mini.dat.sha256`:

   ```sh
   curl -sSf https://cdn.jsdelivr.net/gh/cipheroute/xghqj-whzpq-whqhn@vX/geoip-mini.dat | shasum -a 256
   ```

5. Только после этого менять заголовок `routing` в панели на `@vX`. Если сменить
   раньше, клиенты получат 404 на гео-файлы, и ядро не стартует.

Новый тег, пока не сменён заголовок в панели, ни на кого не действует. Откат —
вернуть в заголовке прежний тег.

Чтобы workflow мог открыть PR, в настройках репозитория должна быть включена
опция «Allow GitHub Actions to create and approve pull requests» (Settings →
Actions → General). Права: у сборки — только `contents: read`, у шага с PR —
`contents: write` и `pull-requests: write`.
