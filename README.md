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

### Состав `DIRECT`

Российское — то, что физически стоит в России, плюс сети крупных российских
компаний и ручные добавки (решение 05-11-2026). Только IPv4:

1. `geoip:ru` из последнего выпуска
   [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat)
   (`geoip.dat`): российское по геобазе. Файл сверяется с `geoip.dat.sha256sum`
   того же выпуска.
2. Сети компаний из `direct-asn.txt` (ниже): все IPv4-префиксы, которые эти ASN
   анонсируют, даже если часть сетей стоит за границей. Российские сервисы через
   VPN не идут никогда.
3. Ручные добавки из `direct-extra.txt`:
   - `ripe:XX` — все сети страны `XX` по RIPE NCC, обновляются с каждой сборкой
     (сейчас `ripe:BY`, Беларусь);
   - CIDR пушей Apple (APNs);
   - прочие CIDR из прошлых версий файла. Их нет ни у runetfreedom, ни в RIPE RU,
     поэтому они помечены «пересмотреть».

«Всё RU по RIPE NCC» в `DIRECT` не берётся. Сети, записанные на Россию, но
стоящие за границей (например, хостинги с российским юрлицом и машинами в
других странах), в `DIRECT` не попадают, если их нет в
`direct-asn.txt` или `direct-extra.txt`. Файл RIPE
(`delegated-ripencc-extended-latest`, сверка с `.md5`) нужен для `ripe:XX` и для
отчёта.

IPv6-часть `DIRECT` переносится из прошлого файла без изменений (85 CIDR). Из
новых источников IPv6 не берётся, строку IPv6 в `direct-extra.txt` сборщик не
принимает.

### Сети компаний (ASN)

`direct-asn.txt` — по строке на ASN: `AS<номер>  # компания, что это`. Сейчас
89 номеров: Яндекс (с облаком и CDN), VK / Mail.ru, Сбер, Т-Банк, Альфа-Банк,
ВТБ, Ozon, Wildberries, Avito, Госуслуги и Минцифры (электронное правительство
Ростелекома, НИИ «Восход»), Ростелеком, МТС, МегаФон, Билайн, Т2, Касперский,
1С, Rambler, X5, НСПК (Мир, СБП), Почта России, Газпромбанк. Чего в списке нет и
почему — в шапке файла.

Новый номер добавлять, только если держатель по RIPEstat as-overview —
та самая компания:

```sh
curl -sS 'https://stat.ripe.net/data/as-overview/data.json?resource=AS13238'
```

Название не совпало — не добавлять.

`tools/fetch-geoip-sources.sh` по каждому ASN сохраняет ответы RIPEstat
(`as-overview` и `announced-prefixes`, окно две недели) в папку источников,
`asn/AS<номер>.overview.json` и `asn/AS<номер>.prefixes.json`. Сборщик дальше
работает без сети. Если RIPEstat по ASN не ответил, скрипт не падает: номер
попадает в `asn_failed=` в `sources.txt`. После 5 отказов подряд остальные ASN
не запрашиваются.

`direct-asn-cache.txt` — кэш в репозитории: префиксы каждого ASN и держатель на
момент последней удачной сборки. Его пишет сборщик, руками не править. Если
ответа RIPEstat по ASN нет или он битый, сборщик берёт префиксы из кэша и пишет
об этом в отчёте («ВНИМАНИЕ», строка «из кэша» в «Источниках»). Нет ни ответа,
ни кэша — сборка останавливается. Предупреждения также выдаются, если:

- сменился держатель ASN;
- ASN потерял больше половины адресов;
- RIPEstat вернул 0 IPv4-префиксов. Тогда сборщик берёт кэш; если ASN правда
  больше не анонсируется, его надо убрать из списка.

Служебные сети (10/8, 192.168/16 и подобные) из анонсов выбрасываются.

### Предохранители

Сборка останавливается без записи файла, если:

- файл вырос больше чем на 20 % (его грузят телефоны);
- `DIRECT` потерял больше 10 % адресов относительно прошлого файла. Для разовой
  перестройки состава есть флаг `--allow-shrink`: ошибка становится
  предупреждением. По умолчанию предохранитель включён, workflow флаг не передаёт;
- в RIPE или у runetfreedom меньше 30 млн адресов RU — источник, похоже, битый;
- по какому-то ASN нет ни ответа RIPEstat, ни кэша.

Первая перестройка по новому составу (05-11-2026) потеряла 2,1 % адресов
относительно пробной сборки и 0,75 % относительно v1.0.6, так что флаг не
понадобился.

### Отчёт

`build-report.txt`:

- источники, ASN из кэша;
- CIDR и адреса по тегам;
- состав `DIRECT` по источникам;
- «RIPE RU, но не в России по геобазе»: сколько таких адресов, сколько из них
  вернули сети компаний, сколько ушло и где они по геобазе runetfreedom;
- вклад каждого ASN: держатель, дата данных RIPEstat, адреса и сколько из них
  сверх `geoip:ru` (по странам);
- разница с прошлым файлом и с файлами из `--compare`: крупнейшие добавленные и
  убранные сети;
- размер, sha256, предупреждения.

### Проверка

`tools/check-geoip.mjs` разбирает файл своим кодом, отдельно от сборщика: все
теги на месте, у каждого больше нуля CIDR, адреса корректны, `PRIVATE` и
`WHITELIST` побайтно совпадают с прошлым файлом. Плюс адреса с известным ответом:

- Яндекс, VK, Сбер и Касперский в `DIRECT`, в том числе их сети вне `geoip:ru`;
- Hetzner и OVH в Германии и Google DNS — не в `DIRECT`.

С `--xray` проверяет файл настоящим ядром:

- `xray run -test` с правилами `geoip:direct`, `geoip:private`, `geoip:whitelist`
  (`XRAY_LOCATION_ASSET` указывает на временную папку с файлом);
- конфиг с несуществующим тегом обязан упасть, иначе проверка ничего не доказывает;
- ядро поднимается с SOCKS на 127.0.0.1 и выходами blackhole, наружу ничего не
  уходит. Через него открываются соединения на выборку адресов, а по журналу
  доступа сверяется, в какой выход ядро отправило каждый адрес;
- отдельный запуск с правилом `geoip:direct` первым — для адресов с известным
  ответом (адреса компаний часто есть и в `WHITELIST`, который в первом запуске
  стоит раньше).

Workflow берёт xray закреплённой версии и сверяет sha256 архива.

### Локальный запуск

```sh
# скачанное — недоверенные данные: отдельная пустая папка, только чтение
CURL_IFACE=en0 tools/fetch-geoip-sources.sh /tmp/geoip-src   # CURL_IFACE — по желанию
cp geoip-mini.dat /tmp/prev-geoip-mini.dat
node tools/build-geoip.mjs --prev /tmp/prev-geoip-mini.dat \
  --ripe /tmp/geoip-src/ripe.txt --runet /tmp/geoip-src/runet-geoip.dat \
  --sources /tmp/geoip-src/sources.txt --extra direct-extra.txt \
  --asn direct-asn.txt --asn-dir /tmp/geoip-src/asn --asn-cache direct-asn-cache.txt \
  --out geoip-mini.dat --report build-report.txt
node tools/check-geoip.mjs --dat geoip-mini.dat --prev /tmp/prev-geoip-mini.dat \
  --xray /path/to/xray --append build-report.txt
```

`--compare метка=старый.dat` (можно несколько раз) добавляет в отчёт разницу
`DIRECT` ещё с одним файлом, например с последней выложенной версией.
`RUNET_TAG=<выпуск>` закрепляет выпуск runetfreedom.

### Порядок выкладки

1. Workflow кладёт `geoip-mini.dat`, `geoip-mini.dat.sha256`, `build-report.txt` и
   `direct-asn-cache.txt` в ветку `geoip-auto` и открывает PR в `main`. Тегов он
   не ставит и в `main` не пишет. Ветку `geoip-auto` он каждый раз пересоздаёт,
   поэтому свои правки в неё не класть.
2. В PR посмотреть отчёт:
   - все «ВНИМАНИЕ»: ASN из кэша, смена держателя, потеря адресов;
   - «RIPE RU, но не в России по геобазе»;
   - вклад ASN;
   - крупнейшие добавленные и убранные сети.
3. Слить PR.
4. Поставить на коммит слияния новый тег `vX` и запушить его. Существующий тег
   не переставлять: jsDelivr навсегда кэширует файлы версии.
5. Дождаться, пока jsDelivr отдаёт файл по новому тегу и его sha256 совпадает с
   `geoip-mini.dat.sha256`:

   ```sh
   curl -sSf https://cdn.jsdelivr.net/gh/cipheroute/xghqj-whzpq-whqhn@vX/geoip-mini.dat | shasum -a 256
   ```

6. Только после этого менять заголовок `routing` в панели на `@vX`. Если сменить
   раньше, клиенты получат 404 на гео-файлы, и ядро не стартует.

Новый тег, пока не сменён заголовок в панели, ни на кого не действует. Откат —
вернуть в заголовке прежний тег.

Чтобы workflow мог открыть PR, в настройках репозитория должна быть включена
опция «Allow GitHub Actions to create and approve pull requests» (Settings →
Actions → General). Права: у сборки — только `contents: read`, у шага с PR —
`contents: write` и `pull-requests: write`.
