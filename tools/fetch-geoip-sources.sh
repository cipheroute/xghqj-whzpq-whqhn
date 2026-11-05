#!/usr/bin/env bash
# Скачивает источники для tools/build-geoip.mjs в отдельную ПУСТУЮ папку:
#   ripe.txt       — delegated-ripencc-extended-latest (сверка с .md5 от RIPE);
#   runet-geoip.dat — geoip.dat последнего выпуска runetfreedom/russia-v2ray-rules-dat
#                    (сверка с geoip.dat.sha256sum того же выпуска);
#   asn/AS<N>.overview.json, asn/AS<N>.prefixes.json — ответы RIPEstat (as-overview и
#                    announced-prefixes) по каждому ASN из direct-asn.txt;
#   sources.txt    — откуда и что скачано (попадает в отчёт сборки).
#
# Скачанное — недоверенные данные: сборщик их только читает и разбирает,
# ничего из папки не исполняется.
#
# RIPEstat по отдельному ASN может не ответить — скрипт тогда не падает: файлов этого
# ASN в asn/ нет, номер записан в sources.txt (asn_failed=), а сборщик берёт его
# префиксы из direct-asn-cache.txt. После ASN_MAX_FAILS отказов подряд RIPEstat
# считается недоступным, и остальные ASN не запрашиваются.
#
# Переменные окружения:
#   CURL_IFACE    — сетевой интерфейс для curl (--interface), например en0,
#                   чтобы запросы шли мимо VPN;
#   RUNET_TAG     — взять конкретный выпуск runetfreedom вместо последнего;
#   ASN_FILE      — список ASN (по умолчанию direct-asn.txt в корне репозитория);
#   ASN_MAX_FAILS — сколько отказов RIPEstat подряд терпеть (по умолчанию 5).
#
# Пример: CURL_IFACE=en0 tools/fetch-geoip-sources.sh /tmp/geoip-src
set -euo pipefail

out=${1:?запуск: tools/fetch-geoip-sources.sh <пустая папка>}
mkdir -p "$out"
if [ -n "$(ls -A "$out")" ]; then
  echo "ошибка: папка $out не пуста" >&2
  exit 1
fi

curl_opts=(--fail --silent --show-error --proto '=https' --tlsv1.2 --retry 3 --retry-delay 10 --max-time 600)
if [ -n "${CURL_IFACE:-}" ]; then
  curl_opts+=(--interface "$CURL_IFACE")
fi

fetch() { curl "${curl_opts[@]}" --location -o "$2" "$1"; }

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
asn_file=${ASN_FILE:-$repo/direct-asn.txt}
asn_max_fails=${ASN_MAX_FAILS:-5}
if [ ! -f "$asn_file" ]; then
  echo "ошибка: нет списка ASN $asn_file" >&2
  exit 1
fi

digest() {
  node -e 'const c = require("node:crypto"), f = require("node:fs");
process.stdout.write(c.createHash(process.argv[1]).update(f.readFileSync(process.argv[2])).digest("hex"));' "$1" "$2"
}

# --- RIPE NCC ---------------------------------------------------------------
ripe_url=https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
fetch "$ripe_url.md5" "$out/ripe.txt.md5"
fetch "$ripe_url" "$out/ripe.txt"
ripe_md5_expected=$(sed -n 's/^MD5 (.*) = \([0-9a-f]\{32\}\)$/\1/p' "$out/ripe.txt.md5")
ripe_md5_actual=$(digest md5 "$out/ripe.txt")
if [ -z "$ripe_md5_expected" ] || [ "$ripe_md5_expected" != "$ripe_md5_actual" ]; then
  echo "ошибка: md5 файла RIPE не сходится (ждали '$ripe_md5_expected', получили '$ripe_md5_actual')" >&2
  exit 1
fi

# --- runetfreedom -----------------------------------------------------------
runet_repo=https://github.com/runetfreedom/russia-v2ray-rules-dat
tag=${RUNET_TAG:-}
if [ -z "$tag" ]; then
  # /releases/latest отвечает 302 на /releases/tag/<tag>; берём тег, дальше качаем по нему,
  # чтобы файл и сумма были из одного выпуска.
  location=$(curl "${curl_opts[@]}" -o /dev/null -w '%{redirect_url}' "$runet_repo/releases/latest")
  tag=${location##*/releases/tag/}
fi
if ! [[ "$tag" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "ошибка: странный тег выпуска runetfreedom '$tag'" >&2
  exit 1
fi
fetch "$runet_repo/releases/download/$tag/geoip.dat.sha256sum" "$out/runet-geoip.dat.sha256sum"
fetch "$runet_repo/releases/download/$tag/geoip.dat" "$out/runet-geoip.dat"
runet_sha_expected=$(awk 'NR == 1 { print $1 }' "$out/runet-geoip.dat.sha256sum")
runet_sha_actual=$(digest sha256 "$out/runet-geoip.dat")
if ! [[ "$runet_sha_expected" =~ ^[0-9a-f]{64}$ ]] || [ "$runet_sha_expected" != "$runet_sha_actual" ]; then
  echo "ошибка: sha256 geoip.dat runetfreedom не сходится (ждали '$runet_sha_expected', получили '$runet_sha_actual')" >&2
  exit 1
fi

# --- RIPEstat: сети компаний из direct-asn.txt --------------------------------
# Одна попытка с повтором на ASN, короче общих таймаутов: запросов много, а отказ по
# одному ASN не страшен — сборщик возьмёт кэш.
ripestat=https://stat.ripe.net/data
ripestat_opts=(--fail --silent --show-error --proto '=https' --tlsv1.2 --retry 2 --retry-delay 5 --max-time 60)
if [ -n "${CURL_IFACE:-}" ]; then
  ripestat_opts+=(--interface "$CURL_IFACE")
fi
ripestat_get() { # <data call> <ASN> <файл>
  curl "${ripestat_opts[@]}" -o "$3" "$ripestat/$1/data.json?resource=$2&sourceapp=geoip-mini"
}

asns=()
while IFS= read -r line; do
  line=${line%%#*}
  line=$(printf '%s' "$line" | tr -d '[:space:]')
  [ -z "$line" ] && continue
  if ! [[ "$line" =~ ^AS[0-9]{1,10}$ ]]; then
    echo "ошибка: $asn_file: странная строка '$line'" >&2
    exit 1
  fi
  asns+=("$line")
done < "$asn_file"
if [ "${#asns[@]}" -eq 0 ]; then
  echo "ошибка: в $asn_file нет ни одного ASN" >&2
  exit 1
fi

mkdir "$out/asn"
asn_ok=0
asn_failed=()
fails_in_row=0
for asn in "${asns[@]}"; do
  if [ "$fails_in_row" -ge "$asn_max_fails" ]; then
    asn_failed+=("$asn")
    continue
  fi
  if ripestat_get as-overview "$asn" "$out/asn/$asn.overview.json" \
    && ripestat_get announced-prefixes "$asn" "$out/asn/$asn.prefixes.json"; then
    asn_ok=$((asn_ok + 1))
    fails_in_row=0
  else
    echo "предупреждение: RIPEstat не ответил по $asn — сборка возьмёт кэш" >&2
    rm -f "$out/asn/$asn.overview.json" "$out/asn/$asn.prefixes.json"
    asn_failed+=("$asn")
    fails_in_row=$((fails_in_row + 1))
  fi
  sleep 0.3
done
if [ "$fails_in_row" -ge "$asn_max_fails" ]; then
  echo "предупреждение: $asn_max_fails отказов RIPEstat подряд — остальные ASN не запрашивались" >&2
fi

{
  echo "fetched_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ripe_url=$ripe_url"
  echo "ripe_header=$(head -n 1 "$out/ripe.txt" | tr -cd '[:print:]')"
  echo "ripe_md5=$ripe_md5_actual (сходится с .md5)"
  echo "runet_release=$runet_repo/releases/tag/$tag"
  echo "runet_sha256=$runet_sha_actual (сходится с geoip.dat.sha256sum)"
  echo "asn_source=$ripestat/{as-overview,announced-prefixes}"
  echo "asn_fetched=$asn_ok из ${#asns[@]}"
  echo "asn_failed=${asn_failed[*]:-нет}"
} > "$out/sources.txt"

cat "$out/sources.txt"
