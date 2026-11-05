#!/usr/bin/env bash
# Скачивает источники для tools/build-geoip.mjs в отдельную ПУСТУЮ папку:
#   ripe.txt       — delegated-ripencc-extended-latest (сверка с .md5 от RIPE);
#   runet-geoip.dat — geoip.dat последнего выпуска runetfreedom/russia-v2ray-rules-dat
#                    (сверка с geoip.dat.sha256sum того же выпуска);
#   sources.txt    — откуда и что скачано (попадает в отчёт сборки).
#
# Скачанное — недоверенные данные: сборщик их только читает и разбирает,
# ничего из папки не исполняется.
#
# Переменные окружения:
#   CURL_IFACE — сетевой интерфейс для curl (--interface), например en0,
#                чтобы запросы шли мимо VPN;
#   RUNET_TAG  — взять конкретный выпуск runetfreedom вместо последнего.
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

{
  echo "fetched_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ripe_url=$ripe_url"
  echo "ripe_header=$(head -n 1 "$out/ripe.txt" | tr -cd '[:print:]')"
  echo "ripe_md5=$ripe_md5_actual (сходится с .md5)"
  echo "runet_release=$runet_repo/releases/tag/$tag"
  echo "runet_sha256=$runet_sha_actual (сходится с geoip.dat.sha256sum)"
} > "$out/sources.txt"

cat "$out/sources.txt"
