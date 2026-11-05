// Сборка geoip-mini.dat: тег DIRECT пересобирается из источников, остальные теги
// переносятся из прошлого файла побайтно.
//
//   DIRECT = IPv4 из geoip:ru runetfreedom/russia-v2ray-rules-dat — российское по геобазе
//          ∪ анонсируемые IPv4-префиксы ASN из direct-asn.txt — сети крупных российских
//            компаний, в том числе стоящие за границей (RIPEstat; если по ASN он не ответил —
//            префиксы из direct-asn-cache.txt)
//          ∪ ручные добавки из direct-extra.txt
//          + IPv6-часть DIRECT прошлого файла без изменений (новых IPv6 не добавляем).
//
// «Всё RU по RIPE NCC» в DIRECT больше не берётся (решение 05-11-2026): сети, записанные
// на Россию, но стоящие за границей, туда не попадают, если они не из списка компаний.
// Файл RIPE (delegated-ripencc-extended) нужен для добавок ripe:XX и для отчёта.
//
// Источники качает tools/fetch-geoip-sources.sh; этот скрипт в сеть не ходит.
// Без зависимостей, protobuf разбирается и пишется вручную, как в остальных tools/*.mjs.
//
// node tools/build-geoip.mjs --prev geoip-mini.dat --ripe SRC/ripe.txt \
//   --runet SRC/runet-geoip.dat --extra direct-extra.txt \
//   --asn direct-asn.txt --asn-dir SRC/asn --asn-cache direct-asn-cache.txt \
//   [--sources SRC/sources.txt] [--compare метка=старый.dat ...] [--allow-shrink] \
//   --out geoip-mini.dat --report build-report.txt
//
// --asn-cache читается (префиксы ASN, по которым RIPEstat не ответил) и после удачной сборки
// перезаписывается: в нём всегда префиксы того файла, что собран. Без --asn-dir все ASN
// берутся из кэша. --compare добавляет в отчёт разницу DIRECT с ещё одним файлом.
// --allow-shrink снимает предохранитель «DIRECT потерял больше --max-shrink адресов»:
// только для разовой перестройки состава, ошибка становится предупреждением.

import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {basename, join} from 'node:path';
import {parseArgs} from 'node:util';

const REQUIRED_TAGS = ['DIRECT', 'PRIVATE', 'WHITELIST'];
const REBUILT_TAG = 'DIRECT';
// Защита от битых источников: на 05-11-2026 у RU ~45 млн IPv4 и в RIPE, и у runetfreedom.
const MIN_SOURCE_ADDRESSES = 30_000_000;
const TOP_CHANGES = 20;
const TOP_GEO = 12;
// Данные RIPEstat старше этого — предупреждение (окно announced-prefixes — две недели).
const MAX_ASN_DATA_AGE_DAYS = 30;

const {values: args} = parseArgs({
  options: {
    prev: {type: 'string'},
    ripe: {type: 'string'},
    runet: {type: 'string'},
    extra: {type: 'string'},
    asn: {type: 'string'},
    'asn-dir': {type: 'string'},
    'asn-cache': {type: 'string'},
    sources: {type: 'string'},
    compare: {type: 'string', multiple: true, default: []},
    out: {type: 'string'},
    report: {type: 'string'},
    'max-growth': {type: 'string', default: '0.20'},
    'max-shrink': {type: 'string', default: '0.10'},
    'allow-shrink': {type: 'boolean', default: false},
  },
});

for (const name of ['prev', 'ripe', 'runet', 'extra', 'asn', 'asn-cache', 'out', 'report']) {
  if (!args[name]) {
    throw new Error(
      'Запуск: node tools/build-geoip.mjs --prev geoip-mini.dat --ripe ripe.txt --runet runet-geoip.dat '
      + '--extra direct-extra.txt --asn direct-asn.txt [--asn-dir SRC/asn] --asn-cache direct-asn-cache.txt '
      + '[--sources sources.txt] [--compare метка=файл.dat] [--allow-shrink] --out geoip-mini.dat --report build-report.txt',
    );
  }
}
const maxGrowth = Number(args['max-growth']);
const maxShrink = Number(args['max-shrink']);
const compares = args.compare.map((value) => {
  const index = value.indexOf('=');
  if (index < 1 || index === value.length - 1) throw new Error(`--compare ${value}: нужно метка=файл`);
  return {label: value.slice(0, index), path: value.slice(index + 1)};
});

// ---------------------------------------------------------------- protobuf ---

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;
  for (let index = offset; index < buffer.length; index += 1) {
    const byte = buffer[index];
    value += (byte & 0x7f) * (2 ** shift);
    if ((byte & 0x80) === 0) return {value, nextOffset: index + 1};
    shift += 7;
    if (shift > 49) throw new Error('Слишком длинный varint.');
  }
  throw new Error('Varint обрывается на конце данных.');
}

function writeVarint(value) {
  const bytes = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining > 0);
  return Buffer.from(bytes);
}

function readFields(buffer) {
  const fields = [];
  let offset = 0;
  while (offset < buffer.length) {
    const fieldStart = offset;
    const tag = readVarint(buffer, offset);
    offset = tag.nextOffset;
    const wireType = tag.value % 8;
    let value;
    if (wireType === 0) {
      const integer = readVarint(buffer, offset);
      value = integer.value;
      offset = integer.nextOffset;
    } else if (wireType === 2) {
      const length = readVarint(buffer, offset);
      const start = length.nextOffset;
      const end = start + length.value;
      if (end > buffer.length) throw new Error('Поле protobuf выходит за конец данных.');
      value = buffer.subarray(start, end);
      offset = end;
    } else if (wireType === 1 || wireType === 5) {
      const end = offset + (wireType === 1 ? 8 : 4);
      if (end > buffer.length) throw new Error('Поле protobuf выходит за конец данных.');
      value = buffer.subarray(offset, end);
      offset = end;
    } else {
      throw new Error(`Неподдерживаемый wire type protobuf: ${wireType}.`);
    }
    fields.push({number: Math.floor(tag.value / 8), wireType, value, raw: buffer.subarray(fieldStart, offset)});
  }
  return fields;
}

function lengthDelimited(fieldNumber, body) {
  return Buffer.concat([writeVarint(fieldNumber * 8 + 2), writeVarint(body.length), body]);
}

// GeoIPList { repeated GeoIP entry = 1 }, GeoIP { string code = 1; repeated CIDR cidr = 2; ... },
// CIDR { bytes ip = 1; uint32 prefix = 2 }.
function readGeoIPList(buffer, label) {
  return readFields(buffer).map((field) => {
    if (field.number !== 1 || field.wireType !== 2) throw new Error(`${label}: неожиданное поле верхнего уровня.`);
    const fields = readFields(field.value);
    if (fields[0]?.number !== 1 || fields[0].wireType !== 2) {
      // ядро ищет тег по первому полю записи, так что код обязан идти первым
      throw new Error(`${label}: у записи код не первым полем.`);
    }
    return {code: fields[0].value.toString('utf8'), raw: field.raw, fields};
  });
}

function readCidr(field, label) {
  const fields = readFields(field.value);
  const ip = fields.find((item) => item.number === 1 && item.wireType === 2)?.value;
  const prefix = fields.find((item) => item.number === 2 && item.wireType === 0)?.value ?? 0;
  if (!ip || (ip.length !== 4 && ip.length !== 16)) throw new Error(`${label}: CIDR с адресом не из 4 и не из 16 байт.`);
  if (prefix > ip.length * 8) throw new Error(`${label}: CIDR с префиксом /${prefix}.`);
  return {ip, prefix};
}

function encodeCidr4(start, prefix) {
  const ip = Buffer.alloc(4);
  ip.writeUInt32BE(start);
  const body = Buffer.concat([Buffer.from([0x0a, 0x04]), ip, Buffer.from([0x10]), writeVarint(prefix)]);
  return lengthDelimited(2, body);
}

// ------------------------------------------------------------ IPv4 ranges ---
// Отрезки — пары [начало, конец) в числах; 2^32 помещается в double без потерь.

const TWO32 = 2 ** 32;

function parseIPv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part) || Number(part) > 255) return undefined;
    value = value * 256 + Number(part);
  }
  return value;
}

function formatIPv4(value) {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / (2 ** shift)) % 256).join('.');
}

function merge(ranges) {
  const sorted = ranges.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out = [];
  for (const [start, end] of sorted) {
    const last = out[out.length - 1];
    if (last && start <= last[1]) {
      if (end > last[1]) last[1] = end;
    } else {
      out.push([start, end]);
    }
  }
  return out;
}

function subtract(a, b) {
  const out = [];
  let j = 0;
  for (const [start, end] of a) {
    let cursor = start;
    while (j < b.length && b[j][1] <= cursor) j += 1;
    for (let k = j; k < b.length && b[k][0] < end; k += 1) {
      if (b[k][0] > cursor) out.push([cursor, b[k][0]]);
      cursor = Math.max(cursor, b[k][1]);
    }
    if (cursor < end) out.push([cursor, end]);
  }
  return out;
}

function intersect(a, b) {
  const out = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const start = Math.max(a[i][0], b[j][0]);
    const end = Math.min(a[i][1], b[j][1]);
    if (start < end) out.push([start, end]);
    if (a[i][1] < b[j][1]) i += 1; else j += 1;
  }
  return out;
}

const total = (ranges) => ranges.reduce((sum, [start, end]) => sum + end - start, 0);

// Минимальный набор CIDR для слитых отрезков: от начала берём самый крупный выровненный блок.
function toCidrs(ranges) {
  const out = [];
  for (const [rangeStart, end] of ranges) {
    let start = rangeStart;
    while (start < end) {
      let prefix = 32;
      while (prefix > 0) {
        const size = 2 ** (33 - prefix);
        if (start % size !== 0 || start + size > end) break;
        prefix -= 1;
      }
      out.push([start, prefix]);
      start += 2 ** (32 - prefix);
    }
  }
  return out;
}

const cidrRange = (start, prefix) => [start, start + 2 ** (32 - prefix)];

function describeRange([start, end]) {
  const cidrs = toCidrs([[start, end]]);
  const text = cidrs.length === 1
    ? `${formatIPv4(cidrs[0][0])}/${cidrs[0][1]}`
    : `${formatIPv4(start)}–${formatIPv4(end - 1)}`;
  return `${text} (${fmt(end - start)})`;
}


// ---------------------------------------------------------------- sources ---

function readRipe(path) {
  const text = readFileSync(path, 'utf8');
  if (!text.startsWith('2|ripencc|')) throw new Error(`${path}: не похоже на delegated-ripencc-extended.`);
  const byCountry = new Map();
  const all = [];
  let lines = 0;
  for (const line of text.split('\n')) {
    const parts = line.split('|');
    if (parts.length < 7 || parts[2] !== 'ipv4' || parts[1] === '*') continue;
    const status = parts[6].trim();
    if (status !== 'allocated' && status !== 'assigned') continue;
    const start = parseIPv4(parts[3]);
    const count = Number(parts[4]);
    if (start === undefined || !Number.isInteger(count) || count <= 0 || start + count > TWO32) {
      throw new Error(`${path}: битая строка: ${line.slice(0, 120)}`);
    }
    const country = parts[1].toUpperCase();
    if (!byCountry.has(country)) byCountry.set(country, []);
    byCountry.get(country).push([start, start + count]);
    all.push([start, start + count, country]);
    lines += 1;
  }
  for (const [country, ranges] of byCountry) byCountry.set(country, merge(ranges));
  all.sort((a, b) => a[0] - b[0]);
  return {byCountry, all, lines, header: text.slice(0, text.indexOf('\n'))};
}

// geoip.dat runetfreedom: тег RU идёт в DIRECT, двухбуквенные теги стран — для отчёта
// («где по геобазе» то, что ушло или пришло).
function readRunet(path) {
  const entries = readGeoIPList(readFileSync(path), path);
  const ruEntries = entries.filter((entry) => entry.code.toUpperCase() === 'RU');
  if (ruEntries.length !== 1) throw new Error(`${path}: тег RU найден ${ruEntries.length} раз.`);
  const geo = [];
  let ranges = [];
  let cidrs = 0;
  let ipv6 = 0;
  for (const entry of entries) {
    const code = entry.code.toUpperCase();
    if (!/^[A-Z]{2}$/u.test(code)) continue;
    const list = [];
    for (const field of entry.fields) {
      if (field.number !== 2) continue;
      const {ip, prefix} = readCidr(field, `${path}:${code}`);
      if (ip.length === 16) {
        if (code === 'RU') ipv6 += 1;
        continue;
      }
      if (code === 'RU') cidrs += 1;
      const size = 2 ** (32 - prefix);
      const start = Math.floor(ip.readUInt32BE(0) / size) * size; // на случай лишних бит хоста
      list.push([start, start + size]);
    }
    const merged = merge(list);
    if (code === 'RU') ranges = merged;
    geo.push({code, ranges: merged});
  }
  return {ranges, cidrs, ipv6, tags: entries.length, geo};
}

function readExtra(path, ripe) {
  const ripeCountries = [];
  const cidrRanges = [];
  let cidrLines = 0;
  readFileSync(path, 'utf8').split(/\r?\n/u).forEach((rawLine, index) => {
    const line = rawLine.replace(/#.*$/u, '').trim();
    if (!line) return;
    const where = `${path}:${index + 1}`;
    let match = /^ripe:([A-Za-z]{2})$/u.exec(line);
    if (match) {
      const country = match[1].toUpperCase();
      if (!ripe.byCountry.has(country)) throw new Error(`${where}: в RIPE нет сетей страны ${country}.`);
      ripeCountries.push(country);
      return;
    }
    if (line.includes(':')) throw new Error(`${where}: IPv6 в DIRECT не добавляем: ${line}`);
    match = /^([\d.]+)\/(\d{1,2})$/u.exec(line);
    const start = match && parseIPv4(match[1]);
    const prefix = match && Number(match[2]);
    if (!match || start === undefined || prefix > 32) throw new Error(`${where}: не IPv4 CIDR: ${line}`);
    if (start % (2 ** (32 - prefix)) !== 0) throw new Error(`${where}: у CIDR лишние биты хоста: ${line}`);
    cidrRanges.push(cidrRange(start, prefix));
    cidrLines += 1;
  });
  return {ripeCountries: [...new Set(ripeCountries)], cidrs: merge(cidrRanges), cidrLines};
}

function readSources(path) {
  if (!path) return [];
  return readFileSync(path, 'utf8').split(/\r?\n/u).filter((line) => /^[a-z0-9_]+=/u.test(line)).map((line) => cleanText(line, 300));
}

// ------------------------------------------------------------------- ASN ----
// Ответы RIPEstat — недоверенные данные: только JSON.parse и проверка полей.

// Служебные сети: из анонсов ASN выбрасываются, в DIRECT им не место.
const BOGONS = merge([
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/3',
].map((text) => {
  const [address, prefix] = text.split('/');
  return cidrRange(parseIPv4(address), Number(prefix));
}));

function cleanText(value, max = 200) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]+/gu, ' ').replace(/\s+/gu, ' ').trim().slice(0, max);
}

function readAsnList(path) {
  const list = [];
  const seen = new Set();
  readFileSync(path, 'utf8').split(/\r?\n/u).forEach((rawLine, index) => {
    const hash = rawLine.indexOf('#');
    const line = (hash >= 0 ? rawLine.slice(0, hash) : rawLine).trim();
    if (!line) return;
    const where = `${path}:${index + 1}`;
    const match = /^AS(\d{1,10})$/u.exec(line);
    const asn = match && Number(match[1]);
    if (!match || asn <= 0 || asn > 4294967295) throw new Error(`${where}: не ASN: ${line}`);
    if (seen.has(asn)) throw new Error(`${where}: AS${asn} повторяется.`);
    seen.add(asn);
    list.push({asn, note: hash >= 0 ? cleanText(rawLine.slice(hash + 1), 100) : ''});
  });
  if (!list.length) throw new Error(`${path}: нет ни одного ASN.`);
  return list;
}

// Кэш: «asn AS<номер> <время данных RIPEstat> <держатель>», за ней строки «AS<номер> <CIDR>».
function readAsnCache(path) {
  const cache = new Map();
  if (!existsSync(path)) return cache;
  let current;
  readFileSync(path, 'utf8').split(/\r?\n/u).forEach((line, index) => {
    if (!line.trim() || line.startsWith('#')) return;
    const where = `${path}:${index + 1}`;
    let match = /^asn AS(\d{1,10}) (\S+) ?(.*)$/u.exec(line);
    if (match) {
      const asn = Number(match[1]);
      if (cache.has(asn)) throw new Error(`${where}: AS${asn} в кэше дважды.`);
      current = {asn, time: match[2], holder: cleanText(match[3]), ranges: []};
      cache.set(asn, current);
      return;
    }
    match = /^AS(\d{1,10}) ([\d.]+)\/(\d{1,2})$/u.exec(line);
    const start = match && parseIPv4(match[2]);
    const prefix = match && Number(match[3]);
    if (!match || start === undefined || prefix > 32 || start % (2 ** (32 - prefix)) !== 0) {
      throw new Error(`${where}: битая строка кэша: ${line.slice(0, 80)}`);
    }
    if (!current || current.asn !== Number(match[1])) throw new Error(`${where}: префикс не под своим ASN.`);
    current.ranges.push(cidrRange(start, prefix));
  });
  for (const entry of cache.values()) entry.ranges = merge(entry.ranges);
  return cache;
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return undefined;
  }
}

function readAsnFresh(dir, asn) {
  if (!dir) return {problem: 'RIPEstat не опрашивался (сборка без --asn-dir)'};
  const overviewPath = join(dir, `AS${asn}.overview.json`);
  const prefixesPath = join(dir, `AS${asn}.prefixes.json`);
  if (!existsSync(overviewPath) || !existsSync(prefixesPath)) return {problem: 'RIPEstat не ответил'};
  const overview = readJson(overviewPath);
  const announced = readJson(prefixesPath);
  const sameResource = (doc) => String(doc?.data?.resource ?? '').replace(/^AS/iu, '') === String(asn);
  if (overview?.status !== 'ok' || !sameResource(overview) || typeof overview.data.holder !== 'string') {
    return {problem: 'ответ RIPEstat as-overview битый'};
  }
  if (announced?.status !== 'ok' || !sameResource(announced) || !Array.isArray(announced.data.prefixes)) {
    return {problem: 'ответ RIPEstat announced-prefixes битый'};
  }
  const ranges = [];
  let v4 = 0;
  let v6 = 0;
  let bad = 0;
  for (const item of announced.data.prefixes) {
    const text = typeof item?.prefix === 'string' ? item.prefix : '';
    if (text.includes(':')) {
      v6 += 1; // IPv6 из новых источников не берём
      continue;
    }
    const match = /^([\d.]+)\/(\d{1,2})$/u.exec(text);
    const start = match && parseIPv4(match[1]);
    const prefix = match && Number(match[2]);
    if (!match || start === undefined || prefix > 32 || prefix < 8) {
      bad += 1;
      continue;
    }
    const size = 2 ** (32 - prefix);
    const aligned = Math.floor(start / size) * size;
    ranges.push([aligned, aligned + size]);
    v4 += 1;
  }
  const merged = merge(ranges);
  const clean = subtract(merged, BOGONS);
  const time = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$/u.test(announced.data.query_endtime) ? announced.data.query_endtime : '?';
  return {ranges: clean, holder: cleanText(overview.data.holder), time, v4, v6, bad, bogon: total(merged) - total(clean)};
}

function formatAsnCache(results) {
  const lines = [
    '# direct-asn-cache.txt — пишет tools/build-geoip.mjs после каждой удачной сборки; руками не править.',
    '# IPv4-префиксы ASN из direct-asn.txt, вошедшие в DIRECT собранного geoip-mini.dat (слиты,',
    '# минимальным набором CIDR), и держатель по RIPEstat as-overview. Если RIPEstat по ASN не ответил,',
    '# сборка берёт его префиксы отсюда и пишет об этом в отчёте; при смене держателя — предупреждение.',
    '# Строки: «asn AS<номер> <время данных RIPEstat> <держатель>», за ней «AS<номер> <CIDR>».',
  ];
  for (const result of results) {
    if (result.source === 'none') continue;
    lines.push(`asn AS${result.asn} ${result.time} ${result.holder}`.trimEnd());
    for (const [start, prefix] of toCidrs(result.ranges)) lines.push(`AS${result.asn} ${formatIPv4(start)}/${prefix}`);
  }
  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------- report ----

function fmt(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/gu, ' ');
}

function signed(value) {
  return value > 0 ? `+${fmt(value)}` : value < 0 ? `−${fmt(-value)}` : '0';
}

function ripeCountryOf(ripe, start) {
  let lo = 0;
  let hi = ripe.all.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (ripe.all[mid][0] <= start) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return found >= 0 && ripe.all[found][1] > start ? ripe.all[found][2] : undefined;
}

function contains(ranges, value) {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (ranges[mid][1] <= value) lo = mid + 1;
    else if (ranges[mid][0] > value) hi = mid - 1;
    else return true;
  }
  return false;
}

// ------------------------------------------------------------------ build ---

const errors = [];
const warnings = [];

function readDirect(buffer, label) {
  const entries = readGeoIPList(buffer, label);
  const direct = entries.filter((entry) => entry.code === REBUILT_TAG);
  if (direct.length !== 1) throw new Error(`${label}: тег ${REBUILT_TAG} должен быть ровно один.`);
  const v4 = [];
  const v6Fields = [];
  const otherFields = [];
  for (const field of direct[0].fields.slice(1)) {
    if (field.number !== 2) {
      otherFields.push(field);
      continue;
    }
    const {ip, prefix} = readCidr(field, `${label}:${REBUILT_TAG}`);
    if (ip.length === 16) v6Fields.push(field);
    else v4.push(cidrRange(ip.readUInt32BE(0), prefix));
  }
  return {entries, entry: direct[0], ranges: merge(v4), v4Cidrs: v4.length, v6Fields, otherFields};
}

const prevBuffer = readFileSync(args.prev);
const prev = readDirect(prevBuffer, args.prev);
const prevEntries = prev.entries;
const prevCodes = prevEntries.map((entry) => entry.code);
for (const tag of REQUIRED_TAGS) {
  if (prevCodes.filter((code) => code === tag).length !== 1) {
    throw new Error(`${args.prev}: тег ${tag} должен быть ровно один, а есть: ${prevCodes.join(', ')}`);
  }
}
const baselines = [
  {title: `прошлого файла (${basename(args.prev)})`, path: args.prev, buffer: prevBuffer, direct: prev},
  ...compares.map(({label, path}) => {
    const buffer = readFileSync(path);
    return {title: label, path, buffer, direct: readDirect(buffer, path)};
  }),
];

const ripe = readRipe(args.ripe);
const ripeRu = ripe.byCountry.get('RU') ?? [];
const runet = readRunet(args.runet);
const extra = readExtra(args.extra, ripe);
const extraRipe = extra.ripeCountries.map((country) => ({country, ranges: ripe.byCountry.get(country)}));

if (total(ripeRu) < MIN_SOURCE_ADDRESSES) errors.push(`В RIPE у RU всего ${fmt(total(ripeRu))} адресов — источник битый?`);
if (total(runet.ranges) < MIN_SOURCE_ADDRESSES) errors.push(`У runetfreedom в RU всего ${fmt(total(runet.ranges))} адресов — источник битый?`);

const asnList = readAsnList(args.asn);
const asnCache = readAsnCache(args['asn-cache']);
const asnResults = asnList.map(({asn, note}) => {
  const cached = asnCache.get(asn);
  const fresh = readAsnFresh(args['asn-dir'], asn);
  const result = {asn, note};
  if (fresh.problem) {
    if (cached) {
      Object.assign(result, {source: 'cache', ranges: cached.ranges, holder: cached.holder, time: cached.time, why: fresh.problem});
      warnings.push(`AS${asn}: ${fresh.problem} — взяты префиксы из кэша (данные на ${cached.time}).`);
    } else {
      Object.assign(result, {source: 'none', ranges: [], holder: '', time: '?', why: fresh.problem});
      errors.push(`AS${asn}: ${fresh.problem}, а в кэше его нет — префиксов взять неоткуда.`);
    }
    return result;
  }
  Object.assign(result, {source: 'ripestat', ranges: fresh.ranges, holder: fresh.holder, time: fresh.time, announced: fresh.v4, skippedV6: fresh.v6});
  if (fresh.bad) warnings.push(`AS${asn}: ${fresh.bad} префиксов RIPEstat не разобрались или короче /8 — пропущены.`);
  if (fresh.bogon) warnings.push(`AS${asn}: ${fmt(fresh.bogon)} адресов из служебных сетей — выброшены.`);
  if (cached && cached.holder !== fresh.holder) {
    warnings.push(`AS${asn}: держатель сменился: был «${cached.holder}», стал «${fresh.holder}» — проверить, та ли это компания.`);
  }
  if (fresh.time !== '?' && Date.now() - Date.parse(`${fresh.time}Z`) > MAX_ASN_DATA_AGE_DAYS * 864e5) {
    warnings.push(`AS${asn}: данные RIPEstat на ${fresh.time} — старше ${MAX_ASN_DATA_AGE_DAYS} дней.`);
  }
  if (!total(fresh.ranges)) {
    if (cached && total(cached.ranges)) {
      Object.assign(result, {source: 'cache', ranges: cached.ranges, time: cached.time, why: 'RIPEstat вернул 0 IPv4-префиксов'});
      warnings.push(`AS${asn}: RIPEstat вернул 0 IPv4-префиксов — взяты префиксы из кэша (данные на ${cached.time}); `
        + 'если ASN больше не анонсируется, убрать его из direct-asn.txt.');
    } else {
      warnings.push(`AS${asn}: ни одного IPv4-префикса — убрать из direct-asn.txt?`);
    }
  } else if (cached && total(fresh.ranges) < total(cached.ranges) / 2) {
    warnings.push(`AS${asn}: адресов ${fmt(total(cached.ranges))} → ${fmt(total(fresh.ranges))}, меньше половины — посмотреть.`);
  }
  return result;
});
const asnFromCache = asnResults.filter((result) => result.source === 'cache');
if (!asnResults.some((result) => result.source === 'ripestat')) warnings.push('RIPEstat не дал данных ни по одному ASN — все сети компаний из кэша.');
const asnUnion = merge(asnResults.flatMap((result) => result.ranges));

const sourceParts = [
  {label: 'geoip:ru', ranges: runet.ranges},
  {label: 'ASN', ranges: asnUnion},
  ...extraRipe.map(({country, ranges}) => ({label: `ripe:${country}`, ranges})),
  {label: 'direct-extra CIDR', ranges: extra.cidrs},
];
const directRanges = merge(sourceParts.flatMap((part) => part.ranges));
const directCidrs = toCidrs(directRanges);

const directBody = Buffer.concat([
  prev.entry.fields[0].raw, // код тега как был
  ...directCidrs.map(([start, prefix]) => encodeCidr4(start, prefix)),
  ...prev.v6Fields.map((field) => field.raw),
  ...prev.otherFields.map((field) => field.raw),
]);
const output = Buffer.concat(prevEntries.map((entry) => (
  entry.code === REBUILT_TAG ? lengthDelimited(1, directBody) : entry.raw
)));

// ------------------------------------------------------------ self-check ----

const outEntries = readGeoIPList(output, 'новый файл');
if (outEntries.map((entry) => entry.code).join() !== prevCodes.join()) errors.push('Набор или порядок тегов изменился.');
for (const entry of outEntries) {
  const cidrCount = entry.fields.filter((field) => field.number === 2).length;
  if (cidrCount === 0) errors.push(`В теге ${entry.code} нет ни одного CIDR.`);
  if (entry.code !== REBUILT_TAG && !entry.raw.equals(prevEntries.find((item) => item.code === entry.code).raw)) {
    errors.push(`Тег ${entry.code} перенёсся не побайтно.`);
  }
}
{
  const check = outEntries.find((entry) => entry.code === REBUILT_TAG).fields
    .filter((field) => field.number === 2)
    .map((field) => readCidr(field, 'новый DIRECT'))
    .filter(({ip}) => ip.length === 4)
    .map(({ip, prefix}) => cidrRange(ip.readUInt32BE(0), prefix));
  const merged = merge(check);
  if (total(merged) !== total(check) || total(merged) !== total(directRanges)) errors.push('CIDR нового DIRECT пересекаются или не сходятся с источниками.');
}

const growth = output.length / prevBuffer.length - 1;
if (growth > maxGrowth) {
  errors.push(`Файл вырос на ${(growth * 100).toFixed(1)} % — больше допустимых ${(maxGrowth * 100).toFixed(0)} %.`);
}
const directShrink = 1 - total(directRanges) / total(prev.ranges);
if (directShrink > maxShrink) {
  const text = `DIRECT потерял ${(directShrink * 100).toFixed(1)} % адресов — больше допустимых ${(maxShrink * 100).toFixed(0)} %`;
  if (args['allow-shrink']) warnings.push(`${text}; предохранитель снят флагом --allow-shrink.`);
  else errors.push(`${text}. Если это разовая перестройка состава — флаг --allow-shrink.`);
} else if (directShrink > 0.02) {
  warnings.push(`DIRECT потерял ${(directShrink * 100).toFixed(1)} % адресов — посмотреть «убралось».`);
}
const extraAll = merge([...extraRipe.flatMap((part) => part.ranges), ...extra.cidrs]);
const geoAndAsn = merge([...runet.ranges, ...asnUnion]);
const extraCovered = intersect(extraAll, geoAndAsn);
if (total(extra.cidrs) && total(intersect(extra.cidrs, geoAndAsn)) === total(extra.cidrs)) {
  warnings.push('Все CIDR из direct-extra.txt уже есть в geoip:ru или в сетях компаний — добавки можно чистить.');
}

// ---------------------------------------------------------------- report ----

function geoBreakdown(ranges) {
  const counts = [];
  let covered = 0;
  for (const {code, ranges: geoRanges} of runet.geo) {
    const count = total(intersect(ranges, geoRanges));
    if (count) {
      counts.push([code, count]);
      covered += count;
    }
  }
  counts.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return {counts, unknown: Math.max(0, total(ranges) - covered)};
}

function geoText(ranges, limit = TOP_GEO) {
  const {counts, unknown} = geoBreakdown(ranges);
  const parts = counts.slice(0, limit).map(([code, count]) => `${code} ${fmt(count)}`);
  if (counts.length > limit) {
    parts.push(`ещё ${counts.length - limit} стран ${fmt(counts.slice(limit).reduce((sum, [, count]) => sum + count, 0))}`);
  }
  if (unknown) parts.push(`нет в геобазе ${fmt(unknown)}`);
  return parts.join(', ') || '—';
}

function geoAt(start) {
  return runet.geo.find(({ranges}) => contains(ranges, start))?.code;
}

function sourcesOf(range) {
  return sourceParts.filter((part) => total(intersect([range], part.ranges)) > 0).map((part) => {
    if (part.label !== 'ASN') return part.label;
    const asns = asnResults.filter((result) => total(intersect([range], result.ranges)) > 0).map((result) => `AS${result.asn}`);
    return `ASN ${asns.slice(0, 3).join(', ')}${asns.length > 3 ? ' …' : ''}`;
  }).join(' + ');
}

function whereNow(range) {
  const country = ripeCountryOf(ripe, range[0]);
  const geo = geoAt(range[0]);
  return `${country ? `в RIPE ${country}` : 'в RIPE нет'}, по геобазе ${geo ?? '—'}`;
}

const lines = [];
const out = (line = '') => lines.push(line);
const sha256 = createHash('sha256').update(output).digest('hex');
const bySize = (a, b) => (b[1] - b[0]) - (a[1] - a[0]) || a[0] - b[0];

out(`Сборка ${basename(args.out)} — ${new Date().toISOString().replace(/\.\d+Z$/u, 'Z')}`);
out();
out('Источники');
for (const line of readSources(args.sources)) out(`  ${line}`);
if (!args.sources) out(`  ripe_header=${cleanText(ripe.header)}`);
out(`  сети компаний: ${asnResults.length} ASN из ${basename(args.asn)}; из RIPEstat ${asnResults.filter((result) => result.source === 'ripestat').length},`
  + ` из кэша ${asnFromCache.length}${asnFromCache.length ? ` (${asnFromCache.slice(0, 20).map((result) => `AS${result.asn}`).join(', ')}`
    + `${asnFromCache.length > 20 ? ' …' : ''})` : ''}`);
for (const baseline of baselines) {
  out(`  ${baseline === baselines[0] ? 'прошлый файл' : `для сравнения «${baseline.title}»`}: ${basename(baseline.path)},`
    + ` sha256 ${createHash('sha256').update(baseline.buffer).digest('hex')}`);
}
out();
out('Теги (CIDR / IPv4-адресов; было в прошлом файле → стало)');
for (const entry of outEntries) {
  const count = (fields) => {
    const cidrs = fields.filter((field) => field.number === 2).map((field) => readCidr(field, entry.code));
    const v4 = cidrs.filter(({ip}) => ip.length === 4);
    return {cidrs: cidrs.length, v6: cidrs.length - v4.length, addrs: total(merge(v4.map(({ip, prefix}) => cidrRange(ip.readUInt32BE(0), prefix))))};
  };
  const before = count(prevEntries.find((item) => item.code === entry.code).fields);
  const after = count(entry.fields);
  const v6 = after.v6 ? `, из них IPv6: ${fmt(after.v6)}` : '';
  out(`  ${entry.code.padEnd(10)} CIDR ${fmt(before.cidrs)} → ${fmt(after.cidrs)} (${signed(after.cidrs - before.cidrs)})${v6};`
    + ` адресов ${fmt(before.addrs)} → ${fmt(after.addrs)} (${signed(after.addrs - before.addrs)})`
    + (entry.code === REBUILT_TAG ? '' : ' — перенесён побайтно'));
}
out();
const asnExtra = subtract(asnUnion, runet.ranges);
out(`Состав ${REBUILT_TAG} (IPv4)`);
out(`  geoip:ru runetfreedom: ${fmt(total(runet.ranges))} адресов (${fmt(runet.cidrs)} CIDR; IPv6 пропущено: ${fmt(runet.ipv6)})`);
out(`  сети компаний (ASN):   ${fmt(total(asnUnion))} адресов из ${asnResults.length} ASN; сверх geoip:ru — ${fmt(total(asnExtra))}`);
for (const {country, ranges} of extraRipe) {
  out(`  ripe:${country} (добавка):    ${fmt(total(ranges))} адресов; сверх geoip:ru и ASN — ${fmt(total(subtract(ranges, geoAndAsn)))}`);
}
out(`  CIDR из добавок:       ${fmt(total(extra.cidrs))} адресов (${fmt(extra.cidrLines)} строк)`);
out(`  из добавок уже есть в geoip:ru ∪ ASN: ${fmt(total(extraCovered))} адресов`);
out(`  итого:                 ${fmt(total(directRanges))} адресов, ${fmt(directRanges.length)} отрезков, ${fmt(directCidrs.length)} CIDR`);
out(`  IPv6 из прошлого файла перенесено без изменений: ${fmt(prev.v6Fields.length)} CIDR`);
if (prev.otherFields.length) out(`  прочих полей записи перенесено: ${prev.otherFields.length}`);
out(`  RIPE RU как источник DIRECT не берётся — только ripe:XX из добавок и этот отчёт.`);
out();

const ripeRuNotGeo = subtract(ripeRu, runet.ranges);
const notGeoByAsn = intersect(ripeRuNotGeo, asnUnion);
const notGeoByExtra = intersect(subtract(ripeRuNotGeo, asnUnion), extraAll);
const notGeoGone = subtract(ripeRuNotGeo, directRanges);
out('RIPE RU, но не в России по геобазе (записаны на Россию, стоят за границей или не размечены)');
out(`  RIPE RU: ${fmt(total(ripeRu))} адресов; из них в geoip:ru ${fmt(total(intersect(ripeRu, runet.ranges)))},`
  + ` вне geoip:ru ${fmt(total(ripeRuNotGeo))}`);
out(`  из ${fmt(total(ripeRuNotGeo))} вне geoip:ru: вернули сети компаний (ASN) ${fmt(total(notGeoByAsn))},`
  + ` оставили добавки ${fmt(total(notGeoByExtra))}, ушли из ${REBUILT_TAG} ${fmt(total(notGeoGone))}`);
out(`  ушедшее по геобазе: ${geoText(notGeoGone)}`);
out(`  вернувшееся через ASN по геобазе: ${geoText(notGeoByAsn)}`);
out(`  крупнейшие ушедшие (до ${TOP_CHANGES}):`);
for (const range of notGeoGone.slice().sort(bySize).slice(0, TOP_CHANGES)) out(`    − ${describeRange(range)} — ${whereNow(range)}`);
if (!notGeoGone.length) out('    нет');
out();

out(`Сети компаний (ASN): вклад каждого (сверх geoip:ru — адреса ASN, которых нет в geoip:ru runetfreedom)`);
for (const result of asnResults) {
  const extraPart = subtract(result.ranges, runet.ranges);
  const source = result.source === 'ripestat'
    ? `RIPEstat на ${result.time}, анонсов IPv4 ${fmt(result.announced)}${result.skippedV6 ? ` (IPv6 пропущено: ${fmt(result.skippedV6)})` : ''}`
    : result.source === 'cache' ? `КЭШ (${result.why}), данные на ${result.time}` : `НЕТ ДАННЫХ (${result.why})`;
  out(`  AS${String(result.asn).padEnd(8)} ${result.note || '—'}`);
  out(`             держатель: ${result.holder || '—'}; ${source}`);
  out(`             CIDR ${fmt(toCidrs(result.ranges).length)}, адресов ${fmt(total(result.ranges))}, сверх geoip:ru ${fmt(total(extraPart))}`
    + (total(extraPart) ? ` (${geoText(extraPart, 6)})` : ''));
}
out(`  итого: ${fmt(total(asnUnion))} адресов, сверх geoip:ru ${fmt(total(asnExtra))} (${geoText(asnExtra)})`);
out();

for (const baseline of baselines) {
  const before = baseline.direct;
  const added = subtract(directRanges, before.ranges);
  const removed = subtract(before.ranges, directRanges);
  out(`Изменения ${REBUILT_TAG} относительно ${baseline.title}`);
  out(`  IPv4: CIDR ${fmt(before.v4Cidrs)} → ${fmt(directCidrs.length)}, адресов ${fmt(total(before.ranges))} → ${fmt(total(directRanges))}`
    + ` (${signed(total(directRanges) - total(before.ranges))}); IPv6 CIDR ${fmt(before.v6Fields.length)} → ${fmt(prev.v6Fields.length)}`);
  out(`  добавилось: ${fmt(total(added))} адресов, ${fmt(added.length)} отрезков`);
  out(`  убралось:   ${fmt(total(removed))} адресов, ${fmt(removed.length)} отрезков;`
    + ` из них «RIPE RU, но не в geoip:ru» ${fmt(total(intersect(removed, ripeRuNotGeo)))}`);
  if (removed.length) out(`  убранное по геобазе: ${geoText(removed)}`);
  out(`  крупнейшие добавленные (до ${TOP_CHANGES}):`);
  for (const range of added.slice().sort(bySize).slice(0, TOP_CHANGES)) out(`    + ${describeRange(range)} — ${sourcesOf(range)}`);
  if (!added.length) out('    нет');
  out(`  крупнейшие убранные (до ${TOP_CHANGES}):`);
  for (const range of removed.slice().sort(bySize).slice(0, TOP_CHANGES)) out(`    − ${describeRange(range)} — ${whereNow(range)}`);
  if (!removed.length) out('    нет');
  out();
}

out('Файл');
out(`  размер: ${fmt(prevBuffer.length)} → ${fmt(output.length)} байт (${growth >= 0 ? '+' : '−'}${Math.abs(growth * 100).toFixed(1)} %; предел +${(maxGrowth * 100).toFixed(0)} %)`);
out(`  sha256: ${sha256}`);
out();
out('Проверки сборки');
out(`  теги на месте и в прежнем порядке: ${outEntries.map((entry) => entry.code).join(', ')}`);
out(`  ${outEntries.filter((entry) => entry.code !== REBUILT_TAG).map((entry) => entry.code).join(', ')} — побайтно как в прошлом файле`);
out(`  предохранитель потери ${REBUILT_TAG} (больше ${(maxShrink * 100).toFixed(0)} %): ${args['allow-shrink'] ? 'СНЯТ флагом --allow-shrink' : 'включён'};`
  + ` потеря ${(Math.max(0, directShrink) * 100).toFixed(1)} %`);
for (const warning of warnings) out(`  ВНИМАНИЕ: ${warning}`);
for (const error of errors) out(`  ОШИБКА: ${error}`);
out(errors.length ? '  итог: сборка остановлена, файл не записан' : '  итог: ok');

const report = `${lines.join('\n')}\n`;
writeFileSync(args.report, report);
process.stdout.write(report);
if (errors.length) process.exit(1);

writeFileSync(args.out, output);
writeFileSync(`${args.out}.sha256`, `${sha256}  ${basename(args.out)}\n`);
writeFileSync(args['asn-cache'], formatAsnCache(asnResults));
