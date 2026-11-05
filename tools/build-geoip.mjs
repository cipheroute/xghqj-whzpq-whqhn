// Сборка geoip-mini.dat: тег DIRECT пересобирается из источников, остальные теги
// переносятся из прошлого файла побайтно.
//
//   DIRECT = IPv4-сети RU по RIPE NCC (delegated-ripencc-extended, allocated/assigned)
//          ∪ IPv4 из geoip:ru runetfreedom/russia-v2ray-rules-dat
//          ∪ ручные добавки из direct-extra.txt
//          + IPv6-часть DIRECT прошлого файла без изменений (новых IPv6 не добавляем).
//
// Источники качает tools/fetch-geoip-sources.sh; этот скрипт в сеть не ходит.
// Без зависимостей, protobuf разбирается и пишется вручную, как в остальных tools/*.mjs.
//
// node tools/build-geoip.mjs --prev geoip-mini.dat --ripe SRC/ripe.txt \
//   --runet SRC/runet-geoip.dat --extra direct-extra.txt [--sources SRC/sources.txt] \
//   --out geoip-mini.dat --report build-report.txt

import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {basename} from 'node:path';
import {parseArgs} from 'node:util';

const REQUIRED_TAGS = ['DIRECT', 'PRIVATE', 'WHITELIST'];
const REBUILT_TAG = 'DIRECT';
// Защита от битых источников: на 05-11-2026 у RU ~45 млн IPv4 и в RIPE, и у runetfreedom.
const MIN_SOURCE_ADDRESSES = 30_000_000;
const TOP_CHANGES = 20;

const {values: args} = parseArgs({
  options: {
    prev: {type: 'string'},
    ripe: {type: 'string'},
    runet: {type: 'string'},
    extra: {type: 'string'},
    sources: {type: 'string'},
    out: {type: 'string'},
    report: {type: 'string'},
    'max-growth': {type: 'string', default: '0.20'},
    'max-shrink': {type: 'string', default: '0.10'},
  },
});

for (const name of ['prev', 'ripe', 'runet', 'extra', 'out', 'report']) {
  if (!args[name]) {
    throw new Error(
      'Запуск: node tools/build-geoip.mjs --prev geoip-mini.dat --ripe ripe.txt --runet runet-geoip.dat '
      + '--extra direct-extra.txt [--sources sources.txt] --out geoip-mini.dat --report build-report.txt',
    );
  }
}
const maxGrowth = Number(args['max-growth']);
const maxShrink = Number(args['max-shrink']);

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

function readRunetRu(path) {
  const entries = readGeoIPList(readFileSync(path), path);
  const ru = entries.filter((entry) => entry.code.toUpperCase() === 'RU');
  if (ru.length !== 1) throw new Error(`${path}: тег RU найден ${ru.length} раз.`);
  const ranges = [];
  let ipv6 = 0;
  let cidrs = 0;
  for (const field of ru[0].fields) {
    if (field.number !== 2) continue;
    const {ip, prefix} = readCidr(field, `${path}:RU`);
    if (ip.length === 16) {
      ipv6 += 1;
      continue;
    }
    cidrs += 1;
    const size = 2 ** (32 - prefix);
    const start = Math.floor(ip.readUInt32BE(0) / size) * size; // на случай лишних бит хоста
    ranges.push([start, start + size]);
  }
  return {ranges: merge(ranges), cidrs, ipv6, tags: entries.length};
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
  return readFileSync(path, 'utf8').split(/\r?\n/u).filter((line) => /^[a-z0-9_]+=/u.test(line));
}

// ---------------------------------------------------------------- report ----

function fmt(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/gu, ' ');
}

function signed(value) {
  return value > 0 ? `+${fmt(value)}` : value < 0 ? `−${fmt(-value)}` : '0';
}

function percent(part, whole) {
  return whole ? `${((part / whole) * 100).toFixed(2)} %` : '—';
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

// ------------------------------------------------------------------ build ---

const prevBuffer = readFileSync(args.prev);
const prevEntries = readGeoIPList(prevBuffer, args.prev);
const prevCodes = prevEntries.map((entry) => entry.code);
for (const tag of REQUIRED_TAGS) {
  if (prevCodes.filter((code) => code === tag).length !== 1) {
    throw new Error(`${args.prev}: тег ${tag} должен быть ровно один, а есть: ${prevCodes.join(', ')}`);
  }
}

const prevDirect = prevEntries.find((entry) => entry.code === REBUILT_TAG);
const prevDirectV4 = [];
const prevDirectV6Fields = [];
const prevDirectOtherFields = [];
for (const field of prevDirect.fields.slice(1)) {
  if (field.number !== 2) {
    prevDirectOtherFields.push(field);
    continue;
  }
  const {ip, prefix} = readCidr(field, `${args.prev}:${REBUILT_TAG}`);
  if (ip.length === 16) prevDirectV6Fields.push(field);
  else prevDirectV4.push(cidrRange(ip.readUInt32BE(0), prefix));
}
const prevDirectRanges = merge(prevDirectV4);

const ripe = readRipe(args.ripe);
const ripeRu = ripe.byCountry.get('RU') ?? [];
const runet = readRunetRu(args.runet);
const extra = readExtra(args.extra, ripe);
const extraRipe = extra.ripeCountries.map((country) => ({country, ranges: ripe.byCountry.get(country)}));

const errors = [];
const warnings = [];
if (total(ripeRu) < MIN_SOURCE_ADDRESSES) errors.push(`В RIPE у RU всего ${fmt(total(ripeRu))} адресов — источник битый?`);
if (total(runet.ranges) < MIN_SOURCE_ADDRESSES) errors.push(`У runetfreedom в RU всего ${fmt(total(runet.ranges))} адресов — источник битый?`);

const sourceParts = [
  {label: 'RIPE RU', ranges: ripeRu},
  {label: 'runetfreedom RU', ranges: runet.ranges},
  ...extraRipe.map(({country, ranges}) => ({label: `ripe:${country}`, ranges})),
  {label: 'direct-extra CIDR', ranges: extra.cidrs},
];
const directRanges = merge(sourceParts.flatMap((part) => part.ranges));
const directCidrs = toCidrs(directRanges);

const directBody = Buffer.concat([
  prevDirect.fields[0].raw, // код тега как был
  ...directCidrs.map(([start, prefix]) => encodeCidr4(start, prefix)),
  ...prevDirectV6Fields.map((field) => field.raw),
  ...prevDirectOtherFields.map((field) => field.raw),
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
  if (entry.code !== REBUILT_TAG && !entry.raw.equals(prevEntries.find((prev) => prev.code === entry.code).raw)) {
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
const directShrink = 1 - total(directRanges) / total(prevDirectRanges);
if (directShrink > maxShrink) {
  errors.push(`DIRECT потерял ${(directShrink * 100).toFixed(1)} % адресов — больше допустимых ${(maxShrink * 100).toFixed(0)} %.`);
} else if (directShrink > 0.02) {
  warnings.push(`DIRECT потерял ${(directShrink * 100).toFixed(1)} % адресов — посмотреть «убралось».`);
}
const extraCovered = intersect(merge([...extraRipe.flatMap((part) => part.ranges), ...extra.cidrs]), merge([...ripeRu, ...runet.ranges]));
if (total(extra.cidrs) && total(intersect(extra.cidrs, merge([...ripeRu, ...runet.ranges]))) === total(extra.cidrs)) {
  warnings.push('Все CIDR из direct-extra.txt уже есть в источниках — добавки можно чистить.');
}

// ---------------------------------------------------------------- report ----

const added = subtract(directRanges, prevDirectRanges);
const removed = subtract(prevDirectRanges, directRanges);
const bySize = (a, b) => (b[1] - b[0]) - (a[1] - a[0]) || a[0] - b[0];

function sourcesOf(range) {
  return sourceParts.filter((part) => total(intersect([range], part.ranges)) > 0).map((part) => part.label).join(' + ');
}

const lines = [];
const out = (line = '') => lines.push(line);
const sha256 = createHash('sha256').update(output).digest('hex');

out(`Сборка ${basename(args.out)} — ${new Date().toISOString().replace(/\.\d+Z$/u, 'Z')}`);
out();
out('Источники');
for (const line of readSources(args.sources)) out(`  ${line}`);
if (!args.sources) out(`  ripe_header=${ripe.header}`);
out(`  прошлый файл: ${basename(args.prev)}, sha256 ${createHash('sha256').update(prevBuffer).digest('hex')}`);
out();
out('Теги (CIDR / IPv4-адресов; было → стало)');
for (const entry of outEntries) {
  const count = (fields) => {
    const cidrs = fields.filter((field) => field.number === 2).map((field) => readCidr(field, entry.code));
    const v4 = cidrs.filter(({ip}) => ip.length === 4);
    return {cidrs: cidrs.length, v6: cidrs.length - v4.length, addrs: total(merge(v4.map(({ip, prefix}) => cidrRange(ip.readUInt32BE(0), prefix))))};
  };
  const before = count(prevEntries.find((prev) => prev.code === entry.code).fields);
  const after = count(entry.fields);
  const v6 = after.v6 ? `, из них IPv6: ${fmt(after.v6)}` : '';
  out(`  ${entry.code.padEnd(10)} CIDR ${fmt(before.cidrs)} → ${fmt(after.cidrs)} (${signed(after.cidrs - before.cidrs)})${v6};`
    + ` адресов ${fmt(before.addrs)} → ${fmt(after.addrs)} (${signed(after.addrs - before.addrs)})`
    + (entry.code === REBUILT_TAG ? '' : ' — перенесён побайтно'));
}
out();
out(`Состав ${REBUILT_TAG} (IPv4)`);
out(`  RIPE RU:            ${fmt(total(ripeRu))} адресов (${fmt(ripeRu.length)} слитых отрезков)`);
out(`  runetfreedom RU:    ${fmt(total(runet.ranges))} адресов (${fmt(runet.cidrs)} CIDR; IPv6 пропущено: ${fmt(runet.ipv6)})`);
for (const {country, ranges} of extraRipe) out(`  ripe:${country} (добавка): ${fmt(total(ranges))} адресов`);
out(`  CIDR из добавок:    ${fmt(total(extra.cidrs))} адресов (${fmt(extra.cidrLines)} строк)`);
out(`  из добавок уже есть в RIPE RU ∪ runetfreedom: ${fmt(total(extraCovered))} адресов`);
out(`  итого:              ${fmt(total(directRanges))} адресов, ${fmt(directRanges.length)} отрезков, ${fmt(directCidrs.length)} CIDR`);
out(`  IPv6 из прошлого файла перенесено без изменений: ${fmt(prevDirectV6Fields.length)} CIDR`);
if (prevDirectOtherFields.length) out(`  прочих полей записи перенесено: ${prevDirectOtherFields.length}`);
out();
out(`Изменения ${REBUILT_TAG} относительно прошлого файла`);
out(`  добавилось: ${fmt(total(added))} адресов, ${fmt(added.length)} отрезков`);
out(`  убралось:   ${fmt(total(removed))} адресов, ${fmt(removed.length)} отрезков`);
out(`  крупнейшие добавленные (до ${TOP_CHANGES}):`);
for (const range of added.slice().sort(bySize).slice(0, TOP_CHANGES)) out(`    + ${describeRange(range)} — ${sourcesOf(range)}`);
if (!added.length) out('    нет');
out(`  крупнейшие убранные (до ${TOP_CHANGES}):`);
for (const range of removed.slice().sort(bySize).slice(0, TOP_CHANGES)) {
  const country = ripeCountryOf(ripe, range[0]);
  out(`    − ${describeRange(range)} — ${country ? `в RIPE сейчас ${country}` : 'в RIPE нет'}`);
}
if (!removed.length) out('    нет');
out();
out('Файл');
out(`  размер: ${fmt(prevBuffer.length)} → ${fmt(output.length)} байт (${growth >= 0 ? '+' : '−'}${Math.abs(growth * 100).toFixed(1)} %; предел +${(maxGrowth * 100).toFixed(0)} %)`);
out(`  sha256: ${sha256}`);
out();
out('Проверки сборки');
out(`  теги на месте и в прежнем порядке: ${outEntries.map((entry) => entry.code).join(', ')}`);
out(`  ${outEntries.filter((entry) => entry.code !== REBUILT_TAG).map((entry) => entry.code).join(', ')} — побайтно как в прошлом файле`);
for (const warning of warnings) out(`  ВНИМАНИЕ: ${warning}`);
for (const error of errors) out(`  ОШИБКА: ${error}`);
out(errors.length ? '  итог: сборка остановлена, файл не записан' : '  итог: ok');

const report = `${lines.join('\n')}\n`;
writeFileSync(args.report, report);
process.stdout.write(report);
if (errors.length) process.exit(1);

writeFileSync(args.out, output);
writeFileSync(`${args.out}.sha256`, `${sha256}  ${basename(args.out)}\n`);
