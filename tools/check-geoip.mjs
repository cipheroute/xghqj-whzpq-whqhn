// Проверка geoip-mini.dat перед выкладкой.
//
// 1. Свой разбор файла (отдельный от сборщика): теги DIRECT, PRIVATE, WHITELIST на месте,
//    код — первым полем записи (ядро ищет тег именно так), CIDR больше нуля, адреса по 4/16 байт,
//    без лишних бит хоста; с --prev — PRIVATE и WHITELIST побайтно как в прошлом файле.
// 2. С --xray — настоящее ядро:
//    - `xray run -test` с правилами geoip:private, geoip:whitelist, geoip:direct
//      (XRAY_LOCATION_ASSET — временная папка, где файл лежит как geoip.dat);
//    - тот же конфиг с несуществующим тегом обязан упасть — значит, файл действительно читается;
//    - ядро запускается с SOCKS на 127.0.0.1 и выходами-blackhole (наружу ничего не уходит);
//      через него открываются соединения на выборку адресов, а по журналу доступа
//      сверяется, в какой выход ядро отправило каждый адрес.
//
// node tools/check-geoip.mjs --dat geoip-mini.dat [--prev old.dat] [--xray path/to/xray] [--append build-report.txt]

import {appendFileSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {spawn, spawnSync} from 'node:child_process';
import {createServer, connect} from 'node:net';
import {tmpdir} from 'node:os';
import {basename, join, resolve} from 'node:path';
import {parseArgs} from 'node:util';

const TAGS = ['PRIVATE', 'WHITELIST', 'DIRECT']; // порядок правил в тестовом конфиге
const RANDOM_PROBES = 300;
const SAMPLES_PER_TAG = 40;

const {values: args} = parseArgs({
  options: {
    dat: {type: 'string'},
    prev: {type: 'string'},
    xray: {type: 'string'},
    append: {type: 'string'},
  },
});
if (!args.dat) throw new Error('Запуск: node tools/check-geoip.mjs --dat geoip-mini.dat [--prev old.dat] [--xray xray] [--append report.txt]');

const lines = [];
const failures = [];
const log = (line) => {
  lines.push(line);
  console.log(line);
};
const fail = (line) => {
  failures.push(line);
  log(`  ОШИБКА: ${line}`);
};

// ------------------------------------------------------- свой разбор файла ---

function varint(buffer, offset) {
  let value = 0;
  for (let shift = 0, index = offset; index < buffer.length; index += 1, shift += 7) {
    if (shift > 49) break;
    value += (buffer[index] & 0x7f) * (2 ** shift);
    if (buffer[index] < 0x80) return [value, index + 1];
  }
  throw new Error('битый varint');
}

function messages(buffer) {
  const out = [];
  let offset = 0;
  while (offset < buffer.length) {
    const start = offset;
    let key;
    [key, offset] = varint(buffer, offset);
    const number = Math.floor(key / 8);
    const type = key % 8;
    let value;
    if (type === 0) {
      [value, offset] = varint(buffer, offset);
    } else if (type === 2) {
      let length;
      [length, offset] = varint(buffer, offset);
      if (offset + length > buffer.length) throw new Error('поле за концом данных');
      value = buffer.subarray(offset, offset + length);
      offset += length;
    } else {
      throw new Error(`wire type ${type}`);
    }
    out.push({number, type, value, raw: buffer.subarray(start, offset)});
  }
  return out;
}

function parseGeoIP(path) {
  const entries = new Map();
  const order = [];
  for (const top of messages(readFileSync(path))) {
    if (top.number !== 1 || top.type !== 2) throw new Error(`${path}: поле верхнего уровня ${top.number}`);
    const fields = messages(top.value);
    if (fields[0]?.number !== 1 || fields[0].type !== 2) throw new Error(`${path}: код тега не первым полем`);
    const code = fields[0].value.toString('utf8');
    if (entries.has(code)) throw new Error(`${path}: тег ${code} повторяется`);
    const v4 = [];
    let v6 = 0;
    let bad = 0;
    for (const field of fields.slice(1)) {
      if (field.number !== 2) continue;
      const parts = messages(field.value);
      const ip = parts.find((part) => part.number === 1 && part.type === 2)?.value;
      const prefix = parts.find((part) => part.number === 2 && part.type === 0)?.value ?? 0;
      if (!ip || (ip.length !== 4 && ip.length !== 16) || prefix > ip.length * 8) {
        bad += 1;
      } else if (ip.length === 16) {
        v6 += 1;
        const hostBits = 128 - prefix;
        for (let bit = 0; bit < hostBits; bit += 1) {
          if (ip[15 - Math.floor(bit / 8)] & (1 << (bit % 8))) {
            bad += 1;
            break;
          }
        }
      } else {
        const start = ip.readUInt32BE(0);
        const size = 2 ** (32 - prefix);
        if (start % size !== 0) bad += 1;
        v4.push([start, start + size]);
      }
    }
    v4.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const [start, end] of v4) {
      const last = merged[merged.length - 1];
      if (last && start <= last[1]) last[1] = Math.max(last[1], end);
      else merged.push([start, end]);
    }
    entries.set(code, {raw: top.raw, v4: merged, v4Count: v4.length, v6, bad});
    order.push(code);
  }
  return {entries, order};
}

const ip4 = (value) => [24, 16, 8, 0].map((shift) => Math.floor(value / (2 ** shift)) % 256).join('.');
const ip4Number = (text) => text.split('.').reduce((sum, part) => sum * 256 + Number(part), 0);

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

log('Проверка файла своим разбором');
let dat;
try {
  dat = parseGeoIP(args.dat);
} catch (error) {
  fail(`файл не разбирается: ${error.message}`);
  if (args.append) appendFileSync(args.append, `\n${lines.join('\n')}\n`);
  process.exit(1);
}
log(`  теги: ${dat.order.join(', ')}`);
for (const tag of TAGS) {
  const entry = dat.entries.get(tag);
  if (!entry) {
    fail(`нет тега ${tag}`);
    continue;
  }
  const total = entry.v4.reduce((sum, [start, end]) => sum + end - start, 0);
  log(`  ${tag}: IPv4 CIDR ${entry.v4Count}, адресов ${total}, IPv6 CIDR ${entry.v6}`);
  if (entry.v4Count + entry.v6 === 0) fail(`в теге ${tag} нет CIDR`);
  if (entry.bad) fail(`в теге ${tag} битых CIDR: ${entry.bad}`);
}
// здравый смысл: Яндекс-DNS — в DIRECT, 10/8 — в PRIVATE, Google DNS — не в DIRECT
for (const [address, tag, inside] of [['77.88.8.8', 'DIRECT', true], ['10.1.2.3', 'PRIVATE', true], ['8.8.8.8', 'DIRECT', false]]) {
  const entry = dat.entries.get(tag);
  if (entry && contains(entry.v4, ip4Number(address)) !== inside) fail(`${address} ${inside ? 'не' : ''} в ${tag}`);
}
if (args.prev) {
  const prev = parseGeoIP(args.prev);
  if (prev.order.join() !== dat.order.join()) fail(`теги не как в прошлом файле: было ${prev.order.join(', ')}`);
  for (const tag of dat.order) {
    if (tag === 'DIRECT') continue;
    if (prev.entries.get(tag)?.raw.equals(dat.entries.get(tag).raw)) log(`  ${tag} побайтно как в прошлом файле`);
    else fail(`${tag} отличается от прошлого файла`);
  }
}

// ------------------------------------------------------------ ядро xray ---

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const {port} = server.address();
      server.close(() => resolvePort(port));
    });
  });
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

// SOCKS5 CONNECT на адрес:80. Ответ ядра не важен — важна строка в журнале доступа.
function socksProbe(port, address) {
  return new Promise((done) => {
    const socket = connect({host: '127.0.0.1', port});
    const finish = () => {
      socket.destroy();
      done();
    };
    socket.setTimeout(5000, finish);
    socket.once('error', finish);
    socket.once('close', finish);
    let stage = 0;
    socket.on('connect', () => socket.write(Buffer.from([0x05, 0x01, 0x00])));
    socket.on('data', (data) => {
      if (stage === 0 && data[0] === 0x05) {
        stage = 1;
        const request = Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]);
        request.writeUInt32BE(ip4Number(address), 4);
        socket.write(request);
      } else if (stage === 1) {
        finish();
      }
    });
  });
}

function expectedOutbound(value) {
  for (const tag of TAGS) {
    if (contains(dat.entries.get(tag).v4, value)) return `t-${tag.toLowerCase()}`;
  }
  return 'miss';
}

function probeAddresses() {
  // детерминированный ГПСЧ, чтобы прогоны повторялись
  let seed = 0x9e3779b9;
  const random = () => {
    seed = (Math.imul(seed ^ (seed >>> 15), 0x2c1b3c6d) + 0x6d2b79f5) >>> 0;
    return seed / 2 ** 32;
  };
  const set = new Set(['77.88.8.8', '8.8.8.8', '1.1.1.1', '10.1.2.3', '192.168.1.1', '17.249.0.1']);
  for (const tag of TAGS) {
    const ranges = dat.entries.get(tag).v4;
    for (let index = 0; index < Math.min(SAMPLES_PER_TAG, ranges.length); index += 1) {
      const [start, end] = ranges[Math.floor(random() * ranges.length)];
      set.add(ip4(start)); // первый адрес отрезка
      set.add(ip4(end - 1)); // последний
      if (end < 2 ** 32) set.add(ip4(end)); // первый за отрезком
      if (start > 0) set.add(ip4(start - 1)); // последний перед отрезком
    }
  }
  for (let index = 0; index < RANDOM_PROBES; index += 1) set.add(ip4(Math.floor(random() * 2 ** 32)));
  // 0.0.0.0/8 и 224.0.0.0/3 SOCKS-клиенты и ядро обрабатывают по-особому — не проверяем
  return [...set].filter((address) => {
    const first = Number(address.split('.')[0]);
    return first !== 0 && first < 224;
  });
}

async function checkXray(xrayPath) {
  log('');
  log(`Проверка ядром (${basename(xrayPath)})`); // без полного пути: отчёт уходит в публичный репозиторий
  const version = spawnSync(xrayPath, ['version'], {encoding: 'utf8'});
  log(`  ${(version.stdout || '').split('\n')[0] || 'версия не прочиталась'}`);

  const dir = mkdtempSync(join(tmpdir(), 'geoip-check-'));
  try {
    copyFileSync(args.dat, join(dir, 'geoip.dat'));
    const port = await freePort();
    const accessLog = join(dir, 'access.log');
    const config = (extraRules = []) => ({
      log: {loglevel: 'warning', access: accessLog},
      inbounds: [{tag: 'in', listen: '127.0.0.1', port, protocol: 'socks', settings: {auth: 'noauth', udp: false}}],
      outbounds: ['miss', ...TAGS.map((tag) => `t-${tag.toLowerCase()}`)].map((tag) => ({tag, protocol: 'blackhole'})),
      routing: {
        domainStrategy: 'AsIs',
        rules: [
          ...TAGS.map((tag) => ({type: 'field', ip: [`geoip:${tag.toLowerCase()}`], outboundTag: `t-${tag.toLowerCase()}`})),
          ...extraRules,
        ],
      },
    });
    const env = {...process.env, XRAY_LOCATION_ASSET: dir};
    const goodConfig = join(dir, 'config.json');
    const badConfig = join(dir, 'config-bad.json');
    writeFileSync(goodConfig, JSON.stringify(config(), null, 2));
    writeFileSync(badConfig, JSON.stringify(config([{type: 'field', ip: ['geoip:no-such-tag-for-test'], outboundTag: 'miss'}]), null, 2));

    const test = spawnSync(xrayPath, ['run', '-test', '-c', goodConfig], {env, encoding: 'utf8'});
    if (test.status === 0 && /Configuration OK/u.test(test.stdout)) {
      log('  xray run -test (geoip:private, geoip:whitelist, geoip:direct): Configuration OK');
    } else {
      fail(`xray run -test не прошёл (код ${test.status}): ${(test.stdout + test.stderr).trim().split('\n').slice(-1)[0]}`);
      return;
    }

    const negative = spawnSync(xrayPath, ['run', '-test', '-c', badConfig], {env, encoding: 'utf8'});
    if (negative.status !== 0) log('  несуществующий тег ядро отвергает — файл действительно читается');
    else fail('конфиг с несуществующим тегом прошёл -test — проверка ничего не доказывает');

    const server = spawn(xrayPath, ['run', '-c', goodConfig], {env, stdio: ['ignore', 'pipe', 'pipe']});
    const killServer = () => server.kill('SIGKILL');
    process.once('exit', killServer); // ядро не должно пережить проверку, даже если она упала
    let serverOutput = '';
    server.stdout.on('data', (data) => { serverOutput += data; });
    server.stderr.on('data', (data) => { serverOutput += data; });
    try {
      let up = false;
      for (let attempt = 0; attempt < 100 && !up; attempt += 1) {
        up = await new Promise((done) => {
          const socket = connect({host: '127.0.0.1', port}, () => {
            socket.destroy();
            done(true);
          });
          socket.once('error', () => done(false));
        });
        if (!up) await sleep(100);
      }
      if (!up) {
        fail(`ядро не открыло SOCKS: ${serverOutput.trim().split('\n').slice(-3).join(' | ')}`);
        return;
      }
      const addresses = probeAddresses();
      for (let index = 0; index < addresses.length; index += 16) {
        await Promise.all(addresses.slice(index, index + 16).map((address) => socksProbe(port, address)));
      }
      await sleep(1500);
      const routed = new Map();
      for (const line of readFileSync(accessLog, 'utf8').split('\n')) {
        const match = /accepted tcp:(\d+\.\d+\.\d+\.\d+):80 \[in (?:->|>>) ([\w-]+)\]/u.exec(line);
        if (match) routed.set(match[1], match[2]);
      }
      const counts = {};
      let mismatches = 0;
      for (const address of addresses) {
        const expected = expectedOutbound(ip4Number(address));
        const actual = routed.get(address);
        counts[expected] = (counts[expected] ?? 0) + 1;
        if (actual !== expected) {
          mismatches += 1;
          if (mismatches <= 10) fail(`${address}: ждали ${expected}, ядро — ${actual ?? 'нет в журнале'}`);
        }
      }
      log(`  маршрутизация ядром: ${addresses.length} адресов, совпало ${addresses.length - mismatches}`
        + ` (${Object.entries(counts).map(([tag, count]) => `${tag} ${count}`).join(', ')})`);
      if (mismatches > 10) fail(`и ещё ${mismatches - 10} расхождений`);
    } finally {
      server.kill('SIGTERM');
      process.off('exit', killServer);
    }
  } finally {
    rmSync(dir, {recursive: true, force: true});
  }
}

if (args.xray) {
  if (TAGS.every((tag) => dat.entries.has(tag))) await checkXray(resolve(args.xray));
  else fail('проверка ядром пропущена: не хватает тегов');
}

log(failures.length ? `  итог проверки: ошибок ${failures.length}` : '  итог проверки: ok');
if (args.append) appendFileSync(args.append, `\n${lines.join('\n')}\n`);
process.exit(failures.length ? 1 : 0);
