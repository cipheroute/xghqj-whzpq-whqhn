import {readFileSync, writeFileSync} from 'node:fs';

const [filePath] = process.argv.slice(2);

if (!filePath) {
  throw new Error('Usage: node tools/strip-github-from-microsoft.mjs geosite-mini.dat');
}

// The MICROSOFT category ships GitHub domains (github.com, githubusercontent.com, …).
// In the Happ/INCY routing profile `geosite:microsoft` sits in DirectSites while
// `geosite:github` sits in ProxySites, and RouteOrder is block-direct-proxy, so those
// duplicates send every GitHub host to the direct route and shadow the proxy rule.
// This tool removes from MICROSOFT every domain that GITHUB already covers, plus the
// bare `github.com` (kept as `full:github.com` in WHITELIST — see whitelist-exact.txt).

const EXTRA_VALUES = new Set(['github.com']);

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;

  for (let index = offset; index < buffer.length; index += 1) {
    const byte = buffer[index];
    value += (byte & 0x7f) * (2 ** shift);
    if ((byte & 0x80) === 0) return {value, nextOffset: index + 1};
    shift += 7;
  }

  throw new Error('Unexpected end of protobuf varint.');
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
    const wireType = tag.value & 0x07;
    let value;

    if (wireType === 0) {
      const integer = readVarint(buffer, offset);
      value = integer.value;
      offset = integer.nextOffset;
    } else if (wireType === 2) {
      const length = readVarint(buffer, offset);
      const start = length.nextOffset;
      const end = start + length.value;
      if (end > buffer.length) throw new Error('Invalid length-delimited protobuf field.');
      value = buffer.subarray(start, end);
      offset = end;
    } else {
      throw new Error(`Unsupported protobuf wire type ${wireType}.`);
    }

    fields.push({number: tag.value >>> 3, wireType, value, raw: buffer.subarray(fieldStart, offset)});
  }

  return fields;
}

function getStringField(fields, number) {
  const field = fields.find((item) => item.number === number && item.wireType === 2);
  return field ? field.value.toString('utf8') : undefined;
}

function parseDomainField(field) {
  if (field.number !== 2 || field.wireType !== 2) return undefined;
  const fields = readFields(field.value);
  return {
    type: fields.find((item) => item.number === 1 && item.wireType === 0)?.value,
    value: getStringField(fields, 2),
  };
}

function eachSection(buffer, visit) {
  const output = [];
  let offset = 0;

  while (offset < buffer.length) {
    const fieldStart = offset;
    const tag = readVarint(buffer, offset);
    offset = tag.nextOffset;
    if (tag.value !== 0x0a) throw new Error('Unexpected top-level GeoSiteList field.');

    const length = readVarint(buffer, offset);
    const messageStart = length.nextOffset;
    const messageEnd = messageStart + length.value;
    if (messageEnd > buffer.length) throw new Error('Invalid GeoSiteList message length.');
    offset = messageEnd;

    const message = buffer.subarray(messageStart, messageEnd);
    const fields = readFields(message);
    const replacement = visit(getStringField(fields, 1), fields);

    if (!replacement) {
      output.push(buffer.subarray(fieldStart, messageEnd));
      continue;
    }

    const updated = Buffer.concat(replacement.map((field) => field.raw));
    output.push(Buffer.concat([Buffer.from([0x0a]), writeVarint(updated.length), updated]));
  }

  return Buffer.concat(output);
}

const input = readFileSync(filePath);

const githubValues = new Set();
eachSection(input, (code, fields) => {
  if (code !== 'GITHUB') return undefined;
  for (const field of fields) {
    const domain = parseDomainField(field);
    if (domain?.value) githubValues.add(domain.value);
  }
  return undefined;
});

if (githubValues.size === 0) throw new Error('Missing required geosite section: GITHUB');

let removed = 0;
let sawMicrosoft = false;
const output = eachSection(input, (code, fields) => {
  if (code !== 'MICROSOFT') return undefined;
  sawMicrosoft = true;

  const retained = fields.filter((field) => {
    const domain = parseDomainField(field);
    if (!domain?.value) return true;
    if (!githubValues.has(domain.value) && !EXTRA_VALUES.has(domain.value)) return true;
    removed += 1;
    return false;
  });

  return removed === 0 ? undefined : retained;
});

if (!sawMicrosoft) throw new Error('Missing required geosite section: MICROSOFT');

if (removed === 0) {
  console.log('MICROSOFT already carries no GitHub domains.');
  process.exit(0);
}

writeFileSync(filePath, output);
console.log(`Removed ${removed} GitHub domains from MICROSOFT.`);
