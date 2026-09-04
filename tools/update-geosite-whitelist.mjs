import {readFileSync, writeFileSync} from 'node:fs';

const [filePath, rulesPath] = process.argv.slice(2);

if (!filePath || !rulesPath) {
  throw new Error('Usage: node tools/update-geosite-whitelist.mjs geosite-mini.dat whitelist-exact.txt');
}

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;

  for (let index = offset; index < buffer.length; index += 1) {
    const byte = buffer[index];
    value += (byte & 0x7f) * (2 ** shift);
    if ((byte & 0x80) === 0) {
      return {value, nextOffset: index + 1};
    }
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

    fields.push({
      number: tag.value >>> 3,
      wireType,
      value,
      raw: buffer.subarray(fieldStart, offset),
    });
  }

  return fields;
}

function getStringField(fields, number) {
  const field = fields.find((item) => item.number === number && item.wireType === 2);
  return field ? field.value.toString('utf8') : undefined;
}

function domainMessage(rule) {
  const value = Buffer.from(rule.slice('full:'.length), 'utf8');
  const body = Buffer.concat([
    Buffer.from([0x08, 0x02]), // Domain.Type = Full
    Buffer.from([0x12]),
    writeVarint(value.length),
    value,
  ]);

  return Buffer.concat([Buffer.from([0x12]), writeVarint(body.length), body]);
}

const rules = readFileSync(rulesPath, 'utf8')
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));

if (rules.some((rule) => !rule.startsWith('full:') || rule.length === 'full:'.length)) {
  throw new Error('Only non-empty full: domain rules are supported.');
}

const input = readFileSync(filePath);
const output = [];
let offset = 0;
let updated = false;

while (offset < input.length) {
  const fieldStart = offset;
  const tag = readVarint(input, offset);
  offset = tag.nextOffset;

  if (tag.value !== 0x0a) throw new Error('Unexpected top-level GeoSiteList field.');

  const length = readVarint(input, offset);
  const messageStart = length.nextOffset;
  const messageEnd = messageStart + length.value;
  if (messageEnd > input.length) throw new Error('Invalid GeoSiteList message length.');
  offset = messageEnd;

  const message = input.subarray(messageStart, messageEnd);
  const fields = readFields(message);
  const code = getStringField(fields, 1);

  if (code !== 'WHITELIST') {
    output.push(input.subarray(fieldStart, messageEnd));
    continue;
  }

  const currentRules = new Set(
    fields
      .filter((field) => field.number === 2 && field.wireType === 2)
      .map((field) => {
        const domainFields = readFields(field.value);
        const type = domainFields.find((item) => item.number === 1 && item.wireType === 0)?.value;
        const domain = getStringField(domainFields, 2);
        return type === 2 && domain ? `full:${domain}` : undefined;
      })
      .filter(Boolean),
  );

  const additions = rules.filter((rule) => !currentRules.has(rule));
  const updatedMessage = additions.length === 0
    ? message
    : Buffer.concat([message, ...additions.map(domainMessage)]);

  output.push(Buffer.concat([Buffer.from([0x0a]), writeVarint(updatedMessage.length), updatedMessage]));
  updated = additions.length > 0;
}

if (!updated) {
  console.log('WHITELIST already contains every requested exact domain.');
  process.exit(0);
}

writeFileSync(filePath, Buffer.concat(output));
console.log(`Added ${rules.join(', ')} to WHITELIST.`);
