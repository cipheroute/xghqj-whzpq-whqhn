import {readFileSync, writeFileSync} from 'node:fs';

const [filePath, rulesPath] = process.argv.slice(2);

if (!filePath || !rulesPath) {
  throw new Error('Usage: node tools/update-geosite-whitelist.mjs geosite-mini.dat whitelist-exact.txt');
}

const DOMAIN_TYPE = {
  regex: 1,
  domain: 2,
  full: 3,
};

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

function parseDomainField(field) {
  if (field.number !== 2 || field.wireType !== 2) return undefined;
  const fields = readFields(field.value);
  return {
    type: fields.find((item) => item.number === 1 && item.wireType === 0)?.value,
    value: getStringField(fields, 2),
  };
}

function encodeDomainField(type, value) {
  const encodedValue = Buffer.from(value, 'utf8');
  const body = Buffer.concat([
    Buffer.from([0x08]),
    writeVarint(type),
    Buffer.from([0x12]),
    writeVarint(encodedValue.length),
    encodedValue,
  ]);

  return Buffer.concat([Buffer.from([0x12]), writeVarint(body.length), body]);
}

const whitelistRules = readFileSync(rulesPath, 'utf8')
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'))
  .map((rule) => {
    const match = /^(full|domain):(.+)$/u.exec(rule);
    if (!match) {
      throw new Error('Only non-empty full: and domain: rules are supported.');
    }

    return {
      type: DOMAIN_TYPE[match[1]],
      value: match[2],
    };
  });

const exactHosts = whitelistRules
  .filter((rule) => rule.type === DOMAIN_TYPE.full)
  .map((rule) => rule.value);

const githubSubdomainRegex = '^.+\\.github\\.com$';
const input = readFileSync(filePath);
const output = [];
const updatedSections = new Set();
let offset = 0;

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
  let additions = [];

  const retainedFields = fields.filter((field) => {
    const domain = parseDomainField(field);
    if (!domain) return true;

    if (
      code === 'WHITELIST'
      && whitelistRules.some((rule) => rule.type === domain.type && rule.value === domain.value)
    ) {
      return false;
    }

    if (
      code === 'GITHUB'
      && exactHosts.includes('github.com')
      && (
        (domain.type === DOMAIN_TYPE.domain && domain.value === 'github.com')
        || (domain.type === DOMAIN_TYPE.regex && domain.value === githubSubdomainRegex)
      )
    ) {
      return false;
    }

    return true;
  });

  if (code === 'WHITELIST') {
    additions = whitelistRules.map((rule) => encodeDomainField(rule.type, rule.value));
    updatedSections.add(code);
  } else if (code === 'GITHUB' && exactHosts.includes('github.com')) {
    additions = [encodeDomainField(DOMAIN_TYPE.regex, githubSubdomainRegex)];
    updatedSections.add(code);
  }

  if (additions.length === 0) {
    output.push(input.subarray(fieldStart, messageEnd));
    continue;
  }

  const updatedMessage = Buffer.concat([
    ...retainedFields.map((field) => field.raw),
    ...additions,
  ]);
  output.push(Buffer.concat([Buffer.from([0x0a]), writeVarint(updatedMessage.length), updatedMessage]));
}

for (const requiredSection of ['WHITELIST', 'GITHUB']) {
  if (!updatedSections.has(requiredSection)) {
    throw new Error(`Missing required geosite section: ${requiredSection}`);
  }
}

const updated = Buffer.concat(output);
if (updated.equals(input)) {
  console.log('Whitelist routing rules are already up to date.');
  process.exit(0);
}

writeFileSync(filePath, updated);
console.log('Applied whitelist direct rules and GitHub-subdomains proxy rule.');
