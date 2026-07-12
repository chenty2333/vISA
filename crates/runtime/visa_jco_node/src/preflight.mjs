import { createHash } from 'node:crypto';
import { readSync } from 'node:fs';

const MAGIC = Buffer.from('VISAJCO1', 'ascii');
const ENTRYPOINT_KIND = 1;
const CORE_MODULE_KIND = 2;
const MAX_FILES = 64;
const MAX_NAME_BYTES = 1024;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const EXPECTED_ENTRYPOINT = 'handoff-component.component.js';
const utf8 = new TextDecoder('utf-8', { fatal: true });

function readExact(length, label) {
  if (!Number.isSafeInteger(length) || length < 0) throw new Error(`invalid ${label} length`);
  const bytes = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const count = readSync(0, bytes, offset, length - offset, null);
    if (count === 0) throw new Error(`startup carrier ended while reading ${label}`);
    offset += count;
  }
  return bytes;
}

function u64(value) {
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function readLength(bytes, offset, label) {
  const value = bytes.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} exceeds safe integer`);
  return Number(value);
}

function validName(name) {
  return name.length > 0
    && !name.startsWith('/')
    && name.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..');
}

function readGraph(expectedDigest) {
  if (!/^[0-9a-f]{64}$/.test(expectedDigest || '')) {
    throw new Error('missing or invalid expected generated graph digest');
  }
  if (!readExact(MAGIC.length, 'magic').equals(MAGIC)) {
    throw new Error('unsupported startup carrier magic/version');
  }
  const fileCount = readExact(4, 'artifact count').readUInt32BE();
  if (fileCount < 2 || fileCount > MAX_FILES) throw new Error('invalid carrier artifact count');

  const descriptors = [];
  let previous = null;
  let totalBytes = 0;
  for (let index = 0; index < fileCount; index += 1) {
    const header = readExact(45, `artifact ${index} header`);
    const kind = header.readUInt8(0);
    const nameLength = header.readUInt32BE(1);
    const byteLength = readLength(header, 5, `artifact ${index}`);
    const digest = header.subarray(13, 45).toString('hex');
    if (kind !== ENTRYPOINT_KIND && kind !== CORE_MODULE_KIND) {
      throw new Error(`artifact ${index} has an unknown kind`);
    }
    if (nameLength === 0 || nameLength > MAX_NAME_BYTES) {
      throw new Error(`artifact ${index} has an invalid name length`);
    }
    if (byteLength > MAX_FILE_BYTES) throw new Error(`artifact ${index} exceeds file limit`);
    totalBytes += byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_TOTAL_BYTES) {
      throw new Error('startup carrier exceeds total byte limit');
    }
    const nameBytes = readExact(nameLength, `artifact ${index} name`);
    const name = utf8.decode(nameBytes);
    if (!validName(name) || Buffer.byteLength(name, 'utf8') !== nameLength) {
      throw new Error(`artifact ${index} has a non-canonical name`);
    }
    if (previous !== null && previous >= name) {
      throw new Error('carrier artifact names are not strictly sorted');
    }
    previous = name;
    descriptors.push({ kind, name, nameBytes, byteLength, digest });
  }

  const graphDigest = createHash('sha256');
  let entrypoint = null;
  const coreModuleBytes = new Map();
  for (const descriptor of descriptors) {
    const bytes = readExact(descriptor.byteLength, descriptor.name);
    if (createHash('sha256').update(bytes).digest('hex') !== descriptor.digest) {
      throw new Error(`carrier artifact digest mismatch for ${descriptor.name}`);
    }
    graphDigest.update(u64(descriptor.nameBytes.length));
    graphDigest.update(descriptor.nameBytes);
    graphDigest.update(u64(bytes.length));
    graphDigest.update(bytes);
    if (descriptor.kind === ENTRYPOINT_KIND) {
      if (entrypoint !== null || descriptor.name !== EXPECTED_ENTRYPOINT) {
        throw new Error('carrier must contain exactly the expected JS entrypoint');
      }
      entrypoint = bytes;
    } else {
      if (!descriptor.name.endsWith('.wasm') || coreModuleBytes.has(descriptor.name)) {
        throw new Error(`invalid core module name ${descriptor.name}`);
      }
      coreModuleBytes.set(descriptor.name, bytes);
    }
  }
  if (entrypoint === null || coreModuleBytes.size === 0) {
    throw new Error('carrier requires one entrypoint and at least one core module');
  }
  if (graphDigest.digest('hex') !== expectedDigest) {
    throw new Error('startup carrier does not match the expected generated graph digest');
  }
  return new Map(
    [...coreModuleBytes].map(([name, bytes]) => [name, new WebAssembly.Module(bytes)]),
  );
}

readGraph(process.argv[1]);
process.stdout.write(JSON.stringify({
  node: process.versions.node,
  v8: process.versions.v8,
}));
