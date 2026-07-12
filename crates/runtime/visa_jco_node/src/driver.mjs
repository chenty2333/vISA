import { createHash } from 'node:crypto';
import { readSync, writeSync } from 'node:fs';

const PROTOCOL = 3;
const MAX_JSONL_MESSAGE_BYTES = 1024 * 1024;
const MAX_SAFE_ID = Number.MAX_SAFE_INTEGER;
const MAX_U64 = 18446744073709551615n;
const CARRIER_MAGIC = Buffer.from('VISAJCO1', 'ascii');
const CARRIER_ENTRYPOINT_KIND = 1;
const CARRIER_CORE_MODULE_KIND = 2;
const MAX_CARRIER_FILES = 64;
const MAX_CARRIER_NAME_BYTES = 1024;
const MAX_CARRIER_FILE_BYTES = 64 * 1024 * 1024;
const MAX_CARRIER_TOTAL_BYTES = 256 * 1024 * 1024;
const EXPECTED_ENTRYPOINT = 'handoff-component.component.js';
const dispose = Symbol.dispose || Symbol.for('dispose');
const utf8 = new TextDecoder('utf-8', { fatal: true });
let input = Buffer.alloc(0);
let nextCommandId = 1;
let nextHostCallId = 1;
let activeCommandId = null;
const liveResources = new Set();
const testResources = new Set();

class ProtocolViolation extends Error {}

function readExact(length, label) {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new ProtocolViolation(`invalid ${label} length`);
  }
  const bytes = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const count = readSync(0, bytes, offset, length - offset, null);
    if (count === 0) {
      throw new ProtocolViolation(`startup carrier ended while reading ${label}`);
    }
    offset += count;
  }
  return bytes;
}

function carrierU64(value) {
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function carrierLength(bytes, offset, label) {
  const value = bytes.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ProtocolViolation(`${label} exceeds the safe integer range`);
  }
  return Number(value);
}

function validCarrierName(name) {
  return name.length > 0
    && !name.startsWith('/')
    && name.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..');
}

function readStartupGraph(expectedDigest) {
  if (!/^[0-9a-f]{64}$/.test(expectedDigest || '')) {
    throw new ProtocolViolation('missing or invalid expected generated graph digest');
  }
  if (!readExact(CARRIER_MAGIC.length, 'magic').equals(CARRIER_MAGIC)) {
    throw new ProtocolViolation('unsupported startup carrier magic/version');
  }
  const fileCount = readExact(4, 'artifact count').readUInt32BE();
  if (fileCount < 2 || fileCount > MAX_CARRIER_FILES) {
    throw new ProtocolViolation('invalid startup carrier artifact count');
  }

  const descriptors = [];
  let previous = null;
  let totalBytes = 0;
  for (let index = 0; index < fileCount; index += 1) {
    const header = readExact(45, `artifact ${index} header`);
    const kind = header.readUInt8(0);
    const nameLength = header.readUInt32BE(1);
    const byteLength = carrierLength(header, 5, `artifact ${index}`);
    const digest = header.subarray(13, 45).toString('hex');
    if (kind !== CARRIER_ENTRYPOINT_KIND && kind !== CARRIER_CORE_MODULE_KIND) {
      throw new ProtocolViolation(`artifact ${index} has an unknown kind`);
    }
    if (nameLength === 0 || nameLength > MAX_CARRIER_NAME_BYTES) {
      throw new ProtocolViolation(`artifact ${index} has an invalid name length`);
    }
    if (byteLength > MAX_CARRIER_FILE_BYTES) {
      throw new ProtocolViolation(`artifact ${index} exceeds the per-file carrier limit`);
    }
    totalBytes += byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_CARRIER_TOTAL_BYTES) {
      throw new ProtocolViolation('startup carrier exceeds the total byte limit');
    }
    const nameBytes = readExact(nameLength, `artifact ${index} name`);
    const name = utf8.decode(nameBytes);
    if (!validCarrierName(name) || Buffer.byteLength(name, 'utf8') !== nameLength) {
      throw new ProtocolViolation(`artifact ${index} has a non-canonical name`);
    }
    if (previous !== null && previous >= name) {
      throw new ProtocolViolation('startup carrier artifact names are not strictly sorted');
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
      throw new ProtocolViolation(`carrier artifact digest mismatch for ${descriptor.name}`);
    }
    graphDigest.update(carrierU64(descriptor.nameBytes.length));
    graphDigest.update(descriptor.nameBytes);
    graphDigest.update(carrierU64(bytes.length));
    graphDigest.update(bytes);
    if (descriptor.kind === CARRIER_ENTRYPOINT_KIND) {
      if (entrypoint !== null || descriptor.name !== EXPECTED_ENTRYPOINT) {
        throw new ProtocolViolation('carrier must contain exactly the expected JS entrypoint');
      }
      entrypoint = bytes;
    } else {
      if (!descriptor.name.endsWith('.wasm') || coreModuleBytes.has(descriptor.name)) {
        throw new ProtocolViolation(`invalid core module name ${descriptor.name}`);
      }
      coreModuleBytes.set(descriptor.name, bytes);
    }
  }
  if (entrypoint === null || coreModuleBytes.size === 0) {
    throw new ProtocolViolation('carrier requires one entrypoint and at least one core module');
  }
  if (graphDigest.digest('hex') !== expectedDigest) {
    throw new ProtocolViolation('startup carrier does not match the expected graph digest');
  }
  const coreModules = new Map(
    [...coreModuleBytes].map(([name, bytes]) => [name, new WebAssembly.Module(bytes)]),
  );
  return { entrypoint, coreModules };
}

function writeMessage(message) {
  const json = JSON.stringify(message);
  if (typeof json !== 'string') throw new TypeError('protocol message is not JSON serializable');
  const byteLength = Buffer.byteLength(json, 'utf8') + 1;
  if (byteLength > MAX_JSONL_MESSAGE_BYTES) {
    throw new ProtocolViolation(`protocol message exceeds ${MAX_JSONL_MESSAGE_BYTES} bytes`);
  }
  const bytes = Buffer.from(`${json}\n`, 'utf8');
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(1, bytes, offset, bytes.length - offset);
    if (written <= 0) throw new Error('protocol stdout made no write progress');
    offset += written;
  }
}

function readLine() {
  for (;;) {
    const newline = input.indexOf(0x0a);
    if (newline !== -1) {
      if (newline + 1 > MAX_JSONL_MESSAGE_BYTES) {
        throw new ProtocolViolation(`protocol message exceeds ${MAX_JSONL_MESSAGE_BYTES} bytes`);
      }
      const line = utf8.decode(input.subarray(0, newline));
      input = input.subarray(newline + 1);
      if (line.length !== 0) return line;
      continue;
    }
    const chunk = Buffer.allocUnsafe(4096);
    const count = readSync(0, chunk, 0, chunk.length, null);
    if (count === 0) throw new ProtocolViolation('vISA host closed the protocol stream');
    const received = chunk.subarray(0, count);
    const receivedNewline = received.indexOf(0x0a);
    const nextLineBytes = input.length
      + (receivedNewline === -1 ? received.length : receivedNewline + 1);
    if (nextLineBytes > MAX_JSONL_MESSAGE_BYTES
        || (receivedNewline === -1 && nextLineBytes >= MAX_JSONL_MESSAGE_BYTES)) {
      throw new ProtocolViolation(`protocol message exceeds ${MAX_JSONL_MESSAGE_BYTES} bytes`);
    }
    input = Buffer.concat([input, received]);
  }
}

function readMessage() {
  let message;
  try {
    message = JSON.parse(readLine());
  } catch (error) {
    if (error instanceof ProtocolViolation) throw error;
    throw new ProtocolViolation(`protocol message is not valid JSON: ${error}`);
  }
  if (message === null || typeof message !== 'object' || Array.isArray(message)) {
    throw new ProtocolViolation('protocol message must be an object');
  }
  if (message.protocol !== PROTOCOL) {
    throw new ProtocolViolation(`unsupported protocol version ${message.protocol}`);
  }
  return message;
}

function requireShape(message, type, required, optional = []) {
  if (message.type !== type) throw new ProtocolViolation(`expected ${type} message`);
  const allowed = new Set(['type', 'protocol', ...required, ...optional]);
  for (const key of Object.keys(message)) {
    if (!allowed.has(key)) throw new ProtocolViolation(`${type} message has unknown field ${key}`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(message, key)) {
      throw new ProtocolViolation(`${type} message omitted ${key}`);
    }
  }
}

function requirePositiveId(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_SAFE_ID) {
    throw new ProtocolViolation(`invalid ${label}`);
  }
}

function advanceId(value, label) {
  requirePositiveId(value, label);
  return value === MAX_SAFE_ID ? null : value + 1;
}

function canonicalU64(value, label) {
  if (typeof value !== 'string') {
    throw new ProtocolViolation(`${label} must be canonical decimal text`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw new ProtocolViolation(`${label} must be canonical decimal text`);
  }
  if (parsed < 0n || parsed > MAX_U64 || parsed.toString() !== value) {
    throw new ProtocolViolation(`${label} must be canonical decimal text`);
  }
  return parsed;
}

function validateCommand(message) {
  requireShape(message, 'command', ['id', 'op', 'args']);
  requirePositiveId(message.id, 'command id');
  if (message.id !== nextCommandId) {
    throw new ProtocolViolation(`command id ${message.id} did not match expected ${nextCommandId}`);
  }
  if (typeof message.op !== 'string' || message.op.length === 0) {
    throw new ProtocolViolation('invalid command operation');
  }
  if (message.args === null || typeof message.args !== 'object' || Array.isArray(message.args)) {
    throw new ProtocolViolation('command args must be an object');
  }
  nextCommandId = advanceId(message.id, 'command id');
}

function validateWireError(error) {
  if (error === null || typeof error !== 'object' || Array.isArray(error)) {
    throw new ProtocolViolation('invalid host error');
  }
  const keys = Object.keys(error);
  if (keys.some((key) => !['domain', 'kind', 'detail'].includes(key))
      || typeof error.domain !== 'string'
      || typeof error.kind !== 'string'
      || (error.detail !== undefined && typeof error.detail !== 'string')) {
    throw new ProtocolViolation('invalid host error');
  }
}

function validateHostResponse(message, id) {
  requireShape(message, 'hostcall-response', ['id', 'ok'], ['result', 'error']);
  requirePositiveId(message.id, 'hostcall response id');
  if (message.id !== id) throw new ProtocolViolation(`unexpected host response for hostcall ${id}`);
  if (typeof message.ok !== 'boolean') {
    throw new ProtocolViolation('invalid hostcall response status');
  }
  if (message.ok) {
    if (!Object.prototype.hasOwnProperty.call(message, 'result') || message.error !== undefined) {
      throw new ProtocolViolation('successful hostcall response has invalid result/error fields');
    }
  } else {
    if (!Object.prototype.hasOwnProperty.call(message, 'error') || message.result !== undefined) {
      throw new ProtocolViolation('failed hostcall response has invalid result/error fields');
    }
    validateWireError(message.error);
  }
}

function hostCall(op, resource, args = {}) {
  requirePositiveId(activeCommandId, 'active command id');
  requirePositiveId(resource, 'resource id');
  const id = nextHostCallId;
  nextHostCallId = advanceId(id, 'hostcall id');
  writeMessage({
    type: 'hostcall', protocol: PROTOCOL, id, commandId: activeCommandId, op, resource, args,
  });
  let response;
  try {
    response = readMessage();
    validateHostResponse(response, id);
  } catch (error) {
    if (error instanceof ProtocolViolation) throw error;
    throw new ProtocolViolation(`reading hostcall response ${id} failed: ${error}`);
  }
  if (response.ok) return response.result;
  const error = response.error || { domain: 'protocol', kind: 'missing-error' };
  if (error.domain === 'kv' || error.domain === 'timer') {
    const wit = { tag: error.kind };
    if (error.detail !== undefined) wit.val = error.detail;
    throw wit;
  }
  throw new ProtocolViolation(
    `${error.domain}:${error.kind}${error.detail ? `: ${error.detail}` : ''}`,
  );
}

class HostResource {
  constructor(kind, id) {
    requirePositiveId(id, 'resource id');
    this.kind = kind;
    this.id = id;
    this.disposed = false;
    liveResources.add(this);
  }

  [dispose]() {
    if (this.disposed) return;
    hostCall('resource.dispose', this.id, { kind: this.kind });
    this.disposed = true;
    liveResources.delete(this);
  }
}

class Namespace extends HostResource {
  constructor(id) {
    super('kv', id);
  }

  read(key) {
    const value = hostCall('kv.read', this.id, { key });
    if (value === null || value === undefined) return undefined;
    return {
      value: Uint8Array.from(value.value),
      version: canonicalU64(value.version, 'kv.read result version'),
    };
  }

  conditionalPut(idempotencyKey, key, expectedVersion, value) {
    const result = hostCall('kv.conditional-put', this.id, {
      idempotencyKey,
      key,
      expectedVersion: expectedVersion === undefined ? null : expectedVersion.toString(),
      value: Array.from(value),
    });
    return {
      operationId: result.operationId,
      version: canonicalU64(result.version, 'kv.conditional-put result version'),
      applied: result.applied,
    };
  }
}

class TimerBinding extends HostResource {
  constructor(id) {
    super('timer', id);
  }

  arm(idempotencyKey, durationNs) {
    return hostCall('timer.arm', this.id, {
      idempotencyKey,
      durationNs: durationNs.toString(),
    });
  }

  cancel(operationId) {
    hostCall('timer.cancel', this.id, { operationId });
  }
}

class TestLiveResource {
  constructor() {
    this.disposed = false;
    testResources.add(this);
  }

  [dispose]() {
    if (this.disposed) return;
    this.disposed = true;
    testResources.delete(this);
  }
}

function decodeState(state) {
  return {
    sessionId: state.sessionId,
    key: state.key,
    expectedVersion: canonicalU64(state.expectedVersion, 'state expectedVersion'),
    completionValue: Uint8Array.from(state.completionValue),
    timerOperationId: state.timerOperationId,
    timerIdempotencyKey: state.timerIdempotencyKey,
    completionIdempotencyKey: state.completionIdempotencyKey,
    phase: state.phase,
  };
}

function encodeState(state) {
  if (state === undefined) return null;
  return {
    sessionId: state.sessionId,
    key: state.key,
    expectedVersion: state.expectedVersion.toString(),
    completionValue: Array.from(state.completionValue),
    timerOperationId: state.timerOperationId,
    timerIdempotencyKey: state.timerIdempotencyKey,
    completionIdempotencyKey: state.completionIdempotencyKey,
    phase: state.phase,
  };
}

function normalizeError(error) {
  const payload = error && Object.prototype.hasOwnProperty.call(error, 'payload')
    ? error.payload
    : error;
  if (payload && typeof payload === 'object' && typeof payload.tag === 'string') {
    if (payload.tag === 'kv' || payload.tag === 'timer') {
      const nested = payload.val || {};
      return {
        domain: 'workload',
        kind: `${payload.tag}.${nested.tag || 'unknown'}`,
        ...(nested.val === undefined ? {} : { detail: String(nested.val) }),
      };
    }
    return { domain: 'workload', kind: payload.tag };
  }
  const detail = error instanceof Error ? (error.stack || error.message) : String(error);
  return { domain: 'trap', kind: 'guest-trap', detail };
}

function resourcePair(args) {
  return [new Namespace(args.kvResource), new TimerBinding(args.timerResource)];
}

function invoke(workload, op, args) {
  switch (op) {
    case 'activate': {
      const [kv, timer] = resourcePair(args);
      workload.activate(
        args.sessionId,
        args.key,
        Uint8Array.from(args.initialValue),
        Uint8Array.from(args.completionValue),
        canonicalU64(args.delayNs, 'activate delayNs'),
        args.baselineIdempotencyKey,
        args.timerIdempotencyKey,
        args.completionIdempotencyKey,
        kv,
        timer,
      );
      return null;
    }
    case 'freeze':
      return encodeState(workload.freeze());
    case 'thaw': {
      const [kv, timer] = resourcePair(args);
      workload.thaw(decodeState(args.state), kv, timer);
      return null;
    }
    case 'restore': {
      const [kv, timer] = resourcePair(args);
      workload.restore(
        decodeState(args.state),
        canonicalU64(args.remainingDurationNs, 'restore remainingDurationNs'),
        kv,
        timer,
      );
      return null;
    }
    case 'timer-fired':
      workload.timerFired(args.operationId);
      return null;
    case 'cancel-pending':
      workload.cancelPending();
      return null;
    case 'status':
      return encodeState(workload.status());
    case 'test.inject-live-resource':
      new TestLiveResource();
      return null;
    case 'test.clear-live-resource': {
      const resource = testResources.values().next().value;
      if (resource === undefined) throw new Error('no injected live resource');
      resource[dispose]();
      return null;
    }
    default:
      throw new Error(`unsupported command ${op}`);
  }
}

async function main() {
  const { entrypoint, coreModules } = readStartupGraph(process.argv[1]);
  const generated = await import(
    `data:text/javascript;base64,${entrypoint.toString('base64')}`
  );
  if (typeof generated.instantiate !== 'function') {
    throw new Error('Jco output does not export instantiate');
  }
  const imports = {
    'visa:continuity/key-value': { Namespace },
    'visa:continuity/key-value@0.1.0': { Namespace },
    'visa:continuity/timers': { TimerBinding },
    'visa:continuity/timers@0.1.0': { TimerBinding },
  };
  const unusedCoreModules = new Set(coreModules.keys());
  const root = generated.instantiate((name) => {
    if (!unusedCoreModules.delete(name)) {
      throw new Error(`Jco requested an unknown or repeated core module ${name}`);
    }
    return coreModules.get(name);
  }, imports);
  if (root instanceof Promise) throw new Error('Jco emitted an asynchronous instantiation path');
  if (unusedCoreModules.size !== 0) {
    throw new Error(`Jco did not instantiate core modules: ${[...unusedCoreModules].join(', ')}`);
  }
  const workload = root.workload || root['visa:continuity/workload@0.1.0'];
  if (!workload) throw new Error('component did not expose the workload interface');

  writeMessage({
    type: 'ready', protocol: PROTOCOL,
    nodeVersion: process.versions.node,
    v8Version: process.versions.v8,
    liveResources: 0,
  });
  for (;;) {
    const command = readMessage();
    validateCommand(command);
    if (command.op === 'shutdown') return;
    activeCommandId = command.id;
    let response;
    try {
      const result = invoke(workload, command.op, command.args || {});
      response = {
        type: 'response', protocol: PROTOCOL, id: command.id, ok: true, result,
        liveResources: liveResources.size + testResources.size,
      };
    } catch (error) {
      if (error instanceof ProtocolViolation) throw error;
      response = {
        type: 'response', protocol: PROTOCOL, id: command.id, ok: false,
        error: normalizeError(error),
        liveResources: liveResources.size + testResources.size,
      };
    } finally {
      activeCommandId = null;
    }
    writeMessage(response);
    writeMessage({ type: 'settled', protocol: PROTOCOL, id: command.id });
  }
}

main().catch((error) => {
  writeMessage({
    type: 'startup-error', protocol: PROTOCOL, ok: false,
    error: normalizeError(error), liveResources: liveResources.size + testResources.size,
  });
  process.exitCode = 1;
});
