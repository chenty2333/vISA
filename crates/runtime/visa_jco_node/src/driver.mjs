import { readFileSync, readSync, writeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const PROTOCOL = 3;
const MAX_JSONL_MESSAGE_BYTES = 1024 * 1024;
const MAX_SAFE_ID = Number.MAX_SAFE_INTEGER;
const MAX_U64 = 18446744073709551615n;
const dispose = Symbol.dispose || Symbol.for('dispose');
const utf8 = new TextDecoder('utf-8', { fatal: true });
let input = Buffer.alloc(0);
let nextCommandId = 1;
let nextHostCallId = 1;
let activeCommandId = null;
const liveResources = new Set();
const testResources = new Set();

class ProtocolViolation extends Error {}

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
  const entrypoint = resolve(process.argv[2]);
  const generated = await import(pathToFileURL(entrypoint).href);
  if (typeof generated.instantiate !== 'function') {
    throw new Error('Jco output does not export instantiate');
  }
  const imports = {
    'visa:continuity/key-value': { Namespace },
    'visa:continuity/key-value@0.1.0': { Namespace },
    'visa:continuity/timers': { TimerBinding },
    'visa:continuity/timers@0.1.0': { TimerBinding },
  };
  const root = generated.instantiate(
    (name) => new WebAssembly.Module(readFileSync(resolve(dirname(entrypoint), name))),
    imports,
  );
  if (root instanceof Promise) throw new Error('Jco emitted an asynchronous instantiation path');
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
