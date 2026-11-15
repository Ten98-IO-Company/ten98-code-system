// Structured JSON-line logger for ten98 Node services, exported as @ten98/runtime/log only. pino (an exact optional
// peer) writes the line and hides values at the redaction paths. Before pino sees them, the fields are copied into a
// bounded plain object: that copy is what keeps a log call from throwing or running long on hostile values, and it is
// where errors become safe forms. Operator CLI output (ready, migrate and restore summaries) stays plain stdout.
import pino from 'pino';
import { errorClassName, isDatabaseError, safeDatabaseError, SafeDatabaseError } from './database-error.mjs';

export { safeDatabaseError, SafeDatabaseError } from './database-error.mjs';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Readonly<Record<string, unknown>>;

// An Error given as the fields is written under `err`.
export interface Logger {
  debug(message: string, fields?: LogFields | Error): void;
  info(message: string, fields?: LogFields | Error): void;
  warn(message: string, fields?: LogFields | Error): void;
  error(message: string, fields?: LogFields | Error): void;
  /** A logger that adds these fields to every line; fields given to a call override them. */
  child(fields: LogFields): Logger;
}

export interface LoggerOptions {
  service: string;
  /** The least severe level written; defaults to 'info'. */
  level?: LogLevel;
  /** Paths hidden in addition to DEFAULT_REDACT_PATHS, in pino's path syntax (`user.email`, `*.ssn`, `a["b-c"]`). */
  redact?: readonly string[];
  /** Receives each line, newline included; defaults to standard output. */
  write?: (line: string) => void;
}

// Names hidden at the top level and one and two levels down.
const SECRET_NAMES = ['password', 'passwd', 'pass', 'pwd', 'passphrase', 'secret', 'clientSecret', 'token', 'accessToken',
  'refreshToken', 'idToken', 'apiKey', 'x-api-key', 'authorization', 'cookie', 'set-cookie', 'session', 'sessionId', 'sid',
  'jwt', 'bearer', 'signature', 'otp', 'dsn', 'databaseUrl', 'DATABASE_URL', 'connectionString', 'privateKey', 'credential',
  'credentials', 'cvv', 'cardNumber', 'mnemonic', 'seed', 'hmac', 'salt', 'recoveryCodes'];
const segment = (name: string): string => /^[A-Za-z_$][\w$]*$/u.test(name) ? `.${name}` : `[${JSON.stringify(name)}]`;
/** The paths every logger hides with `[redacted]`; `createLogger({ redact })` adds to them and cannot remove any. */
export const DEFAULT_REDACT_PATHS: readonly string[] = Object.freeze([
  ...SECRET_NAMES.flatMap(name => [segment(name).replace(/^\./u, ''), `*${segment(name)}`, `*.*${segment(name)}`]),
  'req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]',
]);

// Bounds on what one call writes. Strings count UTF-16 code units, before JSON escaping.
const LIMITS = { depth: 5, entries: 100, string: 8192, key: 256, values: 1000, characters: 65_536 };
const CORE = new Set(['time', 'level', 'service', 'msg']);
const LEVELS: readonly LogLevel[] = ['debug', 'info', 'warn', 'error'];
const TRUNCATED = '[truncated]';
const REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/u;

type Budget = { values: number; characters: number };
type Plain = Record<string, unknown>;
const budget = (): Budget => ({ values: LIMITS.values, characters: LIMITS.characters });
// Null-prototype records, so a field named __proto__ is an ordinary field.
const record = (): Plain => Object.create(null) as Plain;

function text(value: string, spend: Budget): string {
  const room = Math.min(LIMITS.string, spend.characters);
  if (room <= 0) return TRUNCATED;
  spend.characters -= Math.min(value.length, room);
  return value.length <= room ? value : `${value.slice(0, room)}…${TRUNCATED}`;
}

const key = (name: string): string => name.length <= LIMITS.key ? name : `${name.slice(0, LIMITS.key)}…`;

function read(value: unknown, name: string | number): unknown {
  try {
    return (value as Record<string | number, unknown>)[name];
  } catch {
    return '[unreadable]';
  }
}

function databaseForm(error: SafeDatabaseError): Plain {
  const out = record();
  out.type = error.errorClass;
  out.message = error.message;
  for (const name of ['code', 'constraint', 'table', 'column', 'schema'] as const) if (error[name] !== undefined) out[name] = error[name];
  if (error.cause) out.cause = databaseForm(error.cause);
  return out;
}

// An error is written as its class name, message, stack, code, cause and AggregateError members only, never its other
// properties (a request or a configuration may hang off them). A database error at any depth is written in safe form.
function errorForm(error: Error, depth: number, ancestors: object[], spend: Budget): Plain {
  if (isDatabaseError(error)) return databaseForm(safeDatabaseError(error));
  const out = record();
  out.type = errorClassName(error);
  for (const name of ['message', 'stack'] as const) {
    const value = read(error, name);
    if (typeof value === 'string') out[name] = text(value, spend);
  }
  const code = read(error, 'code');
  if (typeof code === 'string' || typeof code === 'number') out.code = typeof code === 'string' ? text(code, spend) : code;
  for (const name of ['cause', 'errors'] as const) {
    const value = read(error, name);
    if (value !== undefined && (name === 'cause' || Array.isArray(value))) out[name] = copy(value, depth + 1, [...ancestors, error], spend);
  }
  return out;
}

// A bounded plain copy: at most LIMITS.depth levels, LIMITS.entries entries per object or array, LIMITS.values values
// and LIMITS.characters characters in all. Getters that throw, revoked proxies and cycles become markers, never errors.
// Only own enumerable fields are copied and toJSON is not called (a Date is written as its ISO time); binary data is
// written as its type and size.
function copy(value: unknown, depth: number, ancestors: object[], spend: Budget): unknown {
  if (spend.values-- <= 0) return TRUNCATED;
  switch (typeof value) {
    case 'string': return text(value, spend);
    case 'number': return Number.isFinite(value) ? value : String(value);
    case 'boolean': return value;
    case 'bigint': return text(value.toString(), spend);
    case 'undefined': case 'function': case 'symbol': return undefined;
  }
  if (value === null) return null;
  try {
    const object = value as object;
    if (ancestors.includes(object)) return '[circular]';
    if (object instanceof Error) return errorForm(object, depth, ancestors, spend);
    if (ArrayBuffer.isView(object) || object instanceof ArrayBuffer || object instanceof SharedArrayBuffer) {
      return `[${errorClassName(object)} ${(object as ArrayBuffer).byteLength} bytes]`;
    }
    if (object instanceof Date) return Number.isNaN(object.getTime()) ? null : object.toISOString();
    if (depth >= LIMITS.depth) return '[depth limit]';
    const inner = [...ancestors, object];
    if (Array.isArray(object)) {
      const items: unknown[] = [], length = object.length;
      for (let index = 0; index < Math.min(length, LIMITS.entries); index++) items.push(copy(read(object, index), depth + 1, inner, spend) ?? null);
      if (length > LIMITS.entries) items.push(TRUNCATED);
      return items;
    }
    return fields(object, depth, inner, spend, false);
  } catch {
    return '[unreadable]';
  }
}

function fields(source: object, depth: number, ancestors: object[], spend: Budget, top: boolean): Plain {
  const out = record();
  const names = Object.keys(source);
  for (const name of names.slice(0, LIMITS.entries)) {
    if (top && CORE.has(name)) continue;
    const value = copy(read(source, name), depth + 1, ancestors, spend);
    if (value !== undefined) out[key(name)] = value;
  }
  if (names.length > LIMITS.entries) out[TRUNCATED] = `${names.length - LIMITS.entries} more fields`;
  return out;
}

// The fields of one call or one child, bounded. An Error passed as the fields is written under `err`.
function bounded(given: unknown): Plain {
  try {
    if (given === undefined || given === null) return record();
    const source = given instanceof Error ? { err: given } : typeof given === 'object' && !Array.isArray(given) ? given : { fields: given };
    return fields(source, -1, [source], budget(), true);
  } catch {
    return record();
  }
}

function message(value: unknown): string {
  try {
    return text(typeof value === 'string' ? value : String(value), { values: 1, characters: LIMITS.string });
  } catch {
    return '[unreadable]';
  }
}

// Child bindings are kept here, not in pino, so they are bounded and core names are dropped the same way.
function merge(bound: Plain, added: Plain): Plain {
  const out = Object.assign(record(), bound);
  for (const name of Object.keys(added)) if (name in out || Object.keys(out).length < LIMITS.entries) out[name] = added[name];
  return out;
}

/**
 * A logger writing one JSON line per call with `time` (ISO), `level`, `service`, the fields and `msg`. Values at
 * DEFAULT_REDACT_PATHS and `redact` are written as `[redacted]`. A field named `time`, `level`, `service` or `msg` is not
 * written. A log call never throws. Throws a TypeError for a missing service, an unknown level or an invalid path.
 */
export function createLogger({ service, level = 'info', redact = [], write }: LoggerOptions): Logger {
  if (typeof service !== 'string' || !service) throw new TypeError('createLogger needs a service name');
  if (!LEVELS.includes(level)) throw new TypeError(`Unknown log level: ${String(level)}`);
  if (!Array.isArray(redact) || !redact.every(path => typeof path === 'string' && path)) throw new TypeError('redact must be a list of paths');
  if (write !== undefined && typeof write !== 'function') throw new TypeError('write must be a function');
  const options: pino.LoggerOptions = {
    level,
    base: { service },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: { level: label => ({ level: label }) },
    // The fields arrive as plain copies with errors already in safe form; pino's error serializer would rename them.
    serializers: { err: (value: unknown) => value },
    redact: { paths: [...DEFAULT_REDACT_PATHS, ...redact], censor: '[redacted]' },
  };
  let target: pino.Logger;
  try {
    target = write ? pino(options, { write }) : pino(options);
  } catch (error) {
    throw new TypeError(`Invalid logger options: ${error instanceof Error ? error.message : String(error)}`);
  }
  const make = (bound: Plain): Logger => {
    const emit = (at: LogLevel) => (text: string, given?: LogFields | Error): void => {
      try {
        if (target.isLevelEnabled(at)) target[at](Object.assign(record(), bound, bounded(given)), message(text));
      } catch {
        // A failing destination loses the line rather than failing the caller.
      }
    };
    return {
      debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error'),
      child: given => make(merge(bound, bounded(given))),
    };
  };
  return make(record());
}

type HeaderSource = { headers: { get(name: string): string | null } } | { headers: Readonly<Record<string, string | string[] | undefined>> };

/**
 * The caller's `x-request-id` when it is a plain 8–128 character token (letters, digits, `.`, `_`, `-`), otherwise a
 * new UUID. Takes a web Request or a Node IncomingMessage. Bind it with `log.child({ requestId })`.
 */
export function requestId(request: HeaderSource): string {
  try {
    const headers = request.headers as { get?: unknown } & Record<string, unknown>;
    const incoming = typeof headers.get === 'function' ? (headers.get as (name: string) => unknown)('x-request-id') : headers['x-request-id'];
    if (typeof incoming === 'string' && REQUEST_ID.test(incoming)) return incoming;
  } catch {
    // An unreadable header is treated as absent.
  }
  return crypto.randomUUID();
}
