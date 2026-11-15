// Structured JSON-line logger for ten98 Node services, exported as @ten98/runtime/log only.
// One call writes one line; the line's shape is built in record() alone, so the field names change in one place.
// It is for service logs. Operator CLI output (ready, migrate and restore summaries) stays plain stdout, not logger lines.
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Readonly<Record<string, unknown>>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  /** A logger that adds these fields to every line; fields given to a call override them. */
  child(fields: LogFields): Logger;
}

export interface LoggerOptions {
  service: string;
  /** The least severe level written; defaults to 'info'. */
  level?: LogLevel;
  /** Receives each line, newline included; defaults to standard output. */
  write?: (line: string) => void;
}

const SEVERITY: Readonly<Record<LogLevel, number>> = { debug: 10, info: 20, warn: 30, error: 40 };
const CORE = new Set(['time', 'level', 'service', 'message', 'requestId']);
// Field names are compared lowercased with `-`, `_`, `.` and spaces removed, so DATABASE_URL, x-api-key and
// connection_string match. A substring match over-redacts (cacheKey, author, compass) rather than miss a secret.
const SECRET_PARTS = /pass|pwd|secret|token|auth|cookie|key|credential|session|jwt|bearer|signature|otp|dsn|databaseurl|connectionstring|private/u;
const SECRET_EXACT = new Set(['sid']);
const secretName = (name: string): boolean => {
  const plain = name.toLowerCase().replace(/[-_.\s]/gu, '');
  return SECRET_PARTS.test(plain) || SECRET_EXACT.has(plain);
};
// Credentials embedded in a URL (`scheme://user:pass@host`, or `scheme://token@host`), whatever the field is called.
const URL_CREDENTIALS = /([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/giu;
const REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/u;

function record(level: LogLevel, service: string, message: string, fields: LogFields): Record<string, unknown> {
  const line: Record<string, unknown> = { time: new Date().toISOString(), level, service, message };
  if (fields.requestId !== undefined) line.requestId = fields.requestId;
  // The core names above always describe the call; a field with one of those names is not written.
  for (const [name, value] of Object.entries(fields)) if (!CORE.has(name)) line[name] = value;
  return line;
}

// Applied at every depth, so a secret inside a nested object (a headers map) is redacted too.
function replacer(name: string, value: unknown): unknown {
  if (name && secretName(name)) return '[redacted]';
  // JSON.stringify passes the returned object's strings back through here, so their URL credentials are removed too.
  if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'string') return value.replace(URL_CREDENTIALS, '$1[redacted]@');
  return value;
}

// The line's core alone, for when the fields cannot be read or serialised: String() keeps it serialisable, and a
// request id is kept only when it is a plain string.
const coreLine = (level: LogLevel, service: unknown, message: unknown, requestId: unknown, reason: string): string =>
  `${JSON.stringify({ time: new Date().toISOString(), level, service: String(service), message: String(message),
    ...(typeof requestId === 'string' ? { requestId } : {}), logError: reason }, replacer)}\n`;

function serialise(line: Record<string, unknown>): string {
  try {
    return `${JSON.stringify(line, replacer)}\n`;
  } catch {
    // A circular or unserialisable field must not turn a log call into a thrown error; keep the line's core.
    return coreLine(line.level as LogLevel, line.service, line.message, line.requestId, 'fields could not be serialised');
  }
}

/**
 * A logger never throws: a field getter that throws, an unserialisable value or a failing `write` costs at most that
 * line's fields (or the line), never the caller's request.
 */
export function createLogger({ service, level = 'info', write = line => { process.stdout.write(line); } }: LoggerOptions): Logger {
  if (!Object.hasOwn(SEVERITY, level)) throw new TypeError(`Unknown log level: ${String(level)}`);
  const threshold = SEVERITY[level];
  const safeWrite = (line: string): void => { try { write(line); } catch { /* a failing sink drops the line */ } };
  const make = (bound: LogFields): Logger => {
    const emit = (at: LogLevel) => (message: string, fields: LogFields = {}): void => {
      if (SEVERITY[at] < threshold) return;
      let line: string;
      try { line = serialise(record(at, service, message, { ...bound, ...fields })); }
      catch { try { line = coreLine(at, service, message, undefined, 'fields could not be read'); } catch { return; } }
      safeWrite(line);
    };
    const child = (fields: LogFields): Logger => {
      try { return make({ ...bound, ...fields }); } catch { return make(bound); }
    };
    return { debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error'), child };
  };
  return make({});
}

/** The caller's x-request-id when it is a plain 8–128 character token, otherwise a new UUID. */
export function requestId(request: Request): string {
  const incoming = request.headers.get('x-request-id');
  return incoming !== null && REQUEST_ID.test(incoming) ? incoming : crypto.randomUUID();
}
