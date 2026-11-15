// Structured JSON-line logger for ten98 Node services, exported as @ten98/runtime/log only.
// One call writes one line; the line's shape is built in record() alone, so the field names change in one place.
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
// A substring match over-redacts (cacheKey, monkey) rather than miss apiKey, accessToken, set-cookie or x-api-key.
const SECRET_NAME = /password|secret|token|authorization|cookie|key/iu;
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
  if (name && SECRET_NAME.test(name)) return '[redacted]';
  if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
  if (typeof value === 'bigint') return value.toString();
  return value;
}

function serialise(line: Record<string, unknown>): string {
  try {
    return `${JSON.stringify(line, replacer)}\n`;
  } catch {
    // A circular field must not turn a log call into a thrown error; keep the line's core and say why the rest is missing.
    const { time, level, service, message, requestId } = line;
    return `${JSON.stringify({ time, level, service, message, requestId, logError: 'fields could not be serialised' }, replacer)}\n`;
  }
}

export function createLogger({ service, level = 'info', write = line => { process.stdout.write(line); } }: LoggerOptions): Logger {
  if (!Object.hasOwn(SEVERITY, level)) throw new TypeError(`Unknown log level: ${String(level)}`);
  const threshold = SEVERITY[level];
  const make = (bound: LogFields): Logger => {
    const emit = (at: LogLevel) => (message: string, fields: LogFields = {}): void => {
      if (SEVERITY[at] >= threshold) write(serialise(record(at, service, message, { ...bound, ...fields })));
    };
    return { debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error'), child: fields => make({ ...bound, ...fields }) };
  };
  return make({});
}

/** The caller's x-request-id when it is a plain 8–128 character token, otherwise a new UUID. */
export function requestId(request: Request): string {
  const incoming = request.headers.get('x-request-id');
  return incoming !== null && REQUEST_ID.test(incoming) ? incoming : crypto.randomUUID();
}
