// Database errors without their statement or bound values. A drizzle-orm DrizzleQueryError carries `query`, `params`
// and a message that embeds both; a pg DatabaseError carries `detail`, `where`, `internalQuery` and a server message,
// and PostgreSQL puts input values in some messages (22P02 quotes the value it could not cast). Path-based redaction
// cannot reach text inside a message, so the safe form keeps names and codes only. No library is imported: errors are
// recognised by shape, which also survives a bundler renaming the classes.

// The fields kept from each error in the chain. PostgreSQL identifiers are at most 63 bytes; a longer string is not a name.
const NAMES = ['constraint', 'table', 'column', 'schema'] as const;
const NAME = /^[^\u0000-\u001f\u007f]{1,128}$/u;
const CODE = /^[A-Za-z0-9_]{1,64}$/u;
const CLASS = /^[A-Za-z_$][\w$]{0,63}$/u;
// pg reports SQLSTATE codes as five digits or capitals, with a severity.
const SQLSTATE = /^[0-9A-Z]{5}$/u;
const MAX_CAUSES = 8;

type Kept = Partial<Record<'code' | (typeof NAMES)[number], string>>;

/** A database error reduced to its class name, SQLSTATE code and the constraint, table, column and schema names. */
export class SafeDatabaseError extends Error {
  override name = 'SafeDatabaseError';
  /** The class name of the error this was made from, such as `DrizzleQueryError` or `DatabaseError`. */
  readonly errorClass: string;
  declare readonly code?: string;
  declare readonly constraint?: string;
  declare readonly table?: string;
  declare readonly column?: string;
  declare readonly schema?: string;
  declare readonly cause?: SafeDatabaseError;

  constructor(errorClass: string, message: string, kept: Kept, cause?: SafeDatabaseError) {
    super(message, cause ? { cause } : undefined);
    this.errorClass = errorClass;
    for (const [key, value] of Object.entries(kept)) if (value !== undefined) Object.defineProperty(this, key, { value, enumerable: true });
  }
}

// A property read that never throws: getters and proxies may.
function read(value: unknown, key: string): unknown {
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function owns(value: object, key: string): boolean {
  try {
    return Object.hasOwn(value, key);
  } catch {
    return false;
  }
}

export function errorClassName(value: unknown): string {
  const name = read(read(value, 'constructor'), 'name');
  return typeof name === 'string' && CLASS.test(name) ? name : 'Error';
}

/**
 * Whether the error carries a statement or a database server report: a statement wrapper (own `query` or `params`,
 * as DrizzleQueryError has), a pg server error (a SQLSTATE `code` with a `severity`), or one of those class names.
 */
export function isDatabaseError(value: unknown): boolean {
  if (value instanceof SafeDatabaseError) return true;
  if (typeof value !== 'object' || value === null) return false;
  if (owns(value, 'query') || owns(value, 'params')) return true;
  const code = read(value, 'code');
  if (typeof read(value, 'severity') === 'string' && typeof code === 'string' && SQLSTATE.test(code)) return true;
  return ['DatabaseError', 'DrizzleQueryError'].includes(errorClassName(value));
}

// The message up to the statement: "Failed query: <statement>\nparams: <values>" becomes "Failed query". A message
// that does not contain the error's own statement text is not kept, because it may quote a value.
function messageBeforeStatement(error: unknown): string | undefined {
  const message = read(error, 'message'), query = read(error, 'query');
  if (typeof message !== 'string' || typeof query !== 'string' || !query) return undefined;
  const at = message.indexOf(query);
  if (at < 0) return undefined;
  const head = message.slice(0, at).replace(/[\s:]+$/u, '');
  return head && head.length <= 200 ? head : undefined;
}

function reduce(error: unknown, depth: number, seen: Set<unknown>): SafeDatabaseError {
  if (error instanceof SafeDatabaseError) return error;
  seen.add(error);
  const kept: Kept = {};
  const code = read(error, 'code');
  if (typeof code === 'string' && CODE.test(code)) kept.code = code;
  for (const key of NAMES) {
    const value = read(error, key);
    if (typeof value === 'string' && NAME.test(value)) kept[key] = value;
  }
  const errorClass = errorClassName(error);
  const message = messageBeforeStatement(error) ?? `Database error${kept.code ? ` ${kept.code}` : ''}`;
  const next = read(error, 'cause');
  const cause = next !== undefined && next !== null && depth < MAX_CAUSES && !seen.has(next) ? reduce(next, depth + 1, seen) : undefined;
  return new SafeDatabaseError(errorClass, message, kept, cause);
}

/**
 * The error, and each error in its `cause` chain, reduced to class name, SQLSTATE code and constraint, table, column and
 * schema names. The statement, its parameters, `detail`, `hint`, `where` and the server message are dropped; a
 * statement wrapper's message is cut before the statement ("Failed query"). The original is not attached.
 * Never throws; a value that is already a SafeDatabaseError is returned as it is.
 */
export function safeDatabaseError(error: unknown): SafeDatabaseError {
  try {
    return reduce(error, 0, new Set());
  } catch {
    return new SafeDatabaseError('Error', 'Database error', {});
  }
}
