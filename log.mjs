const SEVERITY = { debug: 10, info: 20, warn: 30, error: 40 };
const CORE = new Set(['time', 'level', 'service', 'message', 'requestId']);
/**
 * Field names are split into lowercase segments at case changes and separators (`sessionId` → session, id;
 * `x-api-key` → x, api, key; `DATABASE_URL` → database, url). A name is secret when its LAST segment is a secret
 * word, or when two adjacent segments form a secret pair, so `accessToken`, `apiKey`, `sessionId` and `databaseUrl`
 * are redacted while `tokenCount`, `keyword`, `authorId` and `otpEnabled` are not. Deliberate choices: `tokens`
 * (usually a list of tokens) and any name ending in `key`, `primaryKey` included, are redacted, because a name cannot
 * tell an id key from a secret key.
 */
const SECRET_WORDS = new Set(['password', 'passwords', 'passwd', 'pass', 'pwd', 'passphrase', 'secret', 'secrets', 'token', 'tokens', 'auth',
    'authorization', 'cookie', 'cookies', 'key', 'keys', 'apikey', 'credential', 'credentials', 'session', 'sid', 'jwt', 'bearer', 'signature',
    'otp', 'dsn', 'cvv', 'mnemonic', 'seed', 'psk', 'csrf', 'hmac', 'salt']);
const SECRET_PAIRS = new Set(['session id', 'session token', 'database url', 'connection string', 'card number', 'private key', 'secret key',
    'access key', 'api key', 'cookie header', 'auth header', 'authorization header', 'set cookie']);
const segments = (name) => name.replace(/([a-z0-9])([A-Z])/gu, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/gu, '$1 $2')
    .split(/[-_.\s]+/u).filter(Boolean).map(part => part.toLowerCase());
const secretName = (name) => {
    const parts = segments(name);
    if (!parts.length)
        return false;
    if (SECRET_WORDS.has(parts.at(-1)))
        return true;
    for (let i = 1; i < parts.length; i++)
        if (SECRET_PAIRS.has(`${parts[i - 1]} ${parts[i]}`))
            return true;
    return false;
};
// Strings are scanned and written up to this many characters; a longer one ends with a truncation marker.
const MAX_STRING = 8192;
const SCHEME_CHARACTER = /[a-z0-9+.-]/iu;
/**
 * Removes credentials embedded in URLs, whatever the field is called, in time linear in the string. For each `://`
 * preceded by a scheme (a letter, then letters, digits, `+`, `.`, `-`, at most 32 characters), everything from `//` to
 * the LAST `@` within the next 256 characters (stopping at a line break or the next `://`) is replaced. Taking the last
 * `@` catches a password that itself holds `@`, a space or `/`; it over-redacts a URL with an `@` in its path.
 */
function withoutUrlCredentials(text) {
    let out = '', from = 0;
    for (let at = text.indexOf('://'); at !== -1; at = text.indexOf('://', at + 3)) {
        let start = at;
        while (start > 0 && at - start < 32 && SCHEME_CHARACTER.test(text[start - 1]))
            start--;
        // No scheme, or a `://` inside a span already redacted.
        if (start === at || !/[a-z]/iu.test(text[start]) || at < from)
            continue;
        const next = text.indexOf('://', at + 3), limit = Math.min(text.length, at + 3 + 256, next === -1 ? Infinity : next);
        let end = -1;
        for (let i = at + 3; i < limit; i++) {
            if (text[i] === '\n' || text[i] === '\r')
                break;
            if (text[i] === '@')
                end = i;
        }
        if (end === -1)
            continue;
        out += `${text.slice(from, at + 3)}[redacted]`;
        from = end;
    }
    return from === 0 ? text : out + text.slice(from);
}
const safeString = (value) => {
    // Scan a bounded prefix (a credential span is at most 256 characters past its `://`), then cut it to length.
    const scanned = withoutUrlCredentials(value.length > MAX_STRING + 300 ? value.slice(0, MAX_STRING + 300) : value);
    return scanned.length > MAX_STRING ? `${scanned.slice(0, MAX_STRING)}…[truncated ${value.length - MAX_STRING} characters]` : scanned;
};
const REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/u;
function record(level, service, message, fields) {
    const line = { time: new Date().toISOString(), level, service, message };
    if (fields.requestId !== undefined)
        line.requestId = fields.requestId;
    // The core names above always describe the call; a field with one of those names is not written.
    for (const [name, value] of Object.entries(fields))
        if (!CORE.has(name))
            line[name] = value;
    return line;
}
// Applied at every depth, so a secret inside a nested object (a headers map) is redacted too.
function replacer(name, value) {
    if (name && secretName(name))
        return '[redacted]';
    // JSON.stringify passes the returned object's strings back through here, so their URL credentials are removed too.
    if (value instanceof Error)
        return { name: value.name, message: value.message, stack: value.stack };
    if (typeof value === 'bigint')
        return value.toString();
    if (typeof value === 'string')
        return safeString(value);
    return value;
}
// The line's core alone, for when the fields cannot be read or serialised: String() keeps it serialisable, and a
// request id is kept only when it is a plain string.
const coreLine = (level, service, message, requestId, reason) => `${JSON.stringify({ time: new Date().toISOString(), level, service: String(service), message: String(message),
    ...(typeof requestId === 'string' ? { requestId } : {}), logError: reason }, replacer)}\n`;
function serialise(line) {
    try {
        return `${JSON.stringify(line, replacer)}\n`;
    }
    catch {
        // A circular or unserialisable field must not turn a log call into a thrown error; keep the line's core.
        return coreLine(line.level, line.service, line.message, line.requestId, 'fields could not be serialised');
    }
}
/**
 * A logger never throws: a field getter that throws, an unserialisable value or a failing `write` costs at most that
 * line's fields (or the line), never the caller's request.
 */
export function createLogger({ service, level = 'info', write = line => { process.stdout.write(line); } }) {
    if (!Object.hasOwn(SEVERITY, level))
        throw new TypeError(`Unknown log level: ${String(level)}`);
    const threshold = SEVERITY[level];
    const safeWrite = (line) => { try {
        write(line);
    }
    catch { /* a failing sink drops the line */ } };
    const make = (bound) => {
        const emit = (at) => (message, fields = {}) => {
            if (SEVERITY[at] < threshold)
                return;
            let line;
            try {
                line = serialise(record(at, service, message, { ...bound, ...fields }));
            }
            catch {
                try {
                    line = coreLine(at, service, message, undefined, 'fields could not be read');
                }
                catch {
                    return;
                }
            }
            safeWrite(line);
        };
        const child = (fields) => {
            try {
                return make({ ...bound, ...fields });
            }
            catch {
                return make(bound);
            }
        };
        return { debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error'), child };
    };
    return make({});
}
/** The caller's x-request-id when it is a plain 8–128 character token, otherwise a new UUID. */
export function requestId(request) {
    const incoming = request.headers.get('x-request-id');
    return incoming !== null && REQUEST_ID.test(incoming) ? incoming : crypto.randomUUID();
}
