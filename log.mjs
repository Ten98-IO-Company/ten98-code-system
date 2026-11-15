const SEVERITY = { debug: 10, info: 20, warn: 30, error: 40 };
const CORE = new Set(['time', 'level', 'service', 'message', 'requestId']);
const REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/u;
// Every bound has a marker, so a cut never passes silently.
const MAX_KEY = 256, MAX_STRING = 8192, MAX_DEPTH = 8, MAX_FIELDS = 200, MAX_LINE = 65_536;
/**
 * Names fail closed. A field is redacted when its normalised name (cut to 256 characters, accents removed,
 * lowercased, `-`, `_`, `.` and whitespace dropped) contains any secret fragment, unless the exact normalised name is
 * on the harmless list (the defaults below plus the logger's `allow`). So `PGPASSWORD`, `password_confirmation`,
 * `apiKey2` and `JSESSIONID` are redacted, while `keyword` and `tokenCount` are written. `tokens` and `primaryKey` are
 * redacted deliberately: a name cannot tell a list of tokens or an id key from a secret.
 */
const SECRET_FRAGMENTS = ['pass', 'pwd', 'secret', 'token', 'auth', 'cookie', 'key', 'credential', 'session', 'sessid', 'jwt', 'bearer',
    'signature', 'otp', 'dsn', 'databaseurl', 'connectionstring', 'private', 'cvv', 'cardnumber', 'creditcard', 'mnemonic', 'seed', 'psk',
    'csrf', 'hmac', 'salt', 'recoverycode', 'resetlink', 'magiclink', 'stripesk', 'пароль'];
const SECRET_EXACT = new Set(['sid', 'sk']);
const HARMLESS = ['author', 'authorid', 'authors', 'authorname', 'authority', 'passed', 'bypass', 'compass', 'keyboard', 'monkey',
    'sessioncount', 'tokencount', 'otpenabled', 'signaturevalid', 'isprivate', 'keyset', 'keyword', 'keywords', 'turkey', 'hotpath',
    'passengercount', 'authenticated', 'footprint'];
// Names an app can never allow: any name containing one of these is a secret whatever the app says.
const NEVER_ALLOW = ['password', 'passwd', 'passphrase', 'secret', 'apikey', 'accesstoken', 'refreshtoken', 'authtoken', 'sessionid',
    'sessid', 'cookie', 'authorization', 'bearer', 'jwt', 'dsn', 'connectionstring', 'databaseurl', 'privatekey', 'secretkey', 'cvv',
    'cardnumber', 'creditcard', 'mnemonic', 'hmac', 'пароль'];
function normalise(name) {
    const capped = name.length > MAX_KEY ? name.slice(0, MAX_KEY) : name;
    let out = '';
    for (const character of capped.normalize('NFKD').toLowerCase()) {
        if (character === '-' || character === '_' || character === '.' || /\s|\p{M}/u.test(character))
            continue;
        out += character;
    }
    return out;
}
const containsAny = (text, fragments) => fragments.some(fragment => text.includes(fragment));
const isSecretName = (name, harmless) => {
    const plain = normalise(name);
    if (SECRET_EXACT.has(plain))
        return true;
    return !harmless.has(plain) && containsAny(plain, SECRET_FRAGMENTS);
};
const writtenKey = (name) => (name.length > MAX_KEY ? `${name.slice(0, MAX_KEY)}…` : name);
const isSchemeCharacter = (code) => (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57) || code === 43 || code === 45 || code === 46;
const isLetter = (code) => (code >= 97 && code <= 122) || (code >= 65 && code <= 90);
// Characters that end a URL authority (the part between `://` and the path).
const AUTHORITY_END = new Set(['/', '?', '#', '"', "'", '<', '>', '\\', '`']);
/**
 * Removes the userinfo of URL authorities, in time linear in the string. For each `://` preceded by a scheme (a
 * letter, then letters, digits, `+`, `.`, `-`, at most 32 characters), the authority runs to the first `/`, `?`, `#`,
 * quote, angle bracket, backslash or whitespace, or the next `://`; everything from `//` to the LAST `@` inside it is
 * replaced. Paths, scoped package URLs, stack frames and a following email address stay as they were. When the string
 * was cut (`truncated`) and an authority runs to the cut, it is redacted whole, since its `@` may lie beyond.
 */
function withoutUrlCredentials(text, truncated) {
    let out = '', from = 0;
    for (let at = text.indexOf('://'); at !== -1; at = text.indexOf('://', at + 3)) {
        if (at < from)
            continue;
        let start = at;
        while (start > 0 && at - start < 32 && isSchemeCharacter(text.charCodeAt(start - 1)))
            start--;
        if (start === at || !isLetter(text.charCodeAt(start)))
            continue;
        let end = -1, i = at + 3;
        for (; i < text.length; i++) {
            const character = text[i];
            if (AUTHORITY_END.has(character) || character.trim() === '' || (character === ':' && text.startsWith('//', i + 1)))
                break;
            if (character === '@')
                end = i;
        }
        if (i === text.length && truncated) {
            out += `${text.slice(from, at + 3)}[redacted]`;
            from = text.length;
            break;
        }
        if (end === -1)
            continue;
        out += `${text.slice(from, at + 3)}[redacted]`;
        from = end;
    }
    return from === 0 ? text : out + text.slice(from);
}
const safeString = (value) => {
    if (value.length <= MAX_STRING)
        return withoutUrlCredentials(value, false);
    return `${withoutUrlCredentials(value.slice(0, MAX_STRING), true)}…[truncated ${value.length - MAX_STRING} characters]`;
};
const charge = (budget, text) => { budget.left -= text.length; return text; };
/**
 * Builds the plain value that is written, within the bounds: strings scanned and cut, names redacted, at most
 * MAX_DEPTH levels and MAX_FIELDS fields or items per object, and about MAX_LINE characters for the whole line, each
 * cut marked. A getter that throws propagates to the caller, which writes the line's core instead.
 */
function sanitise(value, harmless, depth, seen, budget) {
    if (budget.left <= 0)
        return '[line limit]';
    if (typeof value === 'string')
        return charge(budget, safeString(value));
    if (typeof value === 'bigint')
        return charge(budget, value.toString());
    if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
        budget.left -= 8;
        return value;
    }
    if (typeof value !== 'object')
        return undefined;
    if (value instanceof String)
        return charge(budget, safeString(value.valueOf()));
    if (depth >= MAX_DEPTH)
        return charge(budget, '[depth limit]');
    if (seen.has(value))
        return charge(budget, '[circular]');
    seen.add(value);
    try {
        if (value instanceof Error) {
            return { name: sanitise(value.name, harmless, depth + 1, seen, budget), message: sanitise(value.message, harmless, depth + 1, seen, budget),
                stack: sanitise(value.stack, harmless, depth + 1, seen, budget) };
        }
        if (value instanceof Date)
            return Number.isNaN(value.getTime()) ? null : charge(budget, value.toISOString());
        const toJSON = value.toJSON;
        if (typeof toJSON === 'function')
            return sanitise(toJSON.call(value), harmless, depth + 1, seen, budget);
        if (Array.isArray(value)) {
            const out = [], length = Math.min(value.length, MAX_FIELDS);
            for (let i = 0; i < length && budget.left > 0; i++)
                out.push(sanitise(value[i], harmless, depth + 1, seen, budget) ?? null);
            if (out.length < value.length)
                out.push(`…[${value.length - out.length} more items]`);
            return out;
        }
        const keys = Object.keys(value), out = {};
        let written = 0;
        for (; written < keys.length && written < MAX_FIELDS && budget.left > 0; written++) {
            const key = keys[written], name = charge(budget, writtenKey(key));
            const item = isSecretName(key, harmless) ? '[redacted]' : sanitise(value[key], harmless, depth + 1, seen, budget);
            if (item !== undefined)
                out[name] = item;
        }
        if (written < keys.length)
            out['…'] = `${keys.length - written} more fields`;
        return out;
    }
    finally {
        seen.delete(value);
    }
}
function record(level, service, message, fields, harmless) {
    const budget = { left: MAX_LINE }, seen = new Set();
    const line = { time: new Date().toISOString(), level, service: safeString(String(service)), message: charge(budget, safeString(String(message))) };
    const id = sanitise(fields.requestId, harmless, 1, seen, budget);
    if (id !== undefined)
        line.requestId = id;
    const rest = sanitise(Object.fromEntries(Object.entries(fields).filter(([name]) => !CORE.has(name))), harmless, 0, seen, budget);
    const text = JSON.stringify({ ...line, ...rest });
    // The budget keeps a line near MAX_LINE; a line far over it (many small values) is replaced by its core.
    return text.length > MAX_LINE * 2 ? coreLine(level, service, message, id, 'line too large') : `${text}\n`;
}
// The line's core alone, for when the fields cannot be read: a request id is kept only when it is a plain string.
const coreLine = (level, service, message, requestId, reason) => `${JSON.stringify({ time: new Date().toISOString(), level, service: safeString(String(service)), message: safeString(String(message)),
    ...(typeof requestId === 'string' ? { requestId: safeString(requestId) } : {}), logError: reason })}\n`;
/**
 * A logger never throws: a field getter that throws, an unserialisable value or a failing `write` costs at most that
 * line's fields (or the line), never the caller's request. A message whose `toString` throws writes no line.
 */
export function createLogger({ service, level = 'info', write = line => { process.stdout.write(line); }, allow = [] }) {
    if (!Object.hasOwn(SEVERITY, level))
        throw new TypeError(`Unknown log level: ${String(level)}`);
    const harmless = new Set(HARMLESS);
    for (const name of allow) {
        const plain = typeof name === 'string' ? normalise(name) : '';
        if (!plain || SECRET_EXACT.has(plain) || SECRET_FRAGMENTS.includes(plain) || containsAny(plain, NEVER_ALLOW)) {
            throw new TypeError(`The log allow list cannot include ${JSON.stringify(String(name)).slice(0, 80)}: it names a secret.`);
        }
        harmless.add(plain);
    }
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
                line = record(at, service, message, { ...bound, ...fields }, harmless);
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
