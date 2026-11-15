// The Ten98 identity preset on better-auth, promoted from Discover src/server/auth.ts (dev, 2026-10-25) per decision #7/#97.
// It fixes the shared policy (passwords, sessions, two-factor, reset, error redaction) in one place. Each app supplies its
// database adapter, its URL and secret, its reset-email capture, and keeps its routes, transactions, rate limiters,
// first-boot claim, OIDC protocol and workspace authorization. better-auth, drizzle-orm and pg are exact, optional peers.
//
// Tokens at rest (#131): session tokens and verification identifiers are stored as HMACs under keys derived from the
// secret, so reading the database yields no live session or reset link. Locked auth (#132): `withLockedAuth` runs
// better-auth on one transaction that holds the user row, so a password change and a sign-in or revocation cannot
// interleave.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, createHmac, hkdfSync, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { and, eq, getTableName, sql } from 'drizzle-orm';
import { NodePgSession, NodePgTransaction } from 'drizzle-orm/node-postgres';
import { PgTransaction } from 'drizzle-orm/pg-core';
import { betterAuth, getCurrentAdapter } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx, isAPIError, sensitiveSessionMiddleware } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { account as accountTable, transaction, TransactionRolledBackError, user as userTable } from './db.mjs';
import { appOrigin } from './index.mjs';
import { LockedAuthTransactionError, markLockedAuth, refuseLockedAuth } from './locked-auth.mjs';
export { LockedAuthTransactionError } from './locked-auth.mjs';
/** The shared identity policy. Apps read it for forms and route limiters, so the numbers never drift between them. */
export const ten98AuthPolicy = Object.freeze({
    password: Object.freeze({ minLength: 12, maxLength: 128 }),
    /** Seven days, extended at most once a day of use. */
    session: Object.freeze({ expiresInSeconds: 604_800, updateAgeSeconds: 86_400 }),
    /**
     * TOTP (RFC 6238, SHA-1). `replaySeconds` is the window in which an accepted code is refused again; the app keeps that
     * ledger. Recovery codes are `backupCodes` codes matching `backupCodePattern` (a string, so it survives JSON), each
     * `backupCodeInputLength` characters as typed, with the hyphen.
     * The lockout counts failures during sign-in challenges only; session-bound step-up checks are limited per user by the
     * app (`rateLimits.accountSecurityWritesPerUser`).
     */
    twoFactor: Object.freeze({ digits: 6, periodSeconds: 30, replaySeconds: 90, backupCodes: 10, backupCodePattern: '^[A-Za-z0-9]{5}-[A-Za-z0-9]{15}$', backupCodeInputLength: 21, maxFailedAttempts: 10, lockoutSeconds: 900 }),
    reset: Object.freeze({ expiresInSeconds: 3600, revokesSessions: true }),
    /**
     * Counts per `windowSeconds` for each app's route limiter. better-auth's own limiter stays off because it cannot see
     * the trusted client address; apps key these with clientLimitKey (per client) or the email, token or user.
     */
    rateLimits: Object.freeze({
        windowSeconds: 60, signInPerClient: 60, signInPerEmail: 5, twoFactorPerClient: 60, twoFactorPerChallenge: 10,
        resetRequestPerClient: 20, resetRequestPerEmail: 3, resetPerClient: 60, resetPerToken: 5,
        accountSecurityReadsPerUser: 120, accountSecurityWritesPerUser: 30,
    }),
});
// Campaign's stored format (server/auth.ts hashPassword): scrypt$<salt>$<key>, where the salt is 32 hex characters passed
// to scrypt as that text (not decoded), the key is 64 bytes in hex, N=65536 with the default r=8, p=1, and no normalization.
const LEGACY_SCRYPT = /^scrypt\$([0-9a-f]{32})\$([0-9a-f]{128})$/;
const isLegacyHash = (hash) => LEGACY_SCRYPT.test(hash);
const DUMMY_LEGACY_HASH = `scrypt$${'0'.repeat(32)}$${'0'.repeat(128)}`;
/** Verifies a Campaign `scrypt$salt$key` hash; any other format is not legacy and returns false. */
export function verifyLegacyScryptHash(hash, password) {
    const match = LEGACY_SCRYPT.exec(hash);
    if (!match)
        return Promise.resolve(false);
    const expected = Buffer.from(match[2], 'hex');
    return new Promise(resolve => scrypt(password, match[1], expected.length, { N: 65_536, maxmem: 128 * 1024 * 1024 }, (error, derived) => {
        resolve(!error && derived.length === expected.length && timingSafeEqual(derived, expected));
    }));
}
// Keys for tokens at rest: HKDF-SHA256 over the secret, one label per use, so neither equals the secret or any other key
// an app derives from it. Rotating the secret ends every session, reset link and trusted device, and makes enrolled
// second factors (encrypted with the secret itself) unreadable: it is a re-enrolment event.
const keyLabels = { verification: 'ten98-auth:verification-identifier:v1', session: 'ten98-auth:session-token:v1', knownDevice: 'ten98-auth:known-device:v1' };
const checkedSecret = (secret) => {
    if (typeof secret !== 'string' || secret.length < 32)
        throw new TypeError('The auth secret must be at least 32 characters.');
    return secret;
};
const deriveKeys = (secret) => ({
    verification: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.verification, 32)),
    session: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.session, 32)),
    knownDevice: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.knownDevice, 32)),
});
const mac = (key, value) => createHmac('sha256', key).update(value).digest('base64url');
const raw = (value) => {
    if (typeof value !== 'string')
        throw new TypeError('A token or identifier must be a string.');
    return value;
};
/** Stored session tokens and whole-hashed identifiers start with this; better-auth's raw tokens are alphanumeric. */
const handlePrefix = 'v1.';
const isHandle = (value) => typeof value === 'string' && value.startsWith(handlePrefix);
const tokenHandle = (keys, token) => handlePrefix + mac(keys.session, token);
// The kept prefixes, longest first where they overlap. An attempt counter names its challenge, so its tail is stored
// with this same rule and the stored counter is exactly '2fa-attempts-' || <stored challenge identifier>.
const attemptsPrefix = '2fa-attempts-';
const keptPrefixes = ['2fa-otp-', '2fa-', 'trust-device-', 'reset-password:', 'known-device-attempt:', 'known-device:'];
function storedIdentifier(keys, identifier) {
    let head = '', rest = identifier;
    while (rest.startsWith(attemptsPrefix)) {
        head += attemptsPrefix;
        rest = rest.slice(attemptsPrefix.length);
    }
    const prefix = keptPrefixes.find(candidate => rest.startsWith(candidate));
    return head + (prefix ? prefix + mac(keys.verification, rest.slice(prefix.length)) : handlePrefix + mac(keys.verification, rest));
}
// Known devices (#132): a browser that completed a sign-in for an account, so `signInWithPassword` can tell the app's
// limiter to spare it the account-wide bucket. Each is a verification row `known-device:<deviceId>` (value: the user id,
// expiresAt: its 90 days) with one `known-device-attempt:<deviceId>` row per attempt it was trusted for since its last
// success; at 5 it is no longer trusted. Both prefixes are kept in storage, so a user's rows go with one prefix filter.
const device = { cookie: 'known_device', lifetimeSeconds: 90 * 86_400, attempts: 5, entries: 5, cookieLength: 1024 };
const devicePrefix = 'known-device', deviceRow = (deviceId) => `known-device:${deviceId}`, attemptRow = (deviceId) => `known-device-attempt:${deviceId}`;
const deviceEntryPattern = /^([A-Za-z0-9_-]{32})\.([A-Za-z0-9_-]{43})$/;
/** The tag binding a device id to one account: HMAC over userId ‖ deviceId (NUL-separated; neither contains NUL). */
const deviceTag = (keys, userId, deviceId) => mac(keys.knownDevice, `${userId}\u0000${deviceId}`);
/**
 * The cookie's entries, one per account this browser signed in to, newest first and at most `device.entries`. A missing,
 * oversized or malformed value, or a malformed entry, is ignored, never an error.
 */
function deviceEntries(value) {
    if (typeof value !== 'string' || value.length > device.cookieLength)
        return [];
    return value.split('~').slice(0, device.entries).flatMap(text => {
        const match = deviceEntryPattern.exec(text);
        return match ? [{ deviceId: match[1], tag: match[2], text }] : [];
    });
}
/** The entry whose tag verifies for `userId`, compared in constant time; undefined when none does. */
function deviceFor(keys, userId, entries) {
    let found;
    for (const entry of entries) {
        if (timingSafeEqual(Buffer.from(entry.tag), Buffer.from(deviceTag(keys, userId, entry.deviceId))) && !found)
            found = entry;
    }
    return found;
}
/** One cookie from a Cookie header; undefined when absent. */
function cookieFrom(headers, name) {
    const header = headers === undefined ? null : new Headers(headers).get('cookie');
    for (const pair of header?.split(';') ?? []) {
        const at = pair.indexOf('=');
        if (at > 0 && pair.slice(0, at).trim() === name)
            return pair.slice(at + 1).trim();
    }
    return undefined;
}
/**
 * The `verification.identifier` the preset stores for a raw identifier, for an app that locks or reads the row with its
 * own SQL. Prefer the instance method, which needs no secret.
 */
export function storedVerificationIdentifier(secret, identifier) {
    return storedIdentifier(deriveKeys(checkedSecret(secret)), raw(identifier));
}
/**
 * The `session.token` the preset stores (a `v1.` handle) for a raw session token, the cookie's value without its
 * signature. For an app's own read of session liveness; prefer the instance method, which needs no secret.
 */
export function sessionTokenKey(secret, token) {
    return tokenHandle(deriveKeys(checkedSecret(secret)), raw(token));
}
/**
 * The statements every app's numbered migration runs once when it adopts hashed token storage, separated as drizzle-kit
 * separates statements. Rows stored in plain text before it would never match again: every session ends, and reset
 * links, trusted devices and pending two-factor challenges (with their `2fa-otp-` and `2fa-attempts-` rows) go with them.
 * Rows an app writes with its own SQL are its own decision.
 */
export const tokenStorageUpgradeStatements = [
    'DELETE FROM "session";',
    'DELETE FROM verification WHERE identifier LIKE \'reset-password:%\' OR identifier LIKE \'trust-device-%\' OR identifier LIKE \'2fa-%\';',
].join('\n--> statement-breakpoint\n');
// The adapter methods better-auth 1.7.7 defines. Any other function is refused rather than left unwrapped.
const adapterMethods = new Set(['create', 'findOne', 'findMany', 'count', 'update', 'updateMany', 'delete', 'deleteMany', 'consumeOne', 'incrementOne', 'transaction', 'createSchema']);
const fullValueOperators = new Set(['eq', 'ne', 'in', 'not_in']);
/**
 * Wraps the app's adapter so `session.token` and `verification.identifier` are stored as HMACs. Session reads always
 * hash what they are given (a stored handle given back as a token matches nothing) and return the caller's raw token;
 * updates and deletes pass a handle through; listings return handles. Verification identifiers follow
 * `storedIdentifier`; prefix filters (`starts_with`) pass through, as the prefixes are kept.
 *
 * Identifiers are hashed here, not through better-auth's `verification.storeIdentifier`: in 1.7.7 a lookup under that
 * option that finds nothing retries with the raw identifier (internal-adapter.mjs, findVerificationValue and
 * consumeVerificationValue), so a database reader could redeem a stored reset row by sending its stored tail as the token.
 */
function protectTokens(factory, keys) {
    const clause = (model, item, write, restore) => {
        const operator = item.operator ?? 'eq';
        if (model === 'session' && item.field === 'token') {
            if (!fullValueOperators.has(operator))
                throw new TypeError(`Session tokens are stored hashed and cannot be matched with ${operator}.`);
            const one = (value) => {
                if (typeof value !== 'string' || (write && isHandle(value)))
                    return value;
                const handle = tokenHandle(keys, value);
                restore.set(handle, value);
                return handle;
            };
            return { ...item, value: Array.isArray(item.value) ? item.value.map(one) : one(item.value) };
        }
        if (model === 'verification' && item.field === 'identifier' && fullValueOperators.has(operator)) {
            const one = (value) => typeof value === 'string' ? storedIdentifier(keys, value) : value;
            return { ...item, value: Array.isArray(item.value) ? item.value.map(one) : one(item.value) };
        }
        return item;
    };
    const where = (query, write, restore) => query.where?.map(item => clause(query.model, item, write, restore));
    const data = (model, values, restore) => {
        if (!values)
            return values;
        if (model === 'session' && typeof values.token === 'string' && !isHandle(values.token)) {
            const handle = tokenHandle(keys, values.token);
            restore.set(handle, values.token);
            return { ...values, token: handle };
        }
        if (model === 'verification' && typeof values.identifier === 'string')
            return { ...values, identifier: storedIdentifier(keys, values.identifier) };
        return values;
    };
    const back = (row, restore) => row && typeof row.token === 'string' && restore.has(row.token) ? { ...row, token: restore.get(row.token) } : row;
    const wrap = (adapter) => {
        const unknown = Object.entries(adapter).filter(([name, value]) => typeof value === 'function' && !adapterMethods.has(name)).map(([name]) => name);
        if (unknown.length)
            throw new TypeError(`The token storage wrapper does not know the adapter method(s) ${unknown.join(', ')}; review it before upgrading better-auth.`);
        const call = (name, query) => adapter[name](query);
        // `write`: an update or delete, where a stored handle passes through. `values`: the field holding row values.
        const method = (name, write, values) => async (query) => {
            const restore = new Map();
            const result = await call(name, { ...query, where: where(query, write, restore), ...values ? { [values]: data(query.model, query[values], restore) } : {} });
            return Array.isArray(result) ? result.map(row => back(row, restore)) : back(result, restore);
        };
        const wrapped = {
            ...adapter,
            create: method('create', true, 'data'),
            findOne: method('findOne', false),
            findMany: method('findMany', false),
            count: method('count', false),
            update: method('update', true, 'update'),
            updateMany: method('updateMany', true, 'update'),
            delete: method('delete', true),
            deleteMany: method('deleteMany', true),
        };
        if (typeof adapter.consumeOne === 'function')
            wrapped.consumeOne = method('consumeOne', true);
        if (typeof adapter.incrementOne === 'function')
            wrapped.incrementOne = method('incrementOne', true, 'set');
        if (typeof adapter.transaction === 'function') {
            const run = adapter.transaction;
            wrapped.transaction = (callback) => run(trx => callback(wrap(trx)));
        }
        return wrapped;
    };
    return options => wrap(factory(options));
}
/** The user `withLockedAuth` was asked to lock does not exist; answer it as not found. */
export class LockedAuthUserNotFoundError extends Error {
    status = 404;
    code = 'USER_NOT_FOUND';
    constructor() { super('User not found.'); this.name = 'LockedAuthUserNotFoundError'; }
}
/**
 * A locked-auth instance or transaction was used after its callback returned (an un-awaited call, say), or a second
 * locked-auth transaction was opened inside one. Either would run outside, or wait on, the lock: a programming error.
 */
export class LockedAuthClosedError extends Error {
    code = 'LOCKED_AUTH_CLOSED';
    constructor(message = 'This locked-auth transaction has ended; await every call inside its callback.') { super(message); this.name = 'LockedAuthClosedError'; }
}
const storeOf = (auth) => auth.$context;
/** Deletes every known-device and attempt row of a user, so no browser of theirs stays trusted. */
const forgetDevices = (adapter, userId) => adapter.deleteMany({ model: 'verification', where: [{ field: 'value', value: userId }, { field: 'identifier', operator: 'starts_with', value: devicePrefix }] });
const INT32 = 2 ** 31;
/**
 * A better-auth instance with the Ten98 policy. Sign-up stays closed: the first-boot claim creates the owner in the
 * app's own transaction (hash with `hashPassword` from 'better-auth/crypto') and then signs in. Origin and CSRF checks
 * are pinned on, so no environment variable can turn them off. Session tokens and verification identifiers are stored
 * as keyed hashes; the cookie cache stays off and no secondary storage is used, so no token is kept anywhere else.
 */
export function createTen98Auth(options) {
    return build(options, deriveKeys(checkedSecret(options.secret)), true);
}
function build(options, keys, locking, internal = {}) {
    const { database, appUrl, secret, appName, sendResetPassword, legacyPasswords = false, allowPasswordless = false, cookiePrefix, transactionDatabase, emailLockKey = 109_859 } = options;
    const origin = appOrigin(appUrl);
    checkedSecret(secret);
    if (typeof appName !== 'string' || !appName.trim())
        throw new TypeError('appName is required.');
    if (typeof database !== 'function')
        throw new TypeError('database must be a better-auth adapter factory, such as drizzleAdapter(db, { provider: \'pg\', schema }), so tokens can be stored hashed.');
    if (transactionDatabase !== undefined && typeof transactionDatabase !== 'function')
        throw new TypeError('transactionDatabase must be a function of the transaction.');
    if (!Number.isInteger(emailLockKey) || emailLockKey < -INT32 || emailLockKey >= INT32)
        throw new TypeError('emailLockKey must be a 32-bit integer.');
    const prefix = cookiePrefix ?? `ten98-${createHash('sha256').update(origin).digest('hex').slice(0, 16)}`;
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(prefix))
        throw new TypeError('cookiePrefix must be 1 to 64 letters, digits, hyphens or underscores.');
    const { twoFactor: factor, password, session, reset } = ten98AuthPolicy;
    const factors = twoFactor({
        issuer: appName,
        allowPasswordless,
        totpOptions: { digits: factor.digits, period: factor.periodSeconds },
        backupCodeOptions: { amount: factor.backupCodes, length: 20 },
        accountLockout: { enabled: true, maxFailedAttempts: factor.maxFailedAttempts, durationSeconds: factor.lockoutSeconds },
    });
    // completeOidcSession goes through the plugin's sign-in challenge: it is server-only, so no browser can submit a user ID.
    for (const hook of factors.hooks.after) {
        const original = hook.matcher;
        hook.matcher = context => original(context) || (context.path === undefined && typeof context.body?.oidcUserId === 'string');
    }
    const verifiedUser = async (context, field) => {
        const userId = context.body?.[field];
        if (typeof userId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(userId))
            throw APIError.fromStatus('BAD_REQUEST');
        const user = await context.context.internalAdapter.findUserById(userId);
        if (!user)
            throw APIError.fromStatus('UNAUTHORIZED');
        return user;
    };
    const issue = async (context, user) => {
        const created = await context.context.internalAdapter.createSession(user.id, false);
        if (!created)
            throw APIError.fromStatus('INTERNAL_SERVER_ERROR');
        await setSessionCookie(context, { user, session: created });
        return context.json({ ok: true });
    };
    const oidcSessions = {
        id: 'ten98-oidc-session',
        endpoints: {
            rotateVerifiedSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async (context) => {
                const user = await verifiedUser(context, 'verifiedUserId');
                // Only the account's own current session can be rotated; this never signs anyone in.
                const current = await getSessionFromCtx(context);
                if (!current || current.user.id !== user.id)
                    throw APIError.fromStatus('UNAUTHORIZED');
                const response = await issue(context, user);
                await context.context.internalAdapter.deleteSession(current.session.token);
                return response;
            }),
            completeOidcSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async (context) => issue(context, await verifiedUser(context, 'oidcUserId'))),
        },
    };
    // Replaces better-auth's /revoke-other-sessions (a plugin endpoint of the same name wins), which compares the caller's
    // raw token with the listed handles. This one keeps the current session by id and deletes the user's other live
    // sessions through the adapter, so inside withLockedAuth it runs in that transaction.
    const sessionRevocation = {
        id: 'ten98-session-revocation',
        endpoints: {
            revokeOtherSessions: createAuthEndpoint('/revoke-other-sessions', { method: 'POST', requireHeaders: true, use: [sensitiveSessionMiddleware] }, async (context) => {
                const current = context.context.session.session;
                const adapter = await getCurrentAdapter(context.context.adapter);
                const revoked = await adapter.deleteMany({ model: 'session', where: [
                        { field: 'userId', value: current.userId },
                        { field: 'id', operator: 'ne', value: current.id },
                        { field: 'expiresAt', operator: 'gt', value: new Date() },
                    ] });
                await forgetDevices(adapter, current.userId);
                return context.json({ status: true, revoked });
            }),
        },
    };
    const issueDevice = async (context, userId) => {
        const cookie = context.context.createAuthCookie(device.cookie, { maxAge: device.lifetimeSeconds });
        const entries = deviceEntries(context.getCookie(cookie.name));
        const previous = deviceFor(keys, userId, entries);
        const adapter = await getCurrentAdapter(context.context.adapter);
        if (previous) {
            for (const identifier of [deviceRow(previous.deviceId), attemptRow(previous.deviceId)]) {
                await adapter.deleteMany({ model: 'verification', where: [{ field: 'identifier', value: identifier }, { field: 'value', value: userId }] });
            }
        }
        const deviceId = randomBytes(24).toString('base64url');
        await context.context.internalAdapter.createVerificationValue({ identifier: deviceRow(deviceId), value: userId, expiresAt: new Date(Date.now() + device.lifetimeSeconds * 1000) });
        const kept = entries.filter(entry => entry !== previous).map(entry => entry.text);
        context.setCookie(cookie.name, [`${deviceId}.${deviceTag(keys, userId, deviceId)}`, ...kept].slice(0, device.entries).join('~'), cookie.attributes);
    };
    // After the two-factor plugin's hook, which clears newSession while a second factor is still pending, so only a
    // completed sign-in (password, second factor, or the app's OIDC sign-in) issues an entry, and no other response does.
    const signInPaths = new Set(['/sign-in/email', '/two-factor/verify-totp', '/two-factor/verify-backup-code', '/two-factor/verify-otp']);
    const revokingPaths = new Set(['/change-password', '/revoke-sessions']);
    const knownDevices = {
        id: 'ten98-known-device',
        hooks: { after: [
                {
                    matcher: (context) => signInPaths.has(context.path ?? '') || (context.path === undefined && typeof context.body?.oidcUserId === 'string'),
                    handler: createAuthMiddleware(async (context) => {
                        const created = context.context.newSession;
                        if (!created || isAPIError(context.context.returned))
                            return;
                        // Confirming a factor while enabling two-factor is not a sign-in; only a sign-in challenge carries this cookie.
                        if (context.path?.startsWith('/two-factor/') && !context.getCookie(context.context.createAuthCookie('two_factor').name))
                            return;
                        await issueDevice(context, created.user.id);
                    }),
                },
                {
                    matcher: (context) => revokingPaths.has(context.path ?? ''),
                    handler: createAuthMiddleware(async (context) => {
                        const userId = context.context.session?.user.id;
                        if (!userId || isAPIError(context.context.returned))
                            return;
                        await forgetDevices(await getCurrentAdapter(context.context.adapter), userId);
                    }),
                },
            ] },
    };
    // With legacy hashes accepted, every password check runs one legacy derive and one current derive, whichever hash is
    // stored or none, so response time does not reveal which accounts are unmigrated.
    const legacyPassword = legacyPasswords ? {
        hash: async (candidate) => (await Promise.all([hashPassword(candidate), verifyLegacyScryptHash(DUMMY_LEGACY_HASH, candidate)]))[0],
        verify: async ({ hash, password: candidate }) => {
            const legacy = isLegacyHash(hash);
            const [legacyOk, modernOk] = await Promise.all([
                verifyLegacyScryptHash(legacy ? hash : DUMMY_LEGACY_HASH, candidate),
                verifyPassword({ hash: legacy ? await modernDummy() : hash, password: candidate }),
            ]);
            return legacy ? legacyOk : modernOk;
        },
    } : undefined;
    const auth = betterAuth({
        database: protectTokens(database, keys), baseURL: origin, secret, appName, trustedOrigins: [origin],
        // better-auth skips these checks when NODE_ENV=test or TEST is set unless they are pinned.
        advanced: { disableOriginCheck: false, disableCSRFCheck: false, cookiePrefix: prefix },
        // Self-hosted installs send no data to Ten98 or third parties.
        telemetry: { enabled: false },
        // Adapter failures can contain query parameters, and better-call logs non-API exceptions even with the logger off,
        // so every unexpected error becomes a bare 500 before it can expose SQL, hashes or tokens.
        logger: { disabled: true },
        onAPIError: { onError(error) { if (isAPIError(error))
                throw error; throw APIError.fromStatus('INTERNAL_SERVER_ERROR'); } },
        session: { expiresIn: session.expiresInSeconds, updateAge: session.updateAgeSeconds, cookieCache: { enabled: false } },
        plugins: [factors, oidcSessions, sessionRevocation, knownDevices],
        emailAndPassword: {
            enabled: true,
            disableSignUp: true,
            minPasswordLength: password.minLength,
            maxPasswordLength: password.maxLength,
            resetPasswordTokenExpiresIn: reset.expiresInSeconds,
            revokeSessionsOnPasswordReset: reset.revokesSessions,
            ...(sendResetPassword ? { sendResetPassword: async ({ user, token }) => { await sendResetPassword({ userId: user.id, email: user.email, token }); } } : {}),
            // A reset also ends trusted devices, pending two-factor challenges and known devices, so the new password alone
            // never skips the factor and no browser stays trusted across it.
            onPasswordReset: async ({ user }) => {
                // deleteMany has no row cap (findMany defaults to 100). Challenge rows hold the user id; their attempt counters
                // ('2fa-attempts-…', value '0') expire with the challenge they belonged to.
                // The prefixes are kept in storage, so these filters match the hashed rows.
                const { adapter } = await storeOf(auth);
                for (const prefix of ['trust-device-', '2fa-', devicePrefix]) {
                    await adapter.deleteMany({ model: 'verification', where: [{ field: 'value', value: user.id }, { field: 'identifier', operator: 'starts_with', value: prefix }] });
                }
            },
            ...(legacyPassword ? { password: legacyPassword } : {}),
        },
        rateLimit: { enabled: false },
        hooks: { after: createAuthMiddleware(async (context) => {
                if (context.path !== '/sign-in/email' || isAPIError(context.context.returned))
                    return;
                // The account this sign-in created a session (or a two-factor challenge) for, read before the two-factor plugin's
                // hook clears it, so signInWithPassword can check it is the account it locked.
                const signedIn = context.context.newSession?.user.id;
                if (internal.signedIn && signedIn)
                    internal.signedIn(signedIn);
                // signInWithPassword replaces a legacy hash itself, in a savepoint of its locked transaction. Here (raw sign-in,
                // allowRawPasswordSignIn) it is best effort: a failure leaves the legacy hash for the next sign-in.
                if (!legacyPasswords || internal.signedIn)
                    return;
                const { email, password: candidate } = (context.body ?? {});
                if (typeof email !== 'string' || typeof candidate !== 'string')
                    return;
                try {
                    const found = await context.context.internalAdapter.findUserByEmail(email.toLowerCase(), { includeAccounts: true });
                    const credential = found?.accounts.find(account => account.providerId === 'credential');
                    if (found && credential?.password && isLegacyHash(credential.password))
                        await context.context.internalAdapter.updatePassword(found.user.id, await hashPassword(candidate));
                }
                catch { /* retried on the next successful sign-in */ }
            }) },
    });
    const helpers = {
        storedVerificationIdentifier: (identifier) => storedIdentifier(keys, raw(identifier)),
        sessionTokenKey: (token) => tokenHandle(keys, raw(token)),
    };
    if (!locking)
        return Object.assign(auth, helpers);
    // On the instance the app holds, better-auth's own password sign-in has no limit, no lock and no constant-cost check,
    // so it is off: the route (any case, any trailing slash) answers 404 and api.signInEmail throws.
    if (options.allowRawPasswordSignIn !== true) {
        const route = auth.handler.bind(auth);
        const routed = (request) => passwordRoute.test(new URL(request.url).pathname) ? Promise.resolve(refusal(404, 'NOT_FOUND', 'Not found.')) : route(request);
        Object.assign(auth, { handler: routed, fetch: routed });
        Object.assign(auth.api, { signInEmail() { throw new TypeError('Password sign-in is only supported through signInWithPassword.'); } });
    }
    const { lockTimeoutMs = 5000 } = options;
    if (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs < 1 || lockTimeoutMs > 600_000)
        throw new TypeError('lockTimeoutMs must be an integer from 1 to 600000.');
    const slots = boundedSlots(options.passwordVerification);
    void modernDummy();
    /**
     * Binds an instance to the transaction for `run`. The callback gets its own transaction object over a guarded view of
     * the connection, and both are marked (tenancy and team operations refuse them; `hold.email` is the email lock already
     * held). When `run` settles, before COMMIT, the view and the instance close: a later or un-awaited call throws
     * LockedAuthClosedError instead of running outside the lock on a connection back in the pool.
     */
    const bind = async (tx, hold, run, passwordSignIn = false) => {
        // drizzle-orm internals, as transaction() in ./db reads them; drizzle-orm is pinned exactly for this reason.
        const { dialect, _: { session: inner } } = tx;
        const connection = inner.client;
        let open = true;
        const closed = () => new LockedAuthClosedError();
        const guarded = new Proxy(connection, {
            get(target, key) {
                const value = Reflect.get(target, key, target);
                if (typeof value !== 'function')
                    return value;
                if (key === 'query')
                    return (...args) => open ? value.apply(target, args) : Promise.reject(closed());
                return value.bind(target);
            },
        });
        const callbackTx = new NodePgTransaction(dialect, new NodePgSession(guarded, dialect, inner.schema, inner.options), inner.schema);
        // For signInWithPassword: the account better-auth's sign-in created a session for, to compare with the locked one.
        let signedIn;
        const bound = build({ ...options, database: transactionDatabase(callbackTx) }, keys, false, passwordSignIn ? { signedIn(userId) { signedIn = userId; } } : {});
        Object.defineProperty(bound, signedInUser, { value: () => signedIn });
        // signInEmail holds this transaction's connection and lock while it hashes; only signInWithPassword, after its own
        // check outside any transaction, may call it here.
        const stalls = 'Password sign-in inside a locked-auth transaction holds a pool connection while it hashes; use signInWithPassword.';
        const check = (signIn) => {
            if (!open)
                throw closed();
            if (signIn && !passwordSignIn)
                throw new TypeError(stalls);
        };
        const api = bound.api;
        const handler = bound.handler.bind(bound);
        Object.assign(bound, {
            userId: hold.userId,
            api: new Proxy(api, { get(target, key) {
                    const value = target[key];
                    return typeof value === 'function' ? (...args) => { check(key === 'signInEmail'); return value.apply(target, args); } : value;
                } }),
            handler(request) { check(passwordRoute.test(new URL(request.url).pathname)); return handler(request); },
            // better-auth's fetch is the same handler; it gets the same checks.
            fetch(request) { check(passwordRoute.test(new URL(request.url).pathname)); return handler(request); },
            async revokeAllSessions() {
                check(false);
                if (hold.userId === undefined)
                    return;
                const store = await storeOf(bound);
                await store.internalAdapter.deleteUserSessions(hold.userId);
                await forgetDevices(store.adapter, hold.userId);
            },
        });
        const unmark = markLockedAuth({ email: hold.email }, callbackTx, connection);
        try {
            return await lockedContext.run(true, () => run(bound, callbackTx));
        }
        finally {
            open = false;
            unmark();
        }
    };
    // Refused before any statement: without the factory there is nothing to bind; a transaction as `db`, or a database on
    // a locked-auth connection, would put the lock inside another transaction; a second locked-auth transaction opened in
    // a callback would wait on the first's locks (one user per transaction); inside a better-auth request or hook,
    // better-auth's own adapter context would route the bound instance's queries away from `tx`, outside the lock.
    const ready = async (db, run) => {
        if (!transactionDatabase)
            throw new TypeError('withLockedAuth needs the transactionDatabase option of createTen98Auth.');
        if (db instanceof PgTransaction)
            throw new TypeError('withLockedAuth opens its own transaction; pass the database, not a transaction.');
        if (typeof run !== 'function')
            throw new TypeError('withLockedAuth needs a callback.');
        if (lockedContext.getStore())
            throw new LockedAuthTransactionError('withLockedAuth');
        refuseLockedAuth(db, 'withLockedAuth');
        const outside = {};
        if (await getCurrentAdapter(outside) !== outside)
            throw new TypeError('withLockedAuth cannot run inside a better-auth request or hook.');
        await emailIndex(db);
    };
    // Parameterised raw statements by necessity: Drizzle has no builder for set_config or advisory locks. The timeout comes
    // first, so the lock statements that follow cannot wait forever.
    const limitLockWaits = (tx) => tx.execute(sql `SELECT set_config('lock_timeout', ${`${lockTimeoutMs}ms`}, true)`);
    const byEmail = (db, address, run, passwordSignIn) => transaction(db, async (tx) => {
        await limitLockWaits(tx);
        await tx.execute(sql `SELECT pg_advisory_xact_lock(${emailLockKey}, hashtext(${address}))`);
        // lower() on both sides, as user_email_normalized_idx is defined, whatever JavaScript's lowercasing did. That index
        // makes the match unique; were it dropped after the start-up check, two matches are refused, never one picked.
        const rows = await tx.select({ id: userTable.id }).from(userTable).where(sql `lower(${userTable.email}) = lower(${address})`).for('no key update');
        if (rows.length > 1)
            throw new AmbiguousAccountError();
        return bind(tx, { userId: rows[0]?.id, email: address }, (auth, bound) => run(auth, bound, rows[0]?.id), passwordSignIn);
    });
    /**
     * The id of the attempt row claimed for this browser's known device of the account behind `address`, or undefined.
     * True only when an entry's tag verifies for that account, its device row exists, belongs to that user and has not
     * expired, and fewer than `device.attempts` attempts are claimed since its last success. The tag is checked on a plain
     * read first, so a forged or foreign cookie takes no lock; the claim itself runs under the account's email and user
     * locks, so concurrent attempts claim exactly.
     */
    const claimDevice = async (db, address, headers) => {
        const store = await storeOf(auth);
        const entries = deviceEntries(cookieFrom(headers, store.createAuthCookie(device.cookie).name));
        if (!entries.length)
            return undefined;
        const [account] = await db.select({ id: userTable.id }).from(userTable).where(sql `lower(${userTable.email}) = lower(${address})`).limit(1);
        const entry = account ? deviceFor(keys, account.id, entries) : undefined;
        if (!account || !entry)
            return undefined;
        // Two accounts at one email (the index dropped after start-up) claim nothing; the sign-in itself refuses them.
        return byEmail(db, address, async (bound, _tx, userId) => {
            if (userId !== account.id)
                return undefined;
            const { adapter, internalAdapter } = await storeOf(bound);
            const row = await adapter.findOne({ model: 'verification', where: [{ field: 'identifier', value: deviceRow(entry.deviceId) }] });
            const expiresAt = row ? new Date(row.expiresAt) : undefined;
            if (!row || row.value !== userId || !expiresAt || !(expiresAt.getTime() > Date.now()))
                return undefined;
            if (await adapter.count({ model: 'verification', where: [{ field: 'identifier', value: attemptRow(entry.deviceId) }] }) >= device.attempts)
                return undefined;
            return (await internalAdapter.createVerificationValue({ identifier: attemptRow(entry.deviceId), value: userId, expiresAt })).id;
        }, false).catch(error => { if (error instanceof AmbiguousAccountError)
            return undefined; throw error; });
    };
    const locked = {
        async withLockedAuth(db, userId, run) {
            await ready(db, run);
            if (typeof userId !== 'string' || !userId)
                throw new TypeError('withLockedAuth needs a user id.');
            return transaction(db, async (tx) => {
                await limitLockWaits(tx);
                const [row] = await tx.select({ id: userTable.id }).from(userTable).where(eq(userTable.id, userId)).for('no key update');
                if (!row)
                    throw new LockedAuthUserNotFoundError();
                return bind(tx, { userId: row.id, email: undefined }, run);
            });
        },
        async withLockedAuthByEmail(db, email, run) {
            await ready(db, run);
            if (typeof email !== 'string')
                throw new TypeError('withLockedAuthByEmail needs an email.');
            // Normalised as the team controller's lockEmail does, so both take the same advisory lock.
            return byEmail(db, email.trim().toLowerCase(), run, false);
        },
        async signInWithPassword(db, input, limit) {
            if (typeof limit !== 'function')
                throw new TypeError('signInWithPassword needs the app\'s rate limit.');
            await ready(db, limit);
            const { email, password, source, rememberMe, headers } = (input ?? {});
            if (typeof source !== 'string' || !source)
                throw new TypeError('signInWithPassword needs the request\'s source (the client address the app derived).');
            if (typeof email !== 'string' || typeof password !== 'string' || (rememberMe !== undefined && typeof rememberMe !== 'boolean'))
                return refusal(400, 'INVALID_INPUT', 'Enter an email and a password.');
            // better-auth checks the origin only for a request it routes itself, not for this server call, so the browser's
            // Origin and Sec-Fetch-Site are checked here: a cross-site form cannot sign a victim in to another account.
            if (crossSite(headers, origin))
                return refusal(403, 'CROSS_SITE_SIGN_IN', 'Sign in from this site.');
            const address = email.trim().toLowerCase();
            // 0. Whether this browser is a known device of the account behind this email: it then claims one of the device's
            // attempts (released again below unless the password was checked). It never authenticates; it only tells the app.
            const claim = await claimDevice(db, address, headers);
            const unclaim = async () => { if (claim)
                await (await storeOf(auth)).adapter.delete({ model: 'verification', where: [{ field: 'id', value: claim }] }); };
            // 1. The app's limits, per source and per account, counted before any read, hash or queue: a flood of guesses costs
            // a counter, and one source cannot fill the verification queue.
            let allowed;
            try {
                allowed = await limit({ email: address, source, knownDevice: claim !== undefined });
            }
            catch (error) {
                await unclaim();
                throw error;
            }
            if (allowed !== true) {
                await unclaim();
                return refusal(429, 'TOO_MANY_ATTEMPTS', 'Too many sign-in attempts. Try again later.');
            }
            // No stored password is longer than the policy allows, so a longer one is wrong for every account, unhashed.
            if (password.length > ten98AuthPolicy.password.maxLength)
                return refused();
            // 2. A verification slot, so concurrent guesses cannot queue without bound on the hashing threads.
            const release = await slots();
            if (!release) {
                await unclaim();
                return refusal(503, 'SIGN_IN_BUSY', 'Sign-in is busy. Try again shortly.', { 'retry-after': '1' });
            }
            let verified;
            try {
                // 3. One short pool read; its connection is back in the pool before any hashing starts.
                const [stored] = await db.select({ password: accountTable.password }).from(userTable)
                    .leftJoin(accountTable, and(eq(accountTable.userId, userTable.id), eq(accountTable.providerId, 'credential')))
                    .where(sql `lower(${userTable.email}) = lower(${address})`).limit(1);
                verified = await verifyStoredPassword(stored?.password, password, legacyPasswords);
            }
            finally {
                release();
            }
            if (!verified)
                return refused();
            // 4. Only a correct password takes the lock; better-auth verifies again there and creates the session, for the
            // locked account only.
            let response;
            try {
                response = await byEmail(db, address, async (bound, tx, userId) => {
                    // No account under the lock (its email moved before the lock was granted), or one that may not sign in: the
                    // uniform 401, after the derivation the sign-in would have cost.
                    const [account] = userId === undefined ? [] : await tx.select({ id: userTable.id, email: userTable.email, closedAt: userTable.closedAt }).from(userTable).where(eq(userTable.id, userId));
                    if (!account || await usable(account) !== true) {
                        await lockedCost(password);
                        return refused();
                    }
                    const signedIn = await bound.api.signInEmail({ body: { email: address, password, ...(rememberMe === undefined ? {} : { rememberMe }) }, ...(headers === undefined ? {} : { headers }), asResponse: true });
                    if (signedIn.ok) {
                        // A session (or challenge) for any other account than the locked one rolls the transaction back.
                        if (bound[signedInUser]() !== account.id)
                            throw new LockedAccountMismatch();
                        if (legacyPasswords)
                            await replaceLegacyHash(tx, account.id, password);
                    }
                    return signedIn;
                }, true);
            }
            catch (error) {
                if (error instanceof LockedAccountMismatch || error instanceof AmbiguousAccountError)
                    return refused();
                // COMMIT reported a rollback: nothing the callback did persists, so no cookie may be returned for it.
                if (error instanceof TransactionRolledBackError)
                    return refusal(500, 'SIGN_IN_FAILED', 'Sign-in failed. Try again.');
                throw error;
            }
            return response.status === 401 ? refused() : response;
        },
        assertEmailIndex: db => emailIndex(db),
    };
    /** The isAccountUsable hook, refusing a closed account by default. */
    const usable = (account) => options.isAccountUsable ? options.isAccountUsable(account) : account.closedAt === null;
    /** What better-auth's own check under the lock costs: both verifiers with legacy hashes accepted, else the current one. */
    const lockedCost = async (candidate) => {
        if (legacyPasswords)
            await verifyStoredPassword(undefined, candidate, true);
        else
            await verifyPassword({ hash: await modernDummy(), password: candidate }).catch(() => false);
    };
    /**
     * Replaces a legacy hash once, under the lock, in a savepoint: a failure (a trigger, a constraint) rolls back the
     * savepoint only, so the sign-in stands and the next one retries.
     */
    const replaceLegacyHash = async (tx, userId, candidate) => {
        const credential = and(eq(accountTable.userId, userId), eq(accountTable.providerId, 'credential'));
        try {
            await tx.transaction(async (savepoint) => {
                const [stored] = await savepoint.select({ password: accountTable.password }).from(accountTable).where(credential);
                if (stored?.password && isLegacyHash(stored.password))
                    await savepoint.update(accountTable).set({ password: await hashPassword(candidate), updatedAt: new Date() }).where(credential);
            });
        }
        catch (error) {
            if (error instanceof LockedAuthClosedError)
                throw error;
        }
    };
    return Object.assign(auth, helpers, locked);
}
// Shared by every instance in the process: the fixed hashes a check runs against when an account has no hash of that
// kind, so unknown, passwordless, legacy and current accounts all cost one legacy and one current derivation.
let dummyModernHash;
const modernDummy = () => (dummyModernHash ??= hashPassword('ten98-timing-equaliser'));
const lockedContext = new AsyncLocalStorage();
/** better-auth's password route, in any case and with any trailing slash. */
const passwordRoute = /\/sign-in\/email\/*$/i;
/** Where a bound instance keeps the account its password sign-in created a session for. */
const signedInUser = Symbol('ten98.auth.signedInUser');
/** better-auth signed in another account than the one signInWithPassword locked; thrown so the transaction rolls back. */
class LockedAccountMismatch extends Error {
}
/** More than one account matches an email: the unique index on lower(email) is missing. Nothing is picked. */
export class AmbiguousAccountError extends Error {
    code = 'AMBIGUOUS_ACCOUNT';
    constructor() { super('More than one account matches this email; the user table needs its unique index on lower(email).'); this.name = 'AmbiguousAccountError'; }
}
/** The user table has no valid unique index on lower(email), which the locked lookups need to find one account. */
export class MissingEmailIndexError extends Error {
    code = 'MISSING_EMAIL_INDEX';
    constructor() { super('The user table needs a unique index on lower(email) (user_email_normalized_idx in workspace-team.sql) before locked auth can run.'); this.name = 'MissingEmailIndexError'; }
}
// One check per database object. A missing index is remembered, so every later call is refused too; a failed query is
// not, so a transient error is retried.
const emailIndexChecks = new WeakMap();
function emailIndex(db) {
    let check = emailIndexChecks.get(db);
    if (!check) {
        // Parameterised raw statement by necessity: it reads the system catalogue, which has no Drizzle schema.
        check = db.execute(sql `SELECT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = to_regclass(${`"${getTableName(userTable)}"`})
        AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indnatts = 1 AND pg_get_expr(i.indexprs, i.indrelid) = 'lower(email)') AS indexed`)
            .then(result => { if (result.rows[0]?.indexed !== true)
            throw new MissingEmailIndexError(); });
        check.catch(error => { if (!(error instanceof MissingEmailIndexError))
            emailIndexChecks.delete(db); });
        emailIndexChecks.set(db, check);
    }
    return check;
}
/** Both verifiers on every attempt, one of them against a dummy; true only for a stored hash the password matches. */
async function verifyStoredPassword(hash, candidate, legacyAccepted) {
    const present = typeof hash === 'string' && hash !== '', legacy = present && isLegacyHash(hash);
    const [legacyOk, modernOk] = await Promise.all([
        verifyLegacyScryptHash(legacy ? hash : DUMMY_LEGACY_HASH, candidate),
        modernDummy().then(dummy => verifyPassword({ hash: present && !legacy ? hash : dummy, password: candidate })).catch(() => false),
    ]);
    return present && (legacy ? legacyAccepted && legacyOk : modernOk);
}
/** A browser request from another site: an Origin other than the app's, or Sec-Fetch-Site cross-site or same-site. */
function crossSite(headers, origin) {
    if (headers === undefined)
        return false;
    const given = new Headers(headers), from = given.get('origin'), site = given.get('sec-fetch-site')?.toLowerCase();
    return (from !== null && from !== origin) || site === 'cross-site' || site === 'same-site';
}
const refusal = (status, code, message, headers = {}) => new Response(JSON.stringify({ code, message }), { status, headers: { 'content-type': 'application/json', ...headers } });
/** One answer for an unknown email, a wrong password and an account without a password. */
const refused = () => refusal(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password');
/**
 * At most `concurrency` holders at once and `queue` waiting, each for at most `waitMs`. Resolves a release function, or
 * undefined when no slot came in time or the queue is full, so a caller is answered instead of left waiting.
 */
function boundedSlots({ concurrency = 2, queue = 100, waitMs = 15_000 } = {}) {
    for (const [name, value] of Object.entries({ concurrency, queue, waitMs })) {
        if (!Number.isInteger(value) || value < (name === 'concurrency' ? 1 : 0))
            throw new TypeError(`passwordVerification.${name} must be a whole number${name === 'concurrency' ? ' of at least 1' : ''}.`);
    }
    let active = 0;
    const waiting = [];
    const handOver = () => { const next = waiting.shift(); if (next)
        next();
    else
        active--; };
    const once = () => { let done = false; return () => { if (!done) {
        done = true;
        handOver();
    } }; };
    return () => {
        if (active < concurrency) {
            active++;
            return Promise.resolve(once());
        }
        if (waiting.length >= queue)
            return Promise.resolve(undefined);
        return new Promise(resolve => {
            const take = () => { clearTimeout(timer); resolve(once()); };
            const timer = setTimeout(() => { waiting.splice(waiting.indexOf(take), 1); resolve(undefined); }, waitMs);
            timer.unref();
            waiting.push(take);
        });
    };
}
