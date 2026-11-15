// The Ten98 identity preset on better-auth, promoted from Discover src/server/auth.ts (dev, 2026-10-25) per decision #7/#97.
// It fixes the shared policy (passwords, sessions, two-factor, reset, error redaction) in one place. Each app supplies its
// database adapter, its URL and secret, its reset-email capture, and keeps its routes, transactions, rate limiters,
// first-boot claim, OIDC protocol and workspace authorization. better-auth, drizzle-orm and pg are exact, optional peers.
//
// Tokens at rest (#131): session tokens and verification identifiers are stored as HMACs under keys derived from the
// secret, so reading the database yields no live session or reset link. Locked auth (#132): `withLockedAuth` runs
// better-auth on one transaction that holds the user row, so a password change and a sign-in or revocation cannot
// interleave.
import { createHash, createHmac, hkdfSync, scrypt, timingSafeEqual } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { PgTransaction } from 'drizzle-orm/pg-core';
import { betterAuth, getCurrentAdapter } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx, isAPIError, sensitiveSessionMiddleware } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { transaction, user as userTable } from './db.mjs';
import { appOrigin } from './index.mjs';
import { markLockedAuth } from './locked-auth.mjs';
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
const keyLabels = { verification: 'ten98-auth:verification-identifier:v1', session: 'ten98-auth:session-token:v1' };
const checkedSecret = (secret) => {
    if (typeof secret !== 'string' || secret.length < 32)
        throw new TypeError('The auth secret must be at least 32 characters.');
    return secret;
};
const deriveKeys = (secret) => ({
    verification: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.verification, 32)),
    session: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.session, 32)),
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
const keptPrefixes = ['2fa-otp-', '2fa-', 'trust-device-', 'reset-password:'];
function storedIdentifier(keys, identifier) {
    let head = '', rest = identifier;
    while (rest.startsWith(attemptsPrefix)) {
        head += attemptsPrefix;
        rest = rest.slice(attemptsPrefix.length);
    }
    const prefix = keptPrefixes.find(candidate => rest.startsWith(candidate));
    return head + (prefix ? prefix + mac(keys.verification, rest.slice(prefix.length)) : handlePrefix + mac(keys.verification, rest));
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
const storeOf = (auth) => auth.$context;
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
function build(options, keys, locking) {
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
                return context.json({ status: true, revoked });
            }),
        },
    };
    // With legacy hashes accepted, every password check runs one legacy derive and one current derive, whichever hash is
    // stored or none, so response time does not reveal which accounts are unmigrated.
    let dummyModern;
    const modernDummy = () => (dummyModern ??= hashPassword('ten98-timing-equaliser'));
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
        plugins: [factors, oidcSessions, sessionRevocation],
        emailAndPassword: {
            enabled: true,
            disableSignUp: true,
            minPasswordLength: password.minLength,
            maxPasswordLength: password.maxLength,
            resetPasswordTokenExpiresIn: reset.expiresInSeconds,
            revokeSessionsOnPasswordReset: reset.revokesSessions,
            ...(sendResetPassword ? { sendResetPassword: async ({ user, token }) => { await sendResetPassword({ userId: user.id, email: user.email, token }); } } : {}),
            // A reset also ends trusted devices and pending two-factor challenges, so the new password alone never skips the factor.
            onPasswordReset: async ({ user }) => {
                // deleteMany has no row cap (findMany defaults to 100). Challenge rows hold the user id; their attempt counters
                // ('2fa-attempts-…', value '0') expire with the challenge they belonged to.
                // The prefixes are kept in storage, so these filters match the hashed rows.
                const { adapter } = await storeOf(auth);
                for (const prefix of ['trust-device-', '2fa-']) {
                    await adapter.deleteMany({ model: 'verification', where: [{ field: 'value', value: user.id }, { field: 'identifier', operator: 'starts_with', value: prefix }] });
                }
            },
            ...(legacyPassword ? { password: legacyPassword } : {}),
        },
        rateLimit: { enabled: false },
        ...(legacyPasswords ? { hooks: { after: createAuthMiddleware(async (context) => {
                    // After a successful password sign-in (with or without a pending two-factor challenge), replace a legacy hash.
                    // Best effort: a failure leaves the legacy hash for the next sign-in and never blocks this one.
                    if (context.path !== '/sign-in/email' || isAPIError(context.context.returned))
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
                }) } } : {}),
    });
    const helpers = {
        storedVerificationIdentifier: (identifier) => storedIdentifier(keys, raw(identifier)),
        sessionTokenKey: (token) => tokenHandle(keys, raw(token)),
    };
    if (!locking)
        return Object.assign(auth, helpers);
    // Binds an instance to `tx` for `run` and marks the transaction, so tenancy and team operations refuse it.
    const bind = async (tx, userId, run) => {
        const bound = build({ ...options, database: transactionDatabase(tx) }, keys, false);
        Object.assign(bound, { userId, async revokeAllSessions() { if (userId !== undefined)
                await (await storeOf(bound)).internalAdapter.deleteUserSessions(userId); } });
        const unmark = markLockedAuth(tx);
        try {
            return await run(bound, tx);
        }
        finally {
            unmark();
        }
    };
    // Refused before any statement: without the factory there is nothing to bind; a transaction as `db` would make the
    // lock a savepoint's statement, not the transaction's first; inside a better-auth request or hook, better-auth's own
    // adapter context would route the bound instance's queries away from `tx`, outside the lock.
    const ready = async (db, run) => {
        if (!transactionDatabase)
            throw new TypeError('withLockedAuth needs the transactionDatabase option of createTen98Auth.');
        if (db instanceof PgTransaction)
            throw new TypeError('withLockedAuth opens its own transaction; pass the database, not a transaction.');
        if (typeof run !== 'function')
            throw new TypeError('withLockedAuth needs a callback.');
        const outside = {};
        if (await getCurrentAdapter(outside) !== outside)
            throw new TypeError('withLockedAuth cannot run inside a better-auth request or hook.');
    };
    const locked = {
        async withLockedAuth(db, userId, run) {
            await ready(db, run);
            if (typeof userId !== 'string' || !userId)
                throw new TypeError('withLockedAuth needs a user id.');
            return transaction(db, async (tx) => {
                const [row] = await tx.select({ id: userTable.id }).from(userTable).where(eq(userTable.id, userId)).for('no key update');
                if (!row)
                    throw new LockedAuthUserNotFoundError();
                return bind(tx, row.id, run);
            });
        },
        async withLockedAuthByEmail(db, email, run) {
            await ready(db, run);
            if (typeof email !== 'string')
                throw new TypeError('withLockedAuthByEmail needs an email.');
            // Normalised as the team controller's lockEmail does, so both take the same advisory lock.
            const address = email.trim().toLowerCase();
            return transaction(db, async (tx) => {
                // Parameterised raw statement by necessity: Drizzle has no builder for advisory locks.
                await tx.execute(sql `SELECT pg_advisory_xact_lock(${emailLockKey}, hashtext(${address}))`);
                // lower() on both sides, as user_email_normalized_idx is defined, whatever JavaScript's lowercasing did.
                const [row] = await tx.select({ id: userTable.id }).from(userTable).where(sql `lower(${userTable.email}) = lower(${address})`).for('no key update');
                return bind(tx, row?.id, (auth, bound) => run(auth, bound, row?.id));
            });
        },
    };
    return Object.assign(auth, helpers, locked);
}
