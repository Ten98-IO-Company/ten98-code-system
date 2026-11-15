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
import { createHash, createHmac, hkdfSync, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { and, eq, getTableName, sql } from 'drizzle-orm';
import { NodePgSession, NodePgTransaction } from 'drizzle-orm/node-postgres';
import { PgTransaction } from 'drizzle-orm/pg-core';
import type pg from 'pg';
import { betterAuth, getCurrentAdapter, type BetterAuthOptions } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx, isAPIError, sensitiveSessionMiddleware } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { hashPassword, symmetricDecrypt, verifyPassword } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { account as accountTable, session as sessionTable, transaction, TransactionRolledBackError, user as userTable, type AnyDatabase, type ScopedTransaction } from './db.mjs';
import { isEmailAddress } from './email-message.mjs';
import { appOrigin } from './index.mjs';
import { lockedAuthUser, LockedAuthTransactionError, markLockedAuth, refuseLockedAuth } from './locked-auth.mjs';
import { isOidcSubject, oidcProviderId } from './oidc-issuer.mjs';

export { LockedAuthTransactionError } from './locked-auth.mjs';
export { normaliseOidcIssuer, normaliseOidcIssuerSql, oidcProviderId } from './oidc-issuer.mjs';

/** The shared identity policy. Apps read it for forms and route limiters, so the numbers never drift between them. */
export const ten98AuthPolicy = Object.freeze({
  password: Object.freeze({ minLength: 12, maxLength: 128 }),
  /** Seven days, extended at most once a day of use. */
  session: Object.freeze({ expiresInSeconds: 604_800, updateAgeSeconds: 86_400 }),
  /**
   * TOTP (RFC 6238, SHA-1). The preset keeps the replay ledger: per user, the last time step a code was accepted for;
   * a code whose step is at or before it is refused everywhere a TOTP code is taken. `replaySeconds` is how long that
   * refusal can matter (the ±1-step window). Recovery codes are `backupCodes` codes matching `backupCodePattern` (a string, so it survives JSON), each
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

export type ResetPasswordMessage = { userId: string; email: string; token: string };

// Campaign's stored format (server/auth.ts hashPassword): scrypt$<salt>$<key>, where the salt is 32 hex characters passed
// to scrypt as that text (not decoded), the key is 64 bytes in hex, N=65536 with the default r=8, p=1, and no normalization.
const LEGACY_SCRYPT = /^scrypt\$([0-9a-f]{32})\$([0-9a-f]{128})$/;
const isLegacyHash = (hash: string) => LEGACY_SCRYPT.test(hash);
const DUMMY_LEGACY_HASH = `scrypt$${'0'.repeat(32)}$${'0'.repeat(128)}`;

/** Verifies a Campaign `scrypt$salt$key` hash; any other format is not legacy and returns false. */
export function verifyLegacyScryptHash(hash: string, password: string): Promise<boolean> {
  const match = LEGACY_SCRYPT.exec(hash);
  if (!match) return Promise.resolve(false);
  const expected = Buffer.from(match[2]!, 'hex');
  return new Promise(resolve => scrypt(password, match[1]!, expected.length, { N: 65_536, maxmem: 128 * 1024 * 1024 }, (error, derived) => {
    resolve(!error && derived.length === expected.length && timingSafeEqual(derived, expected));
  }));
}

// Keys for tokens at rest: HKDF-SHA256 over the secret, one label per use, so neither equals the secret or any other key
// an app derives from it. Rotating the secret ends every session, reset link and trusted device, and makes enrolled
// second factors (encrypted with the secret itself) unreadable: it is a re-enrolment event.
const keyLabels = { verification: 'ten98-auth:verification-identifier:v1', session: 'ten98-auth:session-token:v1', knownDevice: 'ten98-auth:known-device:v1', challengeLimit: 'ten98-auth:two-factor-limit:v1' } as const;
type TokenKeys = Record<keyof typeof keyLabels, Buffer>;
const checkedSecret = (secret: unknown): string => {
  if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('The auth secret must be at least 32 characters.');
  return secret;
};
const deriveKeys = (secret: string): TokenKeys => ({
  verification: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.verification, 32)),
  session: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.session, 32)),
  knownDevice: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.knownDevice, 32)),
  challengeLimit: Buffer.from(hkdfSync('sha256', secret, '', keyLabels.challengeLimit, 32)),
});
const mac = (key: Buffer, value: string) => createHmac('sha256', key).update(value).digest('base64url');
const raw = (value: unknown): string => {
  if (typeof value !== 'string') throw new TypeError('A token or identifier must be a string.');
  return value;
};

/** Stored session tokens and whole-hashed identifiers start with this; better-auth's raw tokens are alphanumeric. */
const handlePrefix = 'v1.';
const isHandle = (value: unknown): value is string => typeof value === 'string' && value.startsWith(handlePrefix);
const tokenHandle = (keys: TokenKeys, token: string) => handlePrefix + mac(keys.session, token);

// The kept prefixes, longest first where they overlap. An attempt counter and a challenge's provider binding name their
// challenge, so their tails are stored with this same rule: the stored row is exactly '2fa-attempts-' (or
// 'oidc-challenge:') || <stored challenge identifier>, which revokeProviderSessions joins on in SQL.
const attemptsPrefix = '2fa-attempts-';
const challengeProviderPrefix = 'oidc-challenge:';
const namingPrefixes = [attemptsPrefix, challengeProviderPrefix] as const;
const keptPrefixes = ['2fa-otp-', '2fa-', 'trust-device-', 'reset-password:', 'known-device-attempt:', 'known-device:'] as const;
function storedIdentifier(keys: TokenKeys, identifier: string): string {
  let head = '', rest = identifier;
  for (let naming = namingPrefixes.find(candidate => rest.startsWith(candidate)); naming; naming = namingPrefixes.find(candidate => rest.startsWith(candidate))) {
    head += naming;
    rest = rest.slice(naming.length);
  }
  const prefix = keptPrefixes.find(candidate => rest.startsWith(candidate));
  return head + (prefix ? prefix + mac(keys.verification, rest.slice(prefix.length)) : handlePrefix + mac(keys.verification, rest));
}

// Known devices (#132): a browser that completed a sign-in for an account, so `signInWithPassword` can tell the app's
// limiter to spare it the account-wide bucket. Each is a verification row `known-device:<deviceId>` (value: the user id,
// expiresAt: its 90 days) with one `known-device-attempt:<deviceId>` row per attempt it was trusted for since its last
// success; at 5 it is no longer trusted. Both prefixes are kept in storage, so a user's rows go with one prefix filter.
const device = { cookie: 'known_device', lifetimeSeconds: 90 * 86_400, attempts: 5, entries: 5, devices: 5, cookieLength: 1024, claims: { concurrency: 2, queue: 8, waitMs: 1000 } } as const;
const devicePrefix = 'known-device', deviceRow = (deviceId: string) => `known-device:${deviceId}`, attemptRow = (deviceId: string) => `known-device-attempt:${deviceId}`;
type DeviceEntry = { readonly deviceId: string; readonly tag: string; readonly text: string };
const deviceEntryPattern = /^([A-Za-z0-9_-]{32})\.([A-Za-z0-9_-]{43})$/;
/**
 * A device id that carries its own MAC: 16 random bytes (22 characters) and the first 10 characters of an HMAC over them,
 * so a forged id is told apart before any database read or claim slot. The account tag below still binds it to a user.
 */
const newDeviceId = (keys: TokenKeys) => {
  const random = randomBytes(16).toString('base64url');
  return random + mac(keys.knownDevice, `device-id\u0000${random}`).slice(0, 10);
};
const deviceIdSigned = (keys: TokenKeys, deviceId: string) => deviceId.length === 32
  && timingSafeEqual(Buffer.from(deviceId.slice(22)), Buffer.from(mac(keys.knownDevice, `device-id\u0000${deviceId.slice(0, 22)}`).slice(0, 10)));
/** The tag binding a device id to one account: HMAC over userId ‖ deviceId (NUL-separated; neither contains NUL). */
const deviceTag = (keys: TokenKeys, userId: string, deviceId: string) => mac(keys.knownDevice, `${userId}\u0000${deviceId}`);
/**
 * The cookie's entries, one per account this browser signed in to, newest first and at most `device.entries`. A missing,
 * oversized or malformed value, or a malformed entry, is ignored, never an error.
 */
function deviceEntries(value: string | undefined | null): DeviceEntry[] {
  if (typeof value !== 'string' || value.length > device.cookieLength) return [];
  return value.split('~').slice(0, device.entries).flatMap(text => {
    const match = deviceEntryPattern.exec(text);
    return match ? [{ deviceId: match[1]!, tag: match[2]!, text }] : [];
  });
}
/** The entry whose tag verifies for `userId`, compared in constant time; undefined when none does. */
function deviceFor(keys: TokenKeys, userId: string, entries: readonly DeviceEntry[]): DeviceEntry | undefined {
  let found: DeviceEntry | undefined;
  for (const entry of entries) {
    if (timingSafeEqual(Buffer.from(entry.tag), Buffer.from(deviceTag(keys, userId, entry.deviceId))) && !found) found = entry;
  }
  return found;
}
/** Every name=value pair of a Cookie header, in order; a pair without a name is skipped. */
function cookiePairs(headers: HeadersInit | undefined): [string, string][] {
  const header = headers === undefined ? null : new Headers(headers).get('cookie');
  return (header?.split(';') ?? []).flatMap(pair => {
    const at = pair.indexOf('=');
    return at > 0 ? [[pair.slice(0, at).trim(), pair.slice(at + 1).trim()] as [string, string]] : [];
  });
}
/**
 * The value of the one pair named exactly `name`, or undefined when there is none or more than one. Only the exact name
 * the library reads counts: other prefixes, and the other scheme's or separator's forms of this one, are never read by
 * better-auth, so they are ignored rather than refused.
 */
function singleCookie(headers: HeadersInit | undefined, name: string): string | undefined {
  const values = cookiePairs(headers).filter(([key]) => key === name).map(([, value]) => value);
  return values.length === 1 ? values[0] : undefined;
}

/**
 * The `verification.identifier` the preset stores for a raw identifier, for an app that locks or reads the row with its
 * own SQL. Prefer the instance method, which needs no secret.
 */
export function storedVerificationIdentifier(secret: string, identifier: string): string {
  return storedIdentifier(deriveKeys(checkedSecret(secret)), raw(identifier));
}

/**
 * The `session.token` the preset stores (a `v1.` handle) for a raw session token, the cookie's value without its
 * signature. For an app's own read of session liveness; prefer the instance method, which needs no secret.
 */
export function sessionTokenKey(secret: string, token: string): string {
  return tokenHandle(deriveKeys(checkedSecret(secret)), raw(token));
}

/**
 * The statements every app's numbered migration runs once when it adopts runtime 0.29.0's auth storage, separated as
 * drizzle-kit separates statements. Rows stored in plain text before it would never match again: every session ends,
 * and reset links, trusted devices and pending two-factor challenges (with their `2fa-otp-` and `2fa-attempts-` rows) go
 * with them. Then the session gains its provider binding, `oidcProvider`, and emails are stored lower-case
 * (`user_email_lowercase`): the migration stops, listing the account ids and never an address, while two accounts share
 * an email ignoring case, so an operator resolves them first. A second run does not fail (it ends the sessions and pending
 * rows again, nothing else). Rows an app writes with its own SQL are its own decision.
 */
export const tokenStorageUpgradeStatements = [
  'DELETE FROM "session";',
  'DELETE FROM verification WHERE identifier LIKE \'reset-password:%\' OR identifier LIKE \'trust-device-%\' OR identifier LIKE \'2fa-%\';',
  'ALTER TABLE "session" ADD COLUMN IF NOT EXISTS "oidcProvider" text;',
  // #143, comment 6891409340: the pre-check and the UPDATE verbatim; the constraint is added once, NOT VALID, then
  // validated, so a second run passes and VALIDATE (in its own transaction) scans without blocking writes.
  `DO $$
DECLARE twins integer; listed text;
BEGIN
  SELECT count(*), string_agg(ids, ', ' ORDER BY first) FILTER (WHERE n <= 20)
    INTO twins, listed
    FROM (SELECT '[' || string_agg(id, ', ' ORDER BY id) || ']' AS ids, min(id) AS first, row_number() OVER (ORDER BY min(id)) AS n
          FROM "user" GROUP BY lower(email) HAVING count(*) > 1) shared;
  IF twins > 0 THEN
    RAISE EXCEPTION 'user_email_lowercase: % email address(es) belong to more than one user when case is ignored (accounts: %); resolve them before this migration',
      twins, listed || CASE WHEN twins > 20 THEN ', …' ELSE '' END;
  END IF;
END
$$;`,
  'UPDATE "user" SET email = lower(email) WHERE email <> lower(email);',
  `DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_email_lowercase' AND conrelid = '"user"'::regclass) THEN
    ALTER TABLE "user" ADD CONSTRAINT user_email_lowercase CHECK (email = lower(email)) NOT VALID;
  END IF;
END
$$;`,
  'ALTER TABLE "user" VALIDATE CONSTRAINT user_email_lowercase;',
].join('\n--> statement-breakpoint\n');

type Clause = { field: string; value: unknown; operator?: string; [option: string]: unknown };
type Query = { model: string; where?: Clause[]; data?: Record<string, unknown>; update?: Record<string, unknown>; set?: Record<string, unknown>; [option: string]: unknown };
type Row = Record<string, unknown> | null | undefined;
type StoreAdapter = { [method: string]: unknown };
type AdapterFactory = (options: BetterAuthOptions) => StoreAdapter;
/** Stored handle to the raw token the caller gave, so results carry the caller's own token back. */
type Restore = Map<string, string>;

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
function protectTokens(factory: AdapterFactory, keys: TokenKeys): AdapterFactory {
  const clause = (model: string, item: Clause, write: boolean, restore: Restore): Clause => {
    const operator = item.operator ?? 'eq';
    if (model === 'session' && item.field === 'token') {
      if (!fullValueOperators.has(operator)) throw new TypeError(`Session tokens are stored hashed and cannot be matched with ${operator}.`);
      const one = (value: unknown) => {
        if (typeof value !== 'string' || (write && isHandle(value))) return value;
        const handle = tokenHandle(keys, value);
        restore.set(handle, value);
        return handle;
      };
      return { ...item, value: Array.isArray(item.value) ? item.value.map(one) : one(item.value) };
    }
    if (model === 'verification' && item.field === 'identifier' && fullValueOperators.has(operator)) {
      const one = (value: unknown) => typeof value === 'string' ? storedIdentifier(keys, value) : value;
      return { ...item, value: Array.isArray(item.value) ? item.value.map(one) : one(item.value) };
    }
    return item;
  };
  const where = (query: Query, write: boolean, restore: Restore) => query.where?.map(item => clause(query.model, item, write, restore));
  const data = (model: string, values: Record<string, unknown> | undefined, restore: Restore) => {
    if (!values) return values;
    if (model === 'session' && typeof values.token === 'string' && !isHandle(values.token)) {
      const handle = tokenHandle(keys, values.token);
      restore.set(handle, values.token);
      return { ...values, token: handle };
    }
    if (model === 'verification' && typeof values.identifier === 'string') return { ...values, identifier: storedIdentifier(keys, values.identifier) };
    return values;
  };
  const back = (row: Row, restore: Restore): Row => row && typeof row.token === 'string' && restore.has(row.token) ? { ...row, token: restore.get(row.token) } : row;

  const wrap = (adapter: StoreAdapter): StoreAdapter => {
    const unknown = Object.entries(adapter).filter(([name, value]) => typeof value === 'function' && !adapterMethods.has(name)).map(([name]) => name);
    if (unknown.length) throw new TypeError(`The token storage wrapper does not know the adapter method(s) ${unknown.join(', ')}; review it before upgrading better-auth.`);
    const call = (name: string, query: Query) => (adapter[name] as (query: Query) => Promise<unknown>)(query);
    // `write`: an update or delete, where a stored handle passes through. `values`: the field holding row values.
    const method = (name: string, write: boolean, values?: 'data' | 'update' | 'set') => async (query: Query) => {
      const restore: Restore = new Map();
      const result = await call(name, { ...query, where: where(query, write, restore), ...values ? { [values]: data(query.model, query[values] as Record<string, unknown> | undefined, restore) } : {} });
      return Array.isArray(result) ? result.map(row => back(row as Row, restore)) : back(result as Row, restore);
    };
    const wrapped: StoreAdapter = {
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
    if (typeof adapter.consumeOne === 'function') wrapped.consumeOne = method('consumeOne', true);
    if (typeof adapter.incrementOne === 'function') wrapped.incrementOne = method('incrementOne', true, 'set');
    if (typeof adapter.transaction === 'function') {
      const run = adapter.transaction as (callback: (trx: StoreAdapter) => Promise<unknown>) => Promise<unknown>;
      wrapped.transaction = (callback: (trx: StoreAdapter) => Promise<unknown>) => run(trx => callback(wrap(trx)));
    }
    return wrapped;
  };
  return options => wrap(factory(options));
}

/** The user `withLockedAuth` was asked to lock does not exist; answer it as not found. */
export class LockedAuthUserNotFoundError extends Error {
  readonly status = 404 as const;
  readonly code = 'USER_NOT_FOUND' as const;
  constructor() { super('User not found.'); this.name = 'LockedAuthUserNotFoundError'; }
}

/**
 * A locked-auth instance or transaction was used after its callback returned (an un-awaited call, say), or a second
 * locked-auth transaction was opened inside one. Either would run outside, or wait on, the lock: a programming error.
 */
export class LockedAuthClosedError extends Error {
  readonly code = 'LOCKED_AUTH_CLOSED' as const;
  constructor(message = 'This locked-auth transaction has ended; await every call inside its callback.') { super(message); this.name = 'LockedAuthClosedError'; }
}

export interface Ten98AuthOptions {
  /** The app's better-auth adapter factory, such as `drizzleAdapter(db, { provider: 'pg', schema })`. */
  database: BetterAuthOptions['database'];
  /**
   * The same adapter over one transaction, such as `tx => drizzleAdapter(tx, { provider: 'pg', schema })`. Needed by
   * `withLockedAuth` and `withLockedAuthByEmail`, which bind a better-auth instance to the transaction they open.
   */
  transactionDatabase?(tx: ScopedTransaction<AnyDatabase>): BetterAuthOptions['database'];
  /** The first key of the email advisory lock; the team controller's `emailLockKey`, 109859 by default. */
  emailLockKey?: number;
  /**
   * `lock_timeout` for a locked-auth transaction (SET LOCAL, in milliseconds, 5000 by default), so a wait on a lock it
   * cannot get fails with SQLSTATE 55P03 instead of hanging.
   */
  lockTimeoutMs?: number;
  /**
   * The bound on concurrent `signInWithPassword` verifications in this process: `concurrency` at once (2 by default,
   * each running two scrypt derivations, which together fill libuv's default four threads), at most `queue` waiting
   * (100), each for at most `waitMs` (15000). Past either bound the attempt is answered 503, never left waiting.
   * `knownDevices` is the reserved lane for an attempt whose known-device claim was verified (1 at once, 20 waiting,
   * the same `waitMs` by default): such an attempt uses only the lane, so it never takes shared capacity. Its
   * verifications share the hashing threads: count its `concurrency` in when sizing `UV_THREADPOOL_SIZE`.
   */
  passwordVerification?: { concurrency?: number; queue?: number; waitMs?: number; knownDevices?: { concurrency?: number; queue?: number; waitMs?: number } };
  /** The app's public URL (APP_URL); validated with `appOrigin`. */
  appUrl: string;
  secret: string;
  /** Shown by authenticator apps as the TOTP issuer. */
  appName: string;
  /** Captures a reset token; the app sends the email after its transaction commits. Without it, password reset is off. */
  sendResetPassword?(message: ResetPasswordMessage): void | Promise<void>;
  /** Accept Campaign's legacy scrypt hashes and replace each with the current hash on the first successful sign-in. */
  legacyPasswords?: boolean;
  /**
   * Let accounts without a password manage two-factor with a session alone. Only for an app whose router proves a fresh
   * OIDC sign-in before those routes (Discover); off by default.
   */
  allowPasswordless?: boolean;
  /** Cookie name prefix. Defaults to one derived from the origin, so instances on one host (ports differ) never share cookies. */
  cookiePrefix?: string;
  /**
   * Paths and domains the app's auth cookies were once set with, besides the current `Path=/` with no Domain. A request
   * carrying an auth cookie twice is refused and every copy is expired, in each of these scopes too, so a cookie left from
   * an old path or domain cannot strand a user.
   */
  legacyCookieScopes?: readonly { path?: string; domain?: string }[];
  /**
   * Whether an account may sign in or reset its password: asked by `signInWithPassword` (before and under the lock) and
   * `verifyTwoFactor`, where anything but `true` gets the uniform 401, and by the reset routes, where a request for such an
   * account answers as for an unknown email (no token, nothing sent) and a token issued before is refused as invalid.
   * Defaults to refusing a closed account (`closedAt` set).
   */
  isAccountUsable?(account: { id: string; email: string; closedAt: Date | null }): boolean | Promise<boolean>;
  /**
   * Re-enables better-auth's own password sign-in (`POST /sign-in/email` and `api.signInEmail`) on the instance the
   * app holds. It has no rate limit, no lock and no constant-cost check: do not use it outside tests and migrations.
   */
  allowRawPasswordSignIn?: boolean;
}

export interface Ten98AuthSession {
  /** `oidcProvider`: the app's provider key when the session began with a provider sign-in (`completeOidcSession`). */
  session: { id: string; userId: string; token: string; expiresAt: Date; userAgent?: string | null; oidcProvider?: string | null; [field: string]: unknown };
  user: { id: string; email: string; name: string; twoFactorEnabled?: boolean | null; [field: string]: unknown };
}
type ServerCall<Body> = (input: { body: Body; headers?: HeadersInit; asResponse: true }) => Promise<Response>;
/**
 * The surface apps use, declared here because better-auth's inferred type names its internal packages. Reach `handler`
 * only through an app router that allowlists the auth paths it serves. The OIDC session endpoints are server-only.
 */
export interface Ten98Auth {
  handler(request: Request): Promise<Response>;
  api: {
    getSession(input: { headers: HeadersInit; query?: { disableRefresh?: boolean } }): Promise<Ten98AuthSession | null>;
    signInEmail: ServerCall<{ email: string; password: string; rememberMe?: boolean }>;
    /** Replaces the caller's own session with a fresh one and revokes the old one (after the app verified a factor); needs that session's cookie. */
    rotateVerifiedSession: ServerCall<{ verifiedUserId: string }>;
    /**
     * Signs in a user the app's OIDC flow verified (`signInOidcUser`); an account with two-factor enabled gets the TOTP
     * challenge instead. `provider` is the app's key for the provider configuration it signed in through (1 to 256
     * characters, no control characters): the session, or the session the challenge later creates, stores it as
     * `oidcProvider`, so `revokeProviderSessions` can end it.
     */
    completeOidcSession: ServerCall<{ oidcUserId: string; provider: string }>;
    /**
     * Revokes the caller's other live sessions by id and keeps the current one (found from the cookie in `headers`).
     * `revoked` counts the sessions it ended. The same endpoint serves POST /revoke-other-sessions.
     */
    revokeOtherSessions(input: { headers: HeadersInit }): Promise<{ status: true; revoked: number }>;
  };
  options: { readonly telemetry: { readonly enabled: false } };
  /** The stored `verification.identifier` for a raw identifier; see the standalone `storedVerificationIdentifier`. */
  storedVerificationIdentifier(identifier: string): string;
  /**
   * The exact name of one of the auth cookies (`two_factor`, `session_token`, `known_device`, …) for this instance:
   * `__Host-<prefix>.<name>` on https, `<prefix>.<name>` on plain-http development.
   */
  cookieName(name: string): string;
  /**
   * The sign-in challenge a request's `two_factor` cookie names, or null when the cookie is absent, sent more than once,
   * malformed, unsigned, forged, under another prefix, or names no live challenge of an existing account. `limitKey` is
   * a stable HMAC of the challenge under its own derived key, never empty: key the app's per-challenge limiter with it.
   */
  readTwoFactorChallenge(request: Request): Promise<{ identifier: string; userId: string; limitKey: string } | null>;
  /**
   * The Set-Cookie values that expire an auth cookie a request carries more than once (session, challenge or known
   * device), or none: at `/`, on every prefix of the auth routes and of `path` (the request's own, when given), and in
   * each `legacyCookieScopes` entry. An app guard that calls `api.getSession` itself appends them
   * to its response; `handler`, `signInWithPassword` and `verifyTwoFactor` add them on their own.
   */
  expiredAuthCookies(headers: HeadersInit, path?: string): string[];
  /** The stored `session.token` handle for a raw session token; see the standalone `sessionTokenKey`. */
  sessionTokenKey(token: string): string;
  /**
   * Runs `run` in one transaction (`transaction` from ./db) that sets its `lock_timeout` and then locks the user row
   * FOR NO KEY UPDATE, with a better-auth instance bound to that transaction. A missing user throws
   * LockedAuthUserNotFoundError (404). The callback runs its own statements on `tx` and may lock that user's session,
   * credential and verification rows, in that order. Tenancy helpers, workspace-level team operations, `lockEmail`
   * (except for the email `withLockedAuthByEmail` holds) and a nested locked-auth call refuse the transaction. When `run`
   * throws, or the transaction fails, nothing it did persists and the error is rethrown; Set-Cookie headers from inside
   * are lost with it. Once `run` settles, `tx` and the instance throw LockedAuthClosedError.
   */
  withLockedAuth<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>) => Promise<T>): Promise<T>;
  /**
   * `withLockedAuth` for a flow that knows only an email (password sign-in, reset request): takes the email advisory
   * lock (`pg_advisory_xact_lock(emailLockKey, hashtext(email))`, the team controller's `lockEmail`) first, then locks
   * that account's user row if there is one. `userId` is undefined when no account has the email.
   */
  withLockedAuthByEmail<TDatabase extends AnyDatabase, T>(db: TDatabase, email: string, run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>, userId: string | undefined) => Promise<T>): Promise<T>;
  /**
   * The supported password sign-in. A browser request from another site (an Origin other than `appUrl`'s, or a
   * cross-site Sec-Fetch-Site in `headers`) is answered 403 first. Then, in order: `limits.source` (the app's per-source
   * and per-pair limits, before anything touches the database); whether the browser's known-device cookie holds a live
   * device of the account behind `email` (`knownDevice`; see the guide); `limits.account` (the app's account-wide limit,
   * which may skip its bucket for a known device); anything but `true` at either step answers 429; a slot among the
   * bounded verifications (503 when none is free in time); one short pool read of the credential, its connection
   * released; both the modern and the legacy
   * verifier, one of them against a fixed dummy, outside any transaction. A wrong password, an unknown email and an
   * account without a password all get the same 401. Only a correct password enters `withLockedAuthByEmail`, where
   * better-auth verifies again under the lock and creates the session (a legacy hash is replaced there once); if the
   * password changed in between, the answer is the same 401 and no session is created. The response carries the
   * session cookie, or the two-factor challenge, as `/sign-in/email` does.
   */
  signInWithPassword(db: AnyDatabase, input: PasswordSignIn, limits: PasswordSignInLimits): Promise<Response>;
  /**
   * Resolves when the user table has the unique index on `lower(email)` that the locked lookups rely on, and rejects
   * otherwise. Call it at start-up; every locked call also checks it once per database and refuses to run without it.
   */
  assertEmailIndex(db: AnyDatabase): Promise<void>;
  /**
   * The start-up check: resolves when the tables `"user"`, `account`, `session` and `verification` have the columns the
   * preset uses and the user table has its unique index on `lower(email)`; otherwise rejects with SchemaMismatchError
   * (naming the expected and the missing tables and columns) or MissingEmailIndexError. Every locked call runs it once
   * per database too, so a wrong schema fails loudly, never as a refused sign-in.
   */
  assertSchema(db: AnyDatabase): Promise<void>;
  /**
   * Handles every two-factor request (a POST to `/two-factor/*`); the instance the app holds refuses them, naming this
   * function. Completing a sign-in's challenge (`/two-factor/verify-totp`, `-backup-code` or `-otp`, with the signed
   * `two_factor` cookie) runs under the challenged account's lock: an account `isAccountUsable` refuses, or a challenge
   * that is unknown or expired, gets one uniform 401, and a session for any other account rolls back. Every other
   * request (enrolling and confirming a factor, disabling it, recovery codes, the TOTP URI) needs a session and runs
   * under that user's lock; without one it gets better-auth's own 401. Pass the request as received.
   */
  verifyTwoFactor(db: AnyDatabase, request: Request): Promise<Response>;
}

/** `signInWithPassword`'s input; `headers` are the request's: its origin, its cookies, its user agent and address. */
export type PasswordSignIn = { email: string; password: string; source: string; rememberMe?: boolean; headers?: HeadersInit };
/**
 * What `signInWithPassword` gives the app's limiter: the normalised email; `source`, the client address the app derived
 * for the request (`clientLimitKey` of its trusted address); and, at the account step, `knownDevice`, whether this
 * browser is a known device of that account.
 */
export type PasswordAttempt = { email: string; source: string; knownDevice: boolean };
/**
 * One step's answer: `true` allows the attempt; `{ retryAfterSeconds }` (an integer from 1 to 86400) refuses it with that
 * wait; `false`, or anything else, refuses it with a wait of 60 seconds. Every refusal is a 429 with `Retry-After`.
 */
export type PasswordLimitAnswer = boolean | { retryAfterSeconds: number };
/**
 * The app's limiter for `signInWithPassword`, asked in two steps. `source` comes first, before anything touches the
 * database: the per-source and per-pair (source and email) limits, so a flood the app refuses costs a counter and nothing
 * else. Only an attempt it allows has its known-device cookie checked; `account` then gets `knownDevice` and may skip the
 * account-wide bucket for it, and only that bucket. Both are asked before the password is checked: count an attempt
 * against the failure buckets once its response is the 401, never on a 429 or a success.
 */
export type PasswordSignInLimits = {
  source(attempt: Omit<PasswordAttempt, 'knownDevice'>): PasswordLimitAnswer | Promise<PasswordLimitAnswer>;
  account(attempt: PasswordAttempt): PasswordLimitAnswer | Promise<PasswordLimitAnswer>;
};

/**
 * The transaction-bound instance `withLockedAuth` hands out. It opens no further locked-auth transactions, signs no one
 * in with a password (use `signInWithPassword`), and throws LockedAuthClosedError once the callback has returned.
 */
export interface LockedTen98Auth extends Omit<Ten98Auth, 'withLockedAuth' | 'withLockedAuthByEmail' | 'signInWithPassword' | 'assertEmailIndex' | 'assertSchema' | 'verifyTwoFactor'> {
  /** The locked user, or undefined when `withLockedAuthByEmail` found no account. */
  readonly userId: string | undefined;
  /** Deletes every session of the locked user in this transaction (better-auth's `deleteUserSessions`). */
  revokeAllSessions(): Promise<void>;
}

type StoreWhere = { field: string; value: string; operator?: 'eq' | 'starts_with' }[];
type StoreAdapterSurface = {
  update(query: { model: string; where: StoreWhere; update: Record<string, unknown> }): Promise<unknown>;
  deleteMany(query: { model: string; where: StoreWhere }): Promise<number>;
  delete(query: { model: string; where: StoreWhere }): Promise<void>;
  findOne<T>(query: { model: string; where: StoreWhere }): Promise<T | null>;
  findMany<T>(query: { model: string; where: StoreWhere; sortBy?: { field: string; direction: 'asc' | 'desc' } }): Promise<T[]>;
  count(query: { model: string; where: StoreWhere }): Promise<number>;
};
type StoreContext = {
  adapter: StoreAdapterSurface;
  secretConfig: unknown;
  internalAdapter: {
    deleteUserSessions(userId: string): Promise<void>;
    createVerificationValue(data: { identifier: string; value: string; expiresAt: Date }): Promise<{ id: string }>;
  };
  createAuthCookie(name: string, attributes?: { maxAge?: number }): { name: string; attributes: Record<string, unknown> };
};
const storeOf = (auth: object) => (auth as { $context: Promise<StoreContext> }).$context;
/** Deletes every known-device and attempt row of a user, so no browser of theirs stays trusted. */
const forgetDevices = (adapter: StoreAdapterSurface, userId: string) =>
  adapter.deleteMany({ model: 'verification', where: [{ field: 'value', value: userId }, { field: 'identifier', operator: 'starts_with', value: devicePrefix }] });
const INT32 = 2 ** 31;

/**
 * A better-auth instance with the Ten98 policy. Sign-up stays closed: the first-boot claim creates the owner in the
 * app's own transaction (hash with `hashPassword` from 'better-auth/crypto') and then signs in. Origin and CSRF checks
 * are pinned on, so no environment variable can turn them off. Session tokens and verification identifiers are stored
 * as keyed hashes; the cookie cache stays off and no secondary storage is used, so no token is kept anywhere else.
 */
export function createTen98Auth(options: Ten98AuthOptions): Ten98Auth {
  return build(options, deriveKeys(checkedSecret(options.secret)), true) as Ten98Auth;
}

function build(options: Ten98AuthOptions, keys: TokenKeys, locking: boolean, internal: { signedIn?(userId: string): void } = {}): Ten98Auth | LockedTen98Auth {
  const { database, appUrl, secret, appName, sendResetPassword, legacyPasswords = false, allowPasswordless = false, cookiePrefix, transactionDatabase, emailLockKey = 109_859 } = options;
  const origin = appOrigin(appUrl);
  checkedSecret(secret);
  if (typeof appName !== 'string' || !appName.trim()) throw new TypeError('appName is required.');
  if (typeof database !== 'function') throw new TypeError('database must be a better-auth adapter factory, such as drizzleAdapter(db, { provider: \'pg\', schema }), so tokens can be stored hashed.');
  if (transactionDatabase !== undefined && typeof transactionDatabase !== 'function') throw new TypeError('transactionDatabase must be a function of the transaction.');
  if (!Number.isInteger(emailLockKey) || emailLockKey < -INT32 || emailLockKey >= INT32) throw new TypeError('emailLockKey must be a 32-bit integer.');
  const prefix = cookiePrefix ?? `ten98-${createHash('sha256').update(origin).digest('hex').slice(0, 16)}`;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(prefix)) throw new TypeError('cookiePrefix must be 1 to 64 letters, digits, hyphens or underscores.');
  const scopes = [{ path: '/', domain: undefined as string | undefined }, ...(options.legacyCookieScopes ?? []).map(scope => {
    const { path = '/', domain } = scope ?? {};
    if (typeof path !== 'string' || !/^\/[\x21-\x3a\x3c-\x7e]*$/.test(path)) throw new TypeError('legacyCookieScopes: a path starts with / and has no spaces, semicolons or control characters.');
    if (domain !== undefined && (typeof domain !== 'string' || !/^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/.test(domain))) throw new TypeError('legacyCookieScopes: a domain is a host name.');
    return { path, domain };
  })];
  const secureCookies = origin.startsWith('https:');
  /** better-auth's routes live under this path (its default); a cookie copy can sit on any prefix of it. */
  const basePath = '/api/auth';
  /** The exact name of one of the auth cookies on this instance: __Host-<prefix>.<name> on https, <prefix>.<name> on http. */
  const cookieName = (name: string) => `${secureCookies ? '__Host-' : ''}${prefix}.${name}`;
  /** The auth cookies the single-copy rule covers: what the library reads for the session, a challenge and a known device. */
  const guardedCookies = () => [cookieName('session_token'), cookieName('two_factor'), cookieName(device.cookie)];
  const duplicated = (headers: HeadersInit | undefined, name: string) => cookiePairs(headers).filter(([key]) => key === name).length > 1;
  /**
   * The scopes a copy of an auth cookie can live in, so a refused duplicate is expired in each: `/`, every prefix of the
   * auth routes' base path and of the request's own path, and each legacy scope (a parent Domain among them). A __Host-
   * name exists only at Path=/ with no Domain, so it is expired there alone.
   */
  const expiryScopes = (name: string, path: string | undefined) => {
    if (name.startsWith('__Host-')) return [{ path: '/', domain: undefined as string | undefined }];
    const prefixes = (value: string) => value.split('/').filter(Boolean).map((_, at, parts) => `/${parts.slice(0, at + 1).join('/')}`);
    const paths = new Set(['/', ...prefixes(basePath), ...(path ? prefixes(path) : [])]);
    const all = [...[...paths].map(value => ({ path: value, domain: undefined as string | undefined })), ...scopes.slice(1)];
    return all.filter((scope, at) => all.findIndex(other => other.path === scope.path && other.domain === scope.domain) === at);
  };
  const expiry = (name: string, path: string | undefined) => expiryScopes(name, path).map(({ path: scope, domain }) =>
    `${name}=; Max-Age=0; Path=${scope}${domain ? `; Domain=${domain}` : ''}; HttpOnly; SameSite=Lax${secureCookies ? '; Secure' : ''}`);
  const expiredAuthCookies = (headers: HeadersInit | undefined, path?: string) => guardedCookies().filter(name => duplicated(headers, name)).flatMap(name => expiry(name, path));
  /** `response` with the expiring Set-Cookie values first, so a cookie the response itself sets after them stands. */
  const withExpired = (response: Response, headers: HeadersInit | undefined, path?: string) => {
    const expired = expiredAuthCookies(headers, path);
    if (!expired.length) return response;
    const merged = new Headers();
    for (const value of expired) merged.append('set-cookie', value);
    for (const [key, value] of response.headers) if (key.toLowerCase() !== 'set-cookie') merged.append(key, value);
    for (const value of response.headers.getSetCookie()) merged.append('set-cookie', value);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: merged });
  };
  /** Headers without the session cookie when it is sent more than once: the request is then answered as signed out. */
  const withoutDuplicateSession = (headers: HeadersInit | undefined): HeadersInit | undefined => {
    const name = cookieName('session_token');
    if (!duplicated(headers, name)) return headers;
    const kept = new Headers(headers);
    const pairs = cookiePairs(headers).filter(([key]) => key !== name).map(([key, value]) => `${key}=${value}`);
    if (pairs.length) kept.set('cookie', pairs.join('; ')); else kept.delete('cookie');
    return kept;
  };
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
  const verifiedUser = async (context: Parameters<Parameters<typeof createAuthEndpoint.serverOnly>[1]>[0], field: 'verifiedUserId' | 'oidcUserId') => {
    const userId = (context.body as Record<string, unknown> | undefined)?.[field];
    if (typeof userId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(userId)) throw APIError.fromStatus('BAD_REQUEST');
    const user = await context.context.internalAdapter.findUserById(userId);
    if (!user) throw APIError.fromStatus('UNAUTHORIZED');
    return user;
  };
  const issue = async (context: Parameters<Parameters<typeof createAuthEndpoint.serverOnly>[1]>[0], user: Awaited<ReturnType<typeof verifiedUser>>, provider: string | undefined) => {
    const created = await context.context.internalAdapter.createSession(user.id, false, provider === undefined ? undefined : { oidcProvider: provider });
    if (!created) throw APIError.fromStatus('INTERNAL_SERVER_ERROR');
    await setSessionCookie(context, { user, session: created });
    return context.json({ ok: true });
  };
  const oidcSessions = {
    id: 'ten98-oidc-session',
    endpoints: {
      rotateVerifiedSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async context => {
        const user = await verifiedUser(context, 'verifiedUserId');
        // Only the account's own current session can be rotated; this never signs anyone in. The new session keeps the
        // provider binding, so rotation never takes a session out of reach of revokeProviderSessions.
        const current = await getSessionFromCtx(context);
        if (!current || current.user.id !== user.id) throw APIError.fromStatus('UNAUTHORIZED');
        const response = await issue(context, user, providerKey((current.session as { oidcProvider?: unknown }).oidcProvider));
        await context.context.internalAdapter.deleteSession(current.session.token);
        return response;
      }),
      completeOidcSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async context => {
        const provider = providerKey((context.body as Record<string, unknown> | undefined)?.provider);
        if (provider === undefined) throw APIError.fromStatus('BAD_REQUEST');
        const user = await verifiedUser(context, 'oidcUserId');
        // The same usability read as the reset routes (storedAccount): an unmapped closed_at fails loudly, never open, and
        // an unusable account gets the unknown-user 401.
        if (await refusedAccount(await getCurrentAdapter(context.context.adapter), { field: 'id', value: user.id })) throw APIError.fromStatus('UNAUTHORIZED');
        return issue(context, user, provider);
      }),
    },
  } as const;
  // The provider binding of a session created without one (#143). Every sign-in challenge is opened with an
  // `oidc-challenge:<challenge>` row holding its provider (completeOidcSession) or '' (a password sign-in), read and
  // deleted when the challenge creates its session. A challenge with no such row was revoked while it was being opened
  // (revokeProviderSessions deleted the row written just before it), so it never completes. Any other session created
  // while one is current (a password change's replacement, say) keeps the current session's provider.
  type HookContext = {
    path?: string;
    body?: Record<string, unknown>;
    getSignedCookie(name: string, secret: string): Promise<string | null | false>;
    context: { secret: string; session?: { session?: { oidcProvider?: unknown } } | null; createAuthCookie(name: string): { name: string };
      internalAdapter: StoreContext['internalAdapter'] & {
        findVerificationValue(identifier: string): Promise<{ value: string } | null>;
        deleteVerificationByIdentifier(identifier: string): Promise<void>;
      } };
  } | null | undefined;
  const boundProvider = async (context: HookContext): Promise<string | undefined> => {
    const current = providerKey(context?.context.session?.session?.oidcProvider);
    if (current !== undefined || !context || context.context.session || !twoFactorPaths.has(context.path ?? '')) return current;
    const challenge = await context.getSignedCookie(context.context.createAuthCookie('two_factor').name, context.context.secret);
    if (typeof challenge !== 'string' || !challenge) return undefined;
    const binding = await context.context.internalAdapter.findVerificationValue(challengeProviderPrefix + challenge);
    if (!binding) throw APIError.fromStatus('UNAUTHORIZED');
    await context.context.internalAdapter.deleteVerificationByIdentifier(challengeProviderPrefix + challenge);
    return providerKey(binding.value);
  };
  const databaseHooks: BetterAuthOptions['databaseHooks'] = {
    session: { create: { async before(data, context) {
      if (providerKey((data as { oidcProvider?: unknown }).oidcProvider) !== undefined) return;
      const provider = await boundProvider(context as unknown as HookContext);
      return provider === undefined ? undefined : { data: { ...data, oidcProvider: provider } };
    } } },
    verification: { create: { async before(data, context) {
      // A sign-in challenge the two-factor plugin opens: its identifier is exactly '2fa-' and 20 characters of
      // better-auth's generateRandomString (letters, digits, '-' and '_'); its '2fa-attempts-' and '2fa-otp-' rows name
      // the challenge and are always longer. completeOidcSession is a server call (no path); any other is a password sign-in.
      const hook = context as unknown as HookContext;
      if (!hook || !/^2fa-[A-Za-z0-9_-]{20}$/.test(data.identifier)) return;
      const provider = hook.path === undefined && typeof hook.body?.oidcUserId === 'string' ? providerKey(hook.body.provider) : undefined;
      await hook.context.internalAdapter.createVerificationValue({ identifier: challengeProviderPrefix + data.identifier, value: provider ?? '', expiresAt: data.expiresAt });
    } } },
  };
  // Replaces better-auth's /revoke-other-sessions (a plugin endpoint of the same name wins), which compares the caller's
  // raw token with the listed handles. This one keeps the current session by id and deletes the user's other live
  // sessions through the adapter, so inside withLockedAuth it runs in that transaction.
  const sessionRevocation = {
    id: 'ten98-session-revocation',
    endpoints: {
      revokeOtherSessions: createAuthEndpoint('/revoke-other-sessions', { method: 'POST', requireHeaders: true, use: [sensitiveSessionMiddleware] }, async context => {
        const current = context.context.session.session;
        const adapter = await getCurrentAdapter(context.context.adapter);
        const revoked = await adapter.deleteMany({ model: 'session', where: [
          { field: 'userId', value: current.userId },
          { field: 'id', operator: 'ne', value: current.id },
          { field: 'expiresAt', operator: 'gt', value: new Date() },
        ] });
        await forgetDevices(adapter as unknown as StoreAdapterSurface, current.userId);
        return context.json({ status: true as const, revoked });
      }),
    },
  } as const;

  // Issues the browser a known-device entry for this account, replacing (rotating) the one it held: the old device row
  // and its attempt rows go, a new random device id gets a fresh 90 days, and the cookie keeps the browser's entries for
  // other accounts. The device id is random and says nothing about the device; each account gets its own.
  type DeviceHook = {
    getCookie(name: string): string | null;
    setCookie(name: string, value: string, attributes?: Record<string, unknown>): unknown;
    context: { adapter: unknown; internalAdapter: StoreContext['internalAdapter']; createAuthCookie: StoreContext['createAuthCookie'] };
  };
  const issueDevice = async (context: DeviceHook, userId: string) => {
    const cookie = context.context.createAuthCookie(device.cookie, { maxAge: device.lifetimeSeconds });
    const entries = deviceEntries(singleCookie((context as unknown as { headers?: Headers }).headers, cookie.name));
    const previous = deviceFor(keys, userId, entries);
    const adapter = await getCurrentAdapter(context.context.adapter as never) as unknown as StoreAdapterSurface;
    if (previous) {
      for (const identifier of [deviceRow(previous.deviceId), attemptRow(previous.deviceId)]) {
        await adapter.deleteMany({ model: 'verification', where: [{ field: 'identifier', value: identifier }, { field: 'value', value: userId }] });
      }
    }
    const deviceId = newDeviceId(keys);
    await context.context.internalAdapter.createVerificationValue({ identifier: deviceRow(deviceId), value: userId, expiresAt: new Date(Date.now() + device.lifetimeSeconds * 1000) });
    const live = await adapter.findMany<{ id: string }>({ model: 'verification', where: [{ field: 'value', value: userId }, { field: 'identifier', operator: 'starts_with', value: 'known-device:' }], sortBy: { field: 'createdAt', direction: 'desc' } });
    for (const stale of live.slice(device.devices)) await adapter.delete({ model: 'verification', where: [{ field: 'id', value: stale.id }] });
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
        matcher: (context: { path?: string; body?: { oidcUserId?: unknown } }) => signInPaths.has(context.path ?? '') || (context.path === undefined && typeof context.body?.oidcUserId === 'string'),
        handler: createAuthMiddleware(async context => {
          const created = context.context.newSession;
          if (!created || isAPIError(context.context.returned)) return;
          // Confirming a factor while enabling two-factor is not a sign-in; only a sign-in challenge carries this cookie.
          if (context.path?.startsWith('/two-factor/') && !context.getCookie(context.context.createAuthCookie('two_factor').name)) return;
          await issueDevice(context as unknown as DeviceHook, created.user.id);
        }),
      },
      {
        matcher: (context: { path?: string }) => revokingPaths.has(context.path ?? ''),
        handler: createAuthMiddleware(async context => {
          const userId = context.context.session?.user.id;
          if (!userId || isAPIError(context.context.returned)) return;
          await forgetDevices(await getCurrentAdapter(context.context.adapter) as unknown as StoreAdapterSurface, userId);
        }),
      },
    ] },
  };

  // With legacy hashes accepted, every password check runs one legacy derive and one current derive, whichever hash is
  // stored or none, so response time does not reveal which accounts are unmigrated.
  const legacyPassword = legacyPasswords ? {
    hash: async (candidate: string) => (await Promise.all([hashPassword(candidate), verifyLegacyScryptHash(DUMMY_LEGACY_HASH, candidate)]))[0],
    verify: async ({ hash, password: candidate }: { hash: string; password: string }) => {
      const legacy = isLegacyHash(hash);
      const [legacyOk, modernOk] = await Promise.all([
        verifyLegacyScryptHash(legacy ? hash : DUMMY_LEGACY_HASH, candidate),
        verifyPassword({ hash: legacy ? await modernDummy() : hash, password: candidate }),
      ]);
      return legacy ? legacyOk : modernOk;
    },
  } : undefined;

  /**
   * The TOTP replay ledger (RFC 6238 section 5.2): one verification row per user, `totp-step:<userId>` (stored hashed like
   * every identifier), holding the last time step a code was accepted for, never the code. better-auth's verifier says
   * only whether a code matched, so the preset finds the step itself, with the user's secret (decrypted with better-auth's
   * own key, as its route does) and the same digits, period and ±1 window. Every read and write runs on the transaction
   * that holds the user's row, so two submissions of one code are serialised and only the first is accepted.
   */
  const ledger = {
    row: (userId: string) => `totp-step:${userId}`,
    async secretOf(store: StoreContext, userId: string, verifiedOnly: boolean) {
      const row = await store.adapter.findOne<{ secret: string; verified?: boolean | null }>({ model: 'twoFactor', where: [{ field: 'userId', value: userId }] });
      if (!row || (verifiedOnly && row.verified === false)) return undefined;
      return symmetricDecrypt({ key: store.secretConfig as never, data: row.secret });
    },
    async last(store: StoreContext, userId: string) {
      const row = await store.adapter.findOne<{ id: string; value: string; expiresAt: Date | string }>({ model: 'verification', where: [{ field: 'identifier', value: ledger.row(userId) }] });
      const step = row && new Date(row.expiresAt).getTime() > Date.now() ? Number(row.value) : Number.NEGATIVE_INFINITY;
      return { row, step: Number.isSafeInteger(step) ? step : Number.NEGATIVE_INFINITY };
    },
    // The row expires once no code of that step can match any more: steps up to it then fall outside the window anyway.
    async record(store: StoreContext, userId: string, step: number) {
      const { row } = await ledger.last(store, userId);
      const expiresAt = new Date((step + 2) * factor.periodSeconds * 1000);
      if (row) await store.adapter.update({ model: 'verification', where: [{ field: 'id', value: row.id }], update: { value: String(step), expiresAt } });
      else await store.internalAdapter.createVerificationValue({ identifier: ledger.row(userId), value: String(step), expiresAt });
    },
    /** The step a TOTP code is accepted for now, or undefined when it matches none, or only one at or before the last. */
    async fresh(store: StoreContext, userId: string, code: unknown, verifiedOnly: boolean) {
      const secret = await ledger.secretOf(store, userId, verifiedOnly);
      const { step: last } = await ledger.last(store, userId);
      const step = secret === undefined || typeof code !== 'string' ? undefined : matchedStep(secret, code);
      return step !== undefined && step > last ? step : undefined;
    },
  };
  /**
   * A TOTP request (verify-totp, at sign-in or with a session) run through the ledger: a code that is not fresh reaches
   * better-auth as a code that matches nothing, so it is refused, counted and answered exactly as a wrong code; a fresh
   * one is recorded once better-auth accepts it.
   */
  const throughLedger = async (bound: object, userId: string, request: Request, run: (request: Request) => Promise<Response>) => {
    if (!totpRoute.test(new URL(request.url).pathname)) return run(request);
    const body = await request.clone().json().catch(() => undefined) as { code?: unknown } | undefined;
    if (!body || typeof body.code !== 'string') return run(request);
    const store = await storeOf(bound);
    const step = await ledger.fresh(store, userId, body.code, false);
    const sent = step !== undefined ? request : new Request(request.url, { method: 'POST', headers: request.headers, body: JSON.stringify({ ...body, code: notACode }) });
    const response = await run(sent);
    if (response.ok && step !== undefined) await ledger.record(store, userId, step);
    return response;
  };
  /** The isAccountUsable hook, refusing a closed account by default. */
  const usable = (account: { id: string; email: string; closedAt: Date | null }) => options.isAccountUsable ? options.isAccountUsable(account) : account.closedAt === null;
  /**
   * The account an isAccountUsable check outside signInWithPassword reads (a reset or completeOidcSession, by id or
   * lower-cased email): one
   * indexed read of the user row's id, email and closedAt, never joined, so it costs the same whether or not a row
   * exists. Through the adapter, whose user model must map closed_at as closedAt: without it the select throws, so the
   * check fails loudly instead of being skipped (instanceSchema refuses such an adapter at start-up).
   */
  const accountRow = (adapter: unknown, where: { field: 'id' | 'email'; value: string }) =>
    (adapter as { findOne<T>(query: { model: string; where: { field: string; value: string }[]; select: string[] }): Promise<T | null> })
      .findOne<{ id: string; email: string; closedAt?: Date | null }>({ model: 'user', where: [where], select: ['id', 'email', 'closedAt'] });
  // Drizzle cannot build a select of an unmapped field and throws a TypeError: the same 500, naming the mapping, as a row
  // read without the field, whether or not the start-up check has run.
  const unmappedClosedAt = () => new APIError('INTERNAL_SERVER_ERROR', { message: 'The Drizzle user table must map closed_at as closedAt.' });
  const storedAccount = async (adapter: unknown, where: { field: 'id' | 'email'; value: string }) => {
    let found: Awaited<ReturnType<typeof accountRow>>;
    try { found = await accountRow(adapter, where); } catch (error) { if (error instanceof TypeError) throw unmappedClosedAt(); throw error; }
    if (found && found.closedAt === undefined) throw unmappedClosedAt();
    return found;
  };
  const refusedAccount = async (adapter: unknown, where: { field: 'id' | 'email'; value: string }) => {
    const found = await storedAccount(adapter, where);
    return found !== null && await usable({ id: found.id, email: found.email, closedAt: found.closedAt ?? null }) !== true;
  };

  const auth = betterAuth({
    database: protectTokens(database as AdapterFactory, keys) as unknown as BetterAuthOptions['database'], baseURL: origin, secret, appName, trustedOrigins: [origin],
    // better-auth skips these checks when NODE_ENV=test or TEST is set unless they are pinned.
    // On https every auth cookie is named __Host-<prefix>.<name> (Secure, Path=/, no Domain), better-auth's and the
    // preset's alike, so no sibling subdomain or other path can set one the preset reads. better-auth would prefix
    // __Secure- itself; that is turned off and each name given in full, with Secure on every cookie.
    advanced: { disableOriginCheck: false, disableCSRFCheck: false, cookiePrefix: prefix,
      ...(secureCookies ? { useSecureCookies: false, defaultCookieAttributes: { secure: true },
        cookies: Object.fromEntries(authCookieNames.map(name => [name, { name: cookieName(name), attributes: { secure: true, path: '/' } }])) } : {}) },
    // Self-hosted installs send no data to Ten98 or third parties.
    telemetry: { enabled: false },
    // Adapter failures can contain query parameters, and better-call logs non-API exceptions even with the logger off,
    // so every unexpected error becomes a bare 500 before it can expose SQL, hashes or tokens.
    logger: { disabled: true },
    // A deadlock or serialisation failure is a retryable 503 instead.
    onAPIError: { onError(error) { if (isAPIError(error)) throw error; throw APIError.fromStatus(retryable(error) ? 'SERVICE_UNAVAILABLE' : 'INTERNAL_SERVER_ERROR'); } },
    // oidcProvider is server-set only (input: false): no request can bind or unbind a session.
    session: { expiresIn: session.expiresInSeconds, updateAge: session.updateAgeSeconds, cookieCache: { enabled: false },
      additionalFields: { oidcProvider: { type: 'string', required: false, input: false } } },
    // closed_at, read by every isAccountUsable check outside signInWithPassword (storedAccount); never written through
    // better-auth nor returned by it.
    user: { additionalFields: { closedAt: { type: 'date', required: false, input: false, returned: false, defaultValue: () => null } } },
    // Identities are linked and unlinked only through linkOidcIdentity and unlinkOidcIdentity, under the user's lock.
    disabledPaths: [...Object.keys(disabledRoutes)],
    databaseHooks,
    plugins: [factors, oidcSessions, sessionRevocation, knownDevices],
    emailAndPassword: {
      enabled: true,
      disableSignUp: true,
      minPasswordLength: password.minLength,
      maxPasswordLength: password.maxLength,
      resetPasswordTokenExpiresIn: reset.expiresInSeconds,
      revokeSessionsOnPasswordReset: reset.revokesSessions,
      ...(sendResetPassword ? { sendResetPassword: async ({ user, token }: { user: { id: string; email: string }; token: string }) => { await sendResetPassword({ userId: user.id, email: user.email, token }); } } : {}),
      // A reset also ends trusted devices, pending two-factor challenges and known devices, so the new password alone
      // never skips the factor and no browser stays trusted across it.
      onPasswordReset: async ({ user }: { user: { id: string } }) => {
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
    hooks: { before: createAuthMiddleware(async context => {
      // An account isAccountUsable refuses (by default a closed one) gets no reset. The request is handed to better-auth's
      // route with an address no account has (a reset token no row has), so it takes the route's own unknown-email (invalid
      // token) path, after the same validation and origin checks: the same answer, no token, nothing sent.
      const { internalAdapter } = context.context;
      const adapter = await getCurrentAdapter(context.context.adapter);
      const body = (context.body ?? {}) as { email?: unknown; token?: unknown };
      // A body the route's own schema rejects is left to the route, so its 400 stays the same for every account.
      if (context.path === '/request-password-reset' && sendResetPassword && typeof body.email === 'string' && resetBody.safeParse(body).success) {
        // Every request makes this one read, so an existing account costs what an unknown email does.
        if (await refusedAccount(adapter, { field: 'email', value: body.email.toLowerCase() })) {
          return { context: { body: { ...body, email: `${randomBytes(12).toString('hex')}@unusable-account.invalid` } } };
        }
      }
      if (context.path === '/reset-password') {
        const token = body.token || (context.query as { token?: unknown } | undefined)?.token;
        if (typeof token !== 'string' || !token) return;
        const row = await internalAdapter.findVerificationValue(`reset-password:${token}`);
        if (row && await refusedAccount(adapter, { field: 'id', value: row.value })) {
          return { context: { body: { ...body, token: randomBytes(18).toString('base64url') } } };
        }
      }
    }), after: createAuthMiddleware(async context => {
      const path = context.path ?? '';
      if ((path !== '/sign-in/email' && !twoFactorPaths.has(path)) || isAPIError(context.context.returned)) return;
      // The account this sign-in (or completed challenge) created a session (or a two-factor challenge) for, read before
      // the two-factor plugin's hook clears it, so signInWithPassword and verifyTwoFactor can check it is the one locked.
      const signedIn = context.context.newSession?.user.id;
      if (internal.signedIn && signedIn) internal.signedIn(signedIn);
      if (path !== '/sign-in/email') return;
      // signInWithPassword replaces a legacy hash itself, in a savepoint of its locked transaction. Here (raw sign-in,
      // allowRawPasswordSignIn) it is best effort: a failure leaves the legacy hash for the next sign-in.
      if (!legacyPasswords || internal.signedIn) return;
      const { email, password: candidate } = (context.body ?? {}) as { email?: unknown; password?: unknown };
      if (typeof email !== 'string' || typeof candidate !== 'string') return;
      try {
        const found = await context.context.internalAdapter.findUserByEmail(email.toLowerCase(), { includeAccounts: true });
        const credential = found?.accounts.find(account => account.providerId === 'credential');
        if (found && credential?.password && isLegacyHash(credential.password)) await context.context.internalAdapter.updatePassword(found.user.id, await hashPassword(candidate));
      } catch { /* retried on the next successful sign-in */ }
    }) },
  });
  // The request-reset route's body schema, as better-auth validates it after the before hooks; read before any wrapping.
  const resetBody = (auth.api as unknown as { requestPasswordReset: { options: { body: { safeParse(input: unknown): { success: boolean } } } } }).requestPasswordReset.options.body;
  // disabledPaths turns a route off in the router only: its server call (auth.api.*) would still run. Each one throws
  // instead, naming what to use, on this instance and on every bound one.
  for (const [name, endpoint] of Object.entries(auth.api as unknown as Record<string, { path?: unknown }>)) {
    const path = typeof endpoint?.path === 'string' ? endpoint.path : undefined;
    if (path === undefined || !Object.hasOwn(disabledRoutes, path)) continue;
    const message = `auth.api.${name} (${path}) is off in the preset: ${disabledRoutes[path]}.`;
    Object.assign(auth.api, { [name]() { throw new TypeError(message); } });
  }
  /** The challenge a request's single, signed two_factor cookie names: a live '2fa-' challenge row of an existing account. */
  const readChallenge = async (instance: object, headers: HeadersInit | undefined) => {
    const cookie = singleCookie(headers, cookieName('two_factor'));
    if (cookie === undefined || cookie.startsWith('"')) return null;
    const identifier = signedValue(cookie, secret);
    if (identifier === undefined || !challengeIdentifier.test(identifier)) return null;
    const { adapter } = await storeOf(instance);
    const row = await adapter.findOne<{ value: string; expiresAt: Date | string }>({ model: 'verification', where: [{ field: 'identifier', value: identifier }] });
    if (!row || !(new Date(row.expiresAt).getTime() > Date.now()) || typeof row.value !== 'string' || !row.value) return null;
    const user = await adapter.findOne<{ id: string }>({ model: 'user', where: [{ field: 'id', value: row.value }] });
    if (!user) return null;
    return { identifier, userId: user.id, limitKey: `v1.${mac(keys.challengeLimit, identifier)}` };
  };
  {
    const route = auth.handler.bind(auth);
    const guarded = async (request: Request) => {
      const headers = withoutDuplicateSession(request.headers);
      return withExpired(await route(headers === request.headers ? request : new Request(request, { headers })), request.headers, new URL(request.url).pathname);
    };
    Object.assign(auth, { handler: guarded, fetch: guarded });
    const api = auth.api as unknown as Record<string, unknown>;
    for (const [name, call] of Object.entries(api)) {
      if (typeof call !== 'function') continue;
      api[name] = Object.assign((input?: { headers?: HeadersInit }) => {
        const headers = withoutDuplicateSession(input?.headers);
        return (call as (input?: unknown) => unknown)(headers === input?.headers ? input : { ...input, headers });
      }, call);
    }
  }
  const helpers = {
    cookieName: (name: string) => {
      if (typeof name !== 'string' || !/^[a-z_]{1,64}$/.test(name)) throw new TypeError('cookieName takes a cookie name such as two_factor or session_token.');
      return cookieName(name);
    },
    readTwoFactorChallenge: (request: Request) => {
      if (!(request instanceof Request)) throw new TypeError('readTwoFactorChallenge takes the request.');
      return readChallenge(auth, request.headers);
    },
    expiredAuthCookies: (headers: HeadersInit, path?: string) => expiredAuthCookies(headers, typeof path === 'string' ? path : undefined),
    storedVerificationIdentifier: (identifier: string) => storedIdentifier(keys, raw(identifier)),
    sessionTokenKey: (token: string) => tokenHandle(keys, raw(token)),
  };
  /** Which locked route a request needs: a password sign-in, any two-factor request, or neither. */
  const signInKind = (path: string): 'password' | 'twoFactor' | undefined =>
    passwordRoute.test(path) ? 'password' : twoFactorRoute.test(path) ? 'twoFactor' : undefined;
  /** The server calls of the two-factor routes, by name: they too go only through verifyTwoFactor. */
  const twoFactorCalls = new Set(Object.entries(auth.api as unknown as Record<string, { path?: unknown }>)
    .filter(([, endpoint]) => typeof endpoint?.path === 'string' && endpoint.path.startsWith('/two-factor/')).map(([name]) => name));
  // better-auth's own handler, for a two-factor request without a session: it answers that request's 401 itself.
  const unlocked = auth.handler.bind(auth);
  if (!locking) return Object.assign(auth, helpers) as unknown as LockedTen98Auth;
  // On the instance the app holds, better-auth's own password sign-in has no limit, no lock and no constant-cost check,
  // so it is off: the route (any case, any trailing slash) answers 404 and api.signInEmail throws.
  // Every two-factor request (completing a sign-in's challenge, enrolling, disabling, recovery codes) goes only through
  // verifyTwoFactor, under the account's lock, for the same reason; the refusal names it, so a missed route fails loudly.
  if (options.allowRawPasswordSignIn !== true) {
    const route = auth.handler.bind(auth);
    const routed = (request: Request) => {
      const kind = signInKind(new URL(request.url).pathname);
      if (kind === 'twoFactor') return Promise.resolve(refusal(404, 'NOT_FOUND', twoFactorRouting));
      return kind ? Promise.resolve(refusal(404, 'NOT_FOUND', 'Not found.')) : route(request);
    };
    Object.assign(auth, { handler: routed, fetch: routed });
    const api = auth.api as unknown as Record<string, (input?: { headers?: HeadersInit }) => unknown>;
    Object.assign(api, { signInEmail() { throw new TypeError('Password sign-in is only supported through signInWithPassword.'); } });
    for (const name of twoFactorCalls) Object.assign(api, { [name]() { throw new TypeError(`auth.api.${name}: ${twoFactorRouting}`); } });
  }
  const { lockTimeoutMs = 5000 } = options;
  if (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs < 1 || lockTimeoutMs > 600_000) throw new TypeError('lockTimeoutMs must be an integer from 1 to 600000.');
  const slots = boundedSlots(options.passwordVerification);
  const { concurrency: laneConcurrency = 1, queue: laneQueue = 20, waitMs: laneWaitMs = options.passwordVerification?.waitMs } = options.passwordVerification?.knownDevices ?? {};
  const lane = boundedSlots({ concurrency: laneConcurrency, queue: laneQueue, waitMs: laneWaitMs }, 'passwordVerification.knownDevices');
  const claims = boundedSlots(device.claims, 'knownDeviceClaims');
  void modernDummy();

  /**
   * Binds an instance to the transaction for `run`. The callback gets its own transaction object over a guarded view of
   * the connection, and both are marked (tenancy and team operations refuse them; `hold.email` is the email lock already
   * held). When `run` settles, before COMMIT, the view and the instance close: a later or un-awaited call throws
   * LockedAuthClosedError instead of running outside the lock on a connection back in the pool.
   */
  const bind = async <TDatabase extends AnyDatabase, T>(tx: ScopedTransaction<TDatabase>, hold: { userId: string | undefined; email: string | undefined },
    run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>) => Promise<T>, allowed?: 'password' | 'twoFactor') => {
    // drizzle-orm internals, as transaction() in ./db reads them; drizzle-orm is pinned exactly for this reason.
    const { dialect, _: { session: inner } } = tx as unknown as { dialect: never; _: { session: { client: pg.PoolClient; schema: never; options: never } } };
    const connection = inner.client;
    let open = true;
    const closed = () => new LockedAuthClosedError();
    const guarded = new Proxy(connection, {
      get(target, key) {
        const value: unknown = Reflect.get(target, key, target);
        if (typeof value !== 'function') return value;
        if (key === 'query') return (...args: unknown[]) => open ? (value as (...input: unknown[]) => unknown).apply(target, args) : Promise.reject(closed());
        return (value as (...input: unknown[]) => unknown).bind(target);
      },
    });
    const callbackTx = new NodePgTransaction(dialect, new NodePgSession(guarded, dialect, inner.schema, inner.options), inner.schema) as unknown as ScopedTransaction<TDatabase>;
    // For signInWithPassword and verifyTwoFactor: the account better-auth's sign-in created a session for, to compare
    // with the locked one.
    let signedIn: string | undefined;
    const bound = build({ ...options, database: transactionDatabase!(callbackTx as ScopedTransaction<AnyDatabase>) }, keys, false,
      allowed ? { signedIn(userId) { signedIn = userId; } } : {}) as LockedTen98Auth;
    Object.defineProperty(bound, signedInUser, { value: () => signedIn });
    // signInEmail holds this transaction's connection and lock while it hashes; only signInWithPassword, after its own
    // check outside any transaction, may call it here. A challenge is completed only by verifyTwoFactor, which checks
    // the account first.
    const refusals = {
      password: 'Password sign-in inside a locked-auth transaction holds a pool connection while it hashes; use signInWithPassword.',
      twoFactor: twoFactorRouting,
    } as const;
    const check = (kind: 'password' | 'twoFactor' | undefined) => {
      if (!open) throw closed();
      if (kind && kind !== allowed) throw new TypeError(refusals[kind]);
    };
    const apiKind = (key: PropertyKey) => key === 'signInEmail' ? 'password' : typeof key === 'string' && twoFactorCalls.has(key) ? 'twoFactor' : undefined;
    const api = bound.api as unknown as Record<PropertyKey, unknown>;
    const handler = bound.handler.bind(bound);
    Object.assign(bound, {
      userId: hold.userId,
      api: new Proxy(api, { get(target, key) {
        const value = target[key];
        return typeof value === 'function' ? (...args: unknown[]) => { check(apiKind(key)); return (value as (...input: unknown[]) => unknown).apply(target, args); } : value;
      } }),
      handler(request: Request) { check(signInKind(new URL(request.url).pathname)); return handler(request); },
      // better-auth's fetch is the same handler; it gets the same checks.
      fetch(request: Request) { check(signInKind(new URL(request.url).pathname)); return handler(request); },
      async revokeAllSessions() {
        check(undefined);
        if (hold.userId === undefined) return;
        const store = await storeOf(bound);
        await store.internalAdapter.deleteUserSessions(hold.userId);
        await forgetDevices(store.adapter, hold.userId);
      },
    });
    const unmark = markLockedAuth({ email: hold.email, userId: hold.userId }, callbackTx, connection);
    const lockedUserId = hold.userId;
    // verifyCodeForAction and linkOidcIdentity find this transaction's code check here, for the user it locked.
    if (lockedUserId !== undefined && hold.email === undefined) {
      codeChecks.set(callbackTx, {
        userId: lockedUserId,
        async check(code: unknown) {
          if (!open) throw closed();
          const store = await storeOf(bound);
          const step = await ledger.fresh(store, lockedUserId, code, true);
          if (step === undefined) return false;
          await ledger.record(store, lockedUserId, step);
          return true;
        },
      });
    }
    try { return await lockedContext.run(true, () => run(bound, callbackTx)); } finally { open = false; unmark(); codeChecks.delete(callbackTx); }
  };
  // Refused before any statement: without the factory there is nothing to bind; a transaction as `db`, or a database on
  // a locked-auth connection, would put the lock inside another transaction; a second locked-auth transaction opened in
  // a callback would wait on the first's locks (one user per transaction); inside a better-auth request or hook,
  // better-auth's own adapter context would route the bound instance's queries away from `tx`, outside the lock.
  const ready = async (db: unknown, run: unknown) => {
    if (!transactionDatabase) throw new TypeError('withLockedAuth needs the transactionDatabase option of createTen98Auth.');
    if (db instanceof PgTransaction) throw new TypeError('withLockedAuth opens its own transaction; pass the database, not a transaction.');
    if (typeof run !== 'function') throw new TypeError('withLockedAuth needs a callback.');
    if (lockedContext.getStore()) throw new LockedAuthTransactionError('withLockedAuth');
    refuseLockedAuth(db, 'withLockedAuth');
    const outside = {};
    if (await getCurrentAdapter(outside as never) !== outside) throw new TypeError('withLockedAuth cannot run inside a better-auth request or hook.');
    await instanceSchema(db as AnyDatabase);
  };
  /** The database schema, then the adapter's user model: it must map closed_at as closedAt, which the reset checks read. */
  let adapterChecked: { check: Promise<void>; retryAt: number } | undefined;
  const instanceSchema = async (db: AnyDatabase) => {
    await schemaOf(db);
    adapterChecked = recheckable(adapterChecked, async () => {
      // Drizzle cannot build a select of an unmapped field and throws a TypeError; any other failure is reported as it is.
      const { adapter } = await storeOf(auth);
      try { await accountRow(adapter, { field: 'id', value: '' }); } catch (error) {
        if (error instanceof TypeError) throw new SchemaMismatchError(['closedAt (closed_at) in the adapter\'s user model']);
        throw error;
      }
      // A Drizzle adapter names the column closedAt maps to: it must be closed_at, a timestamp with time zone. Mapped to
      // another column (updatedAt, a boolean), every account would read as closed or open by accident.
      const column = (adapter as { options?: { schema?: Record<string, Record<string, { name?: unknown; columnType?: unknown; withTimezone?: unknown } | undefined> | undefined> } })
        .options?.schema?.user?.closedAt;
      if (column && (column.name !== 'closed_at' || column.columnType !== 'PgTimestamp' || column.withTimezone !== true)) {
        throw new SchemaMismatchError([`closedAt mapped to ${String(column.name)} (${String(column.columnType)}); it must map closed_at, a timestamp with time zone`]);
      }
    });
    return adapterChecked.check;
  };
  // Parameterised raw statements by necessity: Drizzle has no builder for set_config or advisory locks. The timeout comes
  // first, so the lock statements that follow cannot wait forever.
  const limitLockWaits = (tx: AnyDatabase) => tx.execute(sql`SELECT set_config('lock_timeout', ${`${lockTimeoutMs}ms`}, true)`);
  const byEmail = <TDatabase extends AnyDatabase, T>(db: TDatabase, address: string, run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>, userId: string | undefined) => Promise<T>, allowed?: 'password' | 'twoFactor') =>
    transaction(db, async tx => {
      await limitLockWaits(tx);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${emailLockKey}, hashtext(${address}))`);
      // lower() on both sides, as user_email_normalized_idx is defined, whatever JavaScript's lowercasing did. That index
      // makes the match unique; were it dropped after the start-up check, two matches are refused, never one picked.
      const rows = await tx.select({ id: userTable.id }).from(userTable).where(sql`lower(${userTable.email}) = lower(${address})`).for('no key update');
      if (rows.length > 1) throw new AmbiguousAccountError();
      return bind(tx, { userId: rows[0]?.id, email: address }, (auth, bound) => run(auth, bound, rows[0]?.id), allowed);
    });
  /**
   * The id of the attempt row claimed for this browser's known device of the account behind `address`, or undefined.
   * True only when an entry's tag verifies for that account, its device row exists, belongs to that user and has not
   * expired, and fewer than `device.attempts` attempts are claimed since its last success. The tag is checked on a plain
   * read first, so a forged or foreign cookie takes no lock; the claim itself runs under the account's email and user
   * locks, so concurrent attempts claim exactly.
   */
  const claimDevice = async (db: AnyDatabase, address: string, headers: HeadersInit | undefined): Promise<string | undefined> => {
    const store = await storeOf(auth);
    // Only one exact copy, and only entries whose device id carries its own MAC: forged cookies never reach the database
    // or a claim slot.
    const entries = deviceEntries(singleCookie(headers, store.createAuthCookie(device.cookie).name)).filter(entry => deviceIdSigned(keys, entry.deviceId));
    if (!entries.length) return undefined;
    // At most `device.claims` claims at once in this process (each one pool read, then one short locked transaction)
    // and a few waiting; past that the browser counts as not known, so its cookie never holds more of the pool than that.
    const release = await claims();
    if (!release) return undefined;
    try { return await claimed(db, address, entries); } finally { release(); }
  };
  const claimed = async (db: AnyDatabase, address: string, entries: DeviceEntry[]): Promise<string | undefined> => {
    const [account] = await db.select({ id: userTable.id }).from(userTable).where(sql`lower(${userTable.email}) = lower(${address})`).limit(1);
    const entry = account ? deviceFor(keys, account.id, entries) : undefined;
    if (!account || !entry) return undefined;
    // Two accounts at one email (the index dropped after start-up) claim nothing; the sign-in itself refuses them.
    return byEmail(db, address, async (bound, _tx, userId) => {
      if (userId !== account.id) return undefined;
      const { adapter, internalAdapter } = await storeOf(bound);
      const row = await adapter.findOne<{ value: string; expiresAt: Date | string }>({ model: 'verification', where: [{ field: 'identifier', value: deviceRow(entry.deviceId) }] });
      const expiresAt = row ? new Date(row.expiresAt) : undefined;
      if (!row || row.value !== userId || !expiresAt || !(expiresAt.getTime() > Date.now())) return undefined;
      if (await adapter.count({ model: 'verification', where: [{ field: 'identifier', value: attemptRow(entry.deviceId) }] }) >= device.attempts) return undefined;
      return (await internalAdapter.createVerificationValue({ identifier: attemptRow(entry.deviceId), value: userId, expiresAt })).id;
    }).catch(error => { if (error instanceof AmbiguousAccountError) return undefined; throw error; });
  };
  const locked: Pick<Ten98Auth, 'withLockedAuth' | 'withLockedAuthByEmail' | 'signInWithPassword' | 'assertEmailIndex' | 'assertSchema' | 'verifyTwoFactor'> = {
    async withLockedAuth(db, userId, run) {
      await ready(db, run);
      if (typeof userId !== 'string' || !userId) throw new TypeError('withLockedAuth needs a user id.');
      return transaction(db, async tx => {
        await limitLockWaits(tx);
        const [row] = await tx.select({ id: userTable.id }).from(userTable).where(eq(userTable.id, userId)).for('no key update');
        if (!row) throw new LockedAuthUserNotFoundError();
        return bind(tx, { userId: row.id, email: undefined }, run);
      });
    },
    async withLockedAuthByEmail(db, email, run) {
      await ready(db, run);
      if (typeof email !== 'string') throw new TypeError('withLockedAuthByEmail needs an email.');
      // Normalised as the team controller's lockEmail does, so both take the same advisory lock.
      return byEmail(db, email.trim().toLowerCase(), run);
    },
    async signInWithPassword(db, input, limits) {
      const { source: sourceLimit, account: accountLimit } = (limits ?? {}) as Partial<PasswordSignInLimits>;
      if (typeof sourceLimit !== 'function' || typeof accountLimit !== 'function') throw new TypeError('signInWithPassword needs the app\'s rate limits: { source, account }.');
      await ready(db, accountLimit);
      const { email, password, source, rememberMe, headers } = (input ?? {}) as Partial<PasswordSignIn>;
      if (typeof source !== 'string' || !source) throw new TypeError('signInWithPassword needs the request\'s source (the client address the app derived).');
      if (typeof email !== 'string' || typeof password !== 'string' || (rememberMe !== undefined && typeof rememberMe !== 'boolean')) return refusal(400, 'INVALID_INPUT', 'Enter an email and a password.');
      // better-auth checks the origin only for a request it routes itself, not for this server call, so the browser's
      // Origin and Sec-Fetch-Site are checked here: a cross-site form cannot sign a victim in to another account.
      if (crossSite(headers, origin)) return refusal(403, 'CROSS_SITE_SIGN_IN', 'Sign in from this site.');
      const address = email.trim().toLowerCase();
      const tooMany = (answer: unknown) => refusal(429, 'TOO_MANY_ATTEMPTS', 'Too many sign-in attempts. Try again later.', { 'retry-after': String(retryAfter(answer)) });
      // 1. The app's per-source limits, counted before anything touches the database: a flood the app refuses costs a
      // counter, never a pool connection, and one source cannot fill the verification queue.
      const sourceAnswer = await sourceLimit({ email: address, source });
      if (sourceAnswer !== true) return tooMany(sourceAnswer);
      // 2. Whether this browser is a known device of the account behind this email: it then claims one of the device's
      // attempts (released again below unless the password was checked). It never authenticates; it only tells the app.
      const claim = await claimDevice(db, address, headers);
      const unclaim = async () => { if (claim) await (await storeOf(auth)).adapter.delete({ model: 'verification', where: [{ field: 'id', value: claim }] }); };
      // 3. The app's account-wide limit, which may spare a known device its bucket, still before any hash or queue.
      let allowed: unknown;
      try { allowed = await accountLimit({ email: address, source, knownDevice: claim !== undefined }); } catch (error) { await unclaim(); throw error; }
      if (allowed !== true) { await unclaim(); return tooMany(allowed); }
      // No stored password is longer than the policy allows, so a longer one is wrong for every account, unhashed.
      if (password.length > ten98AuthPolicy.password.maxLength) return refused();
      // 4. A verification slot, so concurrent guesses cannot queue without bound on the hashing threads. An attempt whose
      // known-device claim was verified above (a database read, before anything that differs between a real and an
      // unknown account) takes the reserved lane and only the lane, so a flood cannot crowd it out and many valid
      // cookies cannot take shared capacity. Every other attempt (an unknown email, an account without a cookie, a
      // forged, revoked or foreign cookie) takes the shared queue under one rule, so none can be told apart.
      const release = claim !== undefined ? await lane() : await slots();
      if (!release) { await unclaim(); return refusal(503, 'SIGN_IN_BUSY', 'Sign-in is busy. Try again shortly.', { 'retry-after': '1' }); }
      let verified: boolean, stored: { id: string; email: string; closedAt: Date | null; password: string | null } | undefined;
      try {
        // 5. One short pool read; its connection is back in the pool before any hashing starts.
        [stored] = await db.select({ id: userTable.id, email: userTable.email, closedAt: userTable.closedAt, password: accountTable.password }).from(userTable)
          .leftJoin(accountTable, and(eq(accountTable.userId, userTable.id), eq(accountTable.providerId, 'credential')))
          .where(sql`lower(${userTable.email}) = lower(${address})`).limit(1);
        verified = await verifyStoredPassword(stored?.password, password, legacyPasswords);
      } finally { release(); }
      if (!verified) return refused();
      // An account that may not sign in is refused here, at a wrong password's cost, rather than after the lock; the lock
      // asks again, for an account closed in between.
      if (await usable({ id: stored!.id, email: stored!.email, closedAt: stored!.closedAt }) !== true) return refused();
      // 6. Only a correct password takes the lock; better-auth verifies again there and creates the session, for the
      // locked account only.
      let response: Response;
      try {
        response = await byEmail(db, address, async (bound, tx, userId) => {
          // No account under the lock (its email moved before the lock was granted), or one closed since the check above:
          // the uniform 401.
          const [account] = userId === undefined ? [] : await tx.select({ id: userTable.id, email: userTable.email, closedAt: userTable.closedAt }).from(userTable).where(eq(userTable.id, userId));
          if (!account || await usable(account) !== true) return refused();
          const signedIn = await bound.api.signInEmail({ body: { email: address, password, ...(rememberMe === undefined ? {} : { rememberMe }) }, ...(headers === undefined ? {} : { headers }), asResponse: true });
          if (signedIn.ok) {
            // A session (or challenge) for any other account than the locked one rolls the transaction back.
            if ((bound as unknown as Record<symbol, () => string | undefined>)[signedInUser]!() !== account.id) throw new LockedAccountMismatch();
            if (legacyPasswords) await replaceLegacyHash(tx, account.id, password);
          }
          return signedIn;
        }, 'password');
      } catch (error) {
        if (error instanceof LockedAccountMismatch || error instanceof AmbiguousAccountError) return refused();
        // COMMIT reported a rollback: nothing the callback did persists, so no cookie may be returned for it.
        if (error instanceof TransactionRolledBackError) return refusal(500, 'SIGN_IN_FAILED', 'Sign-in failed. Try again.');
        throw error;
      }
      return response.status === 401 ? refused() : response;
    },
    assertEmailIndex: db => emailIndex(db),
    assertSchema: db => instanceSchema(db),
    async verifyTwoFactor(db, request) {
      await ready(db, () => undefined);
      if (!(request instanceof Request) || request.method !== 'POST' || !twoFactorRoute.test(new URL(request.url).pathname)) throw new TypeError('verifyTwoFactor takes a POST to a /two-factor/* route.');
      // A request that is not the completion of a sign-in's challenge needs a session, and runs under that user's lock.
      if (!challengeRoute.test(new URL(request.url).pathname) || !cookiePairs(request.headers).some(([name]) => name === cookieName('two_factor'))) {
        return sessionTwoFactor(db, request);
      }
      // The challenge the one signed two_factor cookie names, and the account it was issued for; a cookie sent twice is
      // refused, and expired so the next sign-in starts clean.
      const read = await readChallenge(auth, request.headers);
      if (!read) return challengeRefused();
      const challenge = { value: read.userId };
      let response: Response, interrupted = false;
      try {
        response = await transaction(db, async tx => {
          await limitLockWaits(tx);
          const [row] = await tx.select({ id: userTable.id }).from(userTable).where(eq(userTable.id, challenge.value)).for('no key update');
          if (!row) return challengeRefused();
          return bind(tx, { userId: row.id, email: undefined }, async (bound, boundTx) => {
            // An account closed (or otherwise refused) after its challenge was issued does not complete the sign-in.
            const [account] = await boundTx.select({ id: userTable.id, email: userTable.email, closedAt: userTable.closedAt }).from(userTable).where(eq(userTable.id, row.id));
            if (!account || await usable(account) !== true) return challengeRefused();
            const verified = await throughLedger(bound, account.id, request, sent => bound.handler(sent));
            // 503 is onAPIError's answer to a deadlock or serialisation failure inside better-auth (see retryable).
            interrupted = verified.status === 503;
            if (verified.ok && (bound as unknown as Record<symbol, () => string | undefined>)[signedInUser]!() !== account.id) throw new LockedAccountMismatch();
            return verified;
          }, 'twoFactor');
        });
      } catch (error) {
        if (error instanceof LockedAccountMismatch) return challengeRefused();
        // A deadlock or serialisation failure (this completion against revokeProviderSessions, say): nothing persisted,
        // the challenge stands, and the same request can be sent again.
        if ((interrupted && error instanceof TransactionRolledBackError) || retryable(error)) return signInRetry();
        if (error instanceof TransactionRolledBackError) return refusal(500, 'SIGN_IN_FAILED', 'Sign-in failed. Try again.');
        throw error;
      }
      return response.status === 401 ? challengeRefused() : response;
    },
  };
  /**
   * A session-bound two-factor request (enrolling and confirming a factor, disabling it, recovery codes, the TOTP URI):
   * better-auth's own route, run by an instance bound to a transaction that holds the session user's row. Without a
   * session it is better-auth's own 401.
   */
  const sessionTwoFactor = async (db: AnyDatabase, request: Request) => {
    const current = await auth.api.getSession({ headers: request.headers });
    if (!current) return unlocked(request);
    try {
      return await transaction(db, async tx => {
        await limitLockWaits(tx);
        const [row] = await tx.select({ id: userTable.id }).from(userTable).where(eq(userTable.id, current.user.id)).for('no key update');
        if (!row) return challengeRefused();
        return bind(tx, { userId: row.id, email: undefined }, bound => throughLedger(bound, row.id, request, sent => bound.handler(sent)), 'twoFactor');
      });
    } catch (error) {
      if (retryable(error)) return refusal(503, 'TWO_FACTOR_RETRY', 'The request was interrupted. Try again.', { 'retry-after': '1' });
      if (error instanceof TransactionRolledBackError) return refusal(500, 'TWO_FACTOR_FAILED', 'The request failed. Try again.');
      throw error;
    }
  };
  /**
   * Replaces a legacy hash once, under the lock, in a savepoint: a failure (a trigger, a constraint) rolls back the
   * savepoint only, so the sign-in stands and the next one retries.
   */
  const replaceLegacyHash = async (tx: AnyDatabase, userId: string, candidate: string) => {
    const credential = and(eq(accountTable.userId, userId), eq(accountTable.providerId, 'credential'));
    try {
      await tx.transaction(async savepoint => {
        const [stored] = await savepoint.select({ password: accountTable.password }).from(accountTable).where(credential);
        if (stored?.password && isLegacyHash(stored.password)) await savepoint.update(accountTable).set({ password: await hashPassword(candidate), updatedAt: new Date() }).where(credential);
      });
    } catch (error) { if (error instanceof LockedAuthClosedError) throw error; }
  };
  // A sign-in from a browser that sends an auth cookie twice also expires every copy, before the cookies it sets.
  const { signInWithPassword: signInOnce, verifyTwoFactor: verifyOnce } = locked;
  Object.assign(locked, {
    signInWithPassword: async (db: AnyDatabase, input: PasswordSignIn, limits: PasswordSignInLimits) => withExpired(await signInOnce(db, input, limits), (input as Partial<PasswordSignIn> | undefined)?.headers),
    verifyTwoFactor: async (db: AnyDatabase, request: Request) => withExpired(await verifyOnce(db, request), request?.headers, request instanceof Request ? new URL(request.url).pathname : undefined),
  });
  return Object.assign(auth, helpers, locked) as unknown as Ten98Auth;
}

// Shared by every instance in the process: the fixed hashes a check runs against when an account has no hash of that
// kind, so unknown, passwordless, legacy and current accounts all cost one legacy and one current derivation.
let dummyModernHash: Promise<string> | undefined;
const modernDummy = () => (dummyModernHash ??= hashPassword('ten98-timing-equaliser'));
const lockedContext = new AsyncLocalStorage<true>();
/** The better-auth routes the preset turns off, router and server call alike, and what to use instead. */
const disabledRoutes: Readonly<Record<string, string>> = Object.freeze({
  '/unlink-account': 'use unlinkOidcIdentity inside withLockedAuth',
  '/list-accounts': 'read the user\'s identities from the account table',
});
/** better-auth's password route, in any case and with any trailing slash. */
const passwordRoute = /\/sign-in\/email\/*$/i;
/** The TOTP verification route. */
const totpRoute = /\/two-factor\/verify-totp\/*$/i;
/** What a code that is not fresh is replaced with: it matches no step, so better-auth refuses and counts it as wrong. */
const notACode = '------';
/** The step in better-auth's window (current ±1) a TOTP code matches, the latest if several, or undefined. */
function matchedStep(secret: string, code: string, now = Date.now()): number | undefined {
  const { digits, periodSeconds } = ten98AuthPolicy.twoFactor;
  const counter = Math.floor(now / 1000 / periodSeconds);
  const given = Buffer.from(code.padEnd(digits, '\u0000').slice(0, 64));
  let found: number | undefined;
  for (let step = counter - 1; step <= counter + 1; step++) {
    const expected = Buffer.from(hotp(secret, step, digits).padEnd(given.length, '\u0000'));
    if (expected.length === given.length && timingSafeEqual(given, expected) && code.length === digits) found = step;
  }
  return found;
}
/** RFC 4226 HOTP with HMAC-SHA1 over the secret's text, as better-auth's createOTP computes it. */
function hotp(secret: string, counter: number, digits: number): string {
  const moving = Buffer.alloc(8);
  moving.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(moving).digest();
  const at = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(at) & 0x7fffffff) % 10 ** digits).padStart(digits, '0');
}
/** The code check of each withLockedAuth callback's transaction, while it runs. */
const codeChecks = new WeakMap<object, { userId: string; check(code: unknown): Promise<boolean> }>();
const codeCheckOf = (tx: unknown, operation: string, userId?: string) => {
  const entry = tx !== null && typeof tx === 'object' ? codeChecks.get(tx) : undefined;
  if (!entry) throw new TypeError(`${operation} runs inside withLockedAuth, on its transaction, for the signed-in user it locked.`);
  if (userId !== undefined && userId !== entry.userId) throw new TypeError(`${operation} checks a code for the user withLockedAuth locked.`);
  return entry;
};
/** Every two-factor route, in any case and with any trailing slash. */
const twoFactorRoute = /\/two-factor\/[^/]+\/*$/i;
/** What the instance an app holds answers a two-factor request, so a missed route fails loudly in the app's tests. */
const twoFactorRouting = 'route /two-factor/* through verifyTwoFactor(db, request)';
/** The two-factor routes that complete a sign-in's challenge, in any case and with any trailing slash. */
const challengeRoute = /\/two-factor\/verify-(?:totp|backup-code|otp)\/*$/i;
const twoFactorPaths = new Set(['/two-factor/verify-totp', '/two-factor/verify-backup-code', '/two-factor/verify-otp']);
/** Every cookie better-auth and the preset set, named in full on https so each carries the __Host- prefix. */
const authCookieNames = ['session_token', 'session_data', 'dont_remember', 'account_data', 'two_factor', 'trust_device', 'known_device'] as const;
/** A sign-in challenge the two-factor plugin opens: '2fa-' and 20 characters of better-auth's generateRandomString. */
const challengeIdentifier = /^2fa-[A-Za-z0-9_-]{20}$/;
/** The value of a cookie better-call signed with `secret`, or undefined when it is missing, malformed or forged. */
function signedValue(cookie: string | undefined, secret: string): string | undefined {
  if (cookie === undefined || cookie.length > 512) return undefined;
  let decoded: string;
  try { decoded = decodeURIComponent(cookie); } catch { return undefined; }
  const at = decoded.lastIndexOf('.');
  if (at < 1) return undefined;
  const value = decoded.slice(0, at), signature = Buffer.from(decoded.slice(at + 1));
  const expected = Buffer.from(createHmac('sha256', secret).update(value).digest('base64'));
  return signature.length === expected.length && timingSafeEqual(signature, expected) ? value : undefined;
}
/** A deadlock (40P01) or serialisation failure (40001), possibly wrapped by Drizzle or better-auth: safe to retry. */
function retryable(error: unknown): boolean {
  for (let item = error, depth = 0; item && depth < 5; item = (item as { cause?: unknown }).cause, depth++) {
    const code = (item as { code?: unknown }).code;
    if (code === '40P01' || code === '40001') return true;
  }
  return false;
}
/** A sign-in a deadlock or serialisation failure interrupted; nothing persisted, so the client sends it again. */
const signInRetry = () => refusal(503, 'SIGN_IN_RETRY', 'Sign-in was interrupted. Try again.', { 'retry-after': '1' });
/** One answer for a challenge that is unknown, expired or for an account that may not sign in, and for a wrong code. */
const challengeRefused = () => refusal(401, 'INVALID_TWO_FACTOR', 'Invalid two-factor code or challenge.');
/** Where a bound instance keeps the account its password sign-in created a session for. */
const signedInUser = Symbol('ten98.auth.signedInUser');
/** better-auth signed in another account than the one signInWithPassword locked; thrown so the transaction rolls back. */
class LockedAccountMismatch extends Error {}

/** More than one account matches an email: the unique index on lower(email) is missing. Nothing is picked. */
export class AmbiguousAccountError extends Error {
  readonly code = 'AMBIGUOUS_ACCOUNT' as const;
  constructor() { super('More than one account matches this email; the user table needs its unique index on lower(email).'); this.name = 'AmbiguousAccountError'; }
}
/** The user table has no valid unique index on lower(email), which the locked lookups need to find one account. */
export class MissingEmailIndexError extends Error {
  readonly code = 'MISSING_EMAIL_INDEX' as const;
  constructor() { super('The user table needs a unique index on lower(email) (user_email_normalized_idx in workspace-team.sql) before locked auth can run.'); this.name = 'MissingEmailIndexError'; }
}
/** The tables and columns locked auth reads or writes directly, as workspace-team.sql and better-auth's schema name them. */
const schemaTables: Record<string, readonly string[]> = {
  user: [userTable.id.name, userTable.email.name, userTable.closedAt.name],
  account: [accountTable.userId.name, accountTable.providerId.name, accountTable.password.name, accountTable.updatedAt.name],
  session: [sessionTable.id.name, sessionTable.token.name, sessionTable.userId.name, sessionTable.expiresAt.name, sessionTable.oidcProvider.name],
  verification: ['id', 'identifier', 'value', 'expiresAt'],
};
/** The schema is not the one locked auth uses: the tables or columns it names are missing. */
export class SchemaMismatchError extends Error {
  readonly code = 'AUTH_SCHEMA_MISMATCH' as const;
  readonly missing: readonly string[];
  constructor(missing: readonly string[]) {
    const expected = Object.entries(schemaTables).map(([table, columns]) => `${table === 'user' ? '"user"' : table} (${columns.join(', ')})`).join(', ');
    super(`Locked auth needs the tables ${expected}. Missing: ${missing.join('; ')}. An app whose tables have other names (users, accounts, sessions, verifications) must rename or map them before adopting.`);
    this.name = 'SchemaMismatchError';
    this.missing = missing;
  }
}
type Recheckable = { check: Promise<void>; retryAt: number };
/** How long a failed start-up check is answered from memory before it runs again. */
const recheckMs = 2000;
/**
 * The check in `entry`, or a new run of `run`: a pass (or a run in flight) is kept for good; a failure is answered from
 * memory for `recheckMs`, then checked again, so fixing the schema needs no restart and a wrong one costs one query per
 * interval, not one per attempt.
 */
function recheckable(entry: Recheckable | undefined, run: () => Promise<void>): Recheckable {
  if (entry && Date.now() < entry.retryAt) return entry;
  const fresh: Recheckable = { check: run(), retryAt: Number.POSITIVE_INFINITY };
  fresh.check.catch(() => { fresh.retryAt = Date.now() + recheckMs; });
  return fresh;
}
const schemaChecks = new WeakMap<object, Recheckable>();
/** The tables and columns, then the email index; cached per database like the index check. */
function schemaOf(db: AnyDatabase): Promise<void> {
  const entry = recheckable(schemaChecks.get(db), () =>
    // Parameterised raw statement by necessity: it reads the system catalogue, which has no Drizzle schema.
    db.execute(sql`SELECT t.name, a.attname AS "column" FROM unnest(string_to_array(${Object.keys(schemaTables).join(',')}, ',')) AS t(name)
        LEFT JOIN pg_attribute a ON a.attrelid = to_regclass(quote_ident(t.name)) AND a.attnum > 0 AND NOT a.attisdropped`)
      .then(result => {
        const found = new Map<string, Set<string>>();
        for (const { name, column } of (result as unknown as { rows: { name: string; column: string | null }[] }).rows) {
          const columns = found.get(name) ?? new Set<string>();
          if (column) columns.add(column);
          found.set(name, columns);
        }
        const missing = Object.entries(schemaTables).flatMap(([table, columns]) => {
          const present = found.get(table);
          const label = table === 'user' ? '"user"' : table;
          if (!present?.size) return [`table ${label}`];
          return columns.filter(column => !present.has(column)).map(column => `${label}.${column}`);
        });
        if (missing.length) throw new SchemaMismatchError(missing);
      })
      .then(() => identityIndex(db))
      .then(() => emailIndex(db)));
  schemaChecks.set(db, entry);
  return entry.check;
}

/**
 * The unique index on account ("providerId", "accountId") (account_providerId_accountId_key) that makes a linked
 * identity unique and is the ON CONFLICT arbiter of linkOidcIdentity; SchemaMismatchError without it.
 */
async function identityIndex(db: AnyDatabase): Promise<void> {
  // Parameterised raw statement by necessity: it reads the system catalogue, which has no Drizzle schema.
  const result = await db.execute(sql`SELECT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = to_regclass(${getTableName(accountTable)})
      AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts = 2
      AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey))
        = ARRAY[${accountTable.accountId.name}, ${accountTable.providerId.name}]::text[]) AS indexed`);
  if ((result as unknown as { rows: { indexed: boolean }[] }).rows[0]?.indexed !== true) throw new SchemaMismatchError([`account unique ("${accountTable.providerId.name}", "${accountTable.accountId.name}")`]);
}

// One check per database object, kept like the schema check: a pass for good, a refusal for `recheckMs`.
const emailIndexChecks = new WeakMap<object, Recheckable>();
function emailIndex(db: AnyDatabase): Promise<void> {
  const entry = recheckable(emailIndexChecks.get(db), () =>
    // Parameterised raw statement by necessity: it reads the system catalogue, which has no Drizzle schema.
    db.execute(sql`SELECT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = to_regclass(${`"${getTableName(userTable)}"`})
        AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indnatts = 1 AND (
          -- lower(email) on a text column, or lower(email::text) on a varchar one
          pg_get_expr(i.indexprs, i.indrelid) IN ('lower(email)', 'lower((email)::text)')
          -- or a plain unique index on a citext email column, which compares case-insensitively itself
          OR (i.indexprs IS NULL AND EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
            WHERE a.attrelid = i.indrelid AND a.attnum = i.indkey[0] AND a.attname = 'email' AND t.typname = 'citext')))) AS indexed`)
      .then(result => { if ((result as unknown as { rows: { indexed: boolean }[] }).rows[0]?.indexed !== true) throw new MissingEmailIndexError(); }));
  emailIndexChecks.set(db, entry);
  return entry.check;
}

/** An app's provider key: at most 256 characters, not blank, with no control characters; undefined for anything else. */
function providerKey(value: unknown): string | undefined {
  return typeof value === 'string' && value.length <= 256 && value.trim().length >= 1 && !/[\u0000-\u001f\u007f]/.test(value) ? value : undefined;
}

export type OidcIdentityErrorCode = 'OIDC_EMAIL_UNVERIFIED' | 'OIDC_ACCOUNT_EXISTS' | 'OIDC_IDENTITY_IN_USE' | 'OIDC_IDENTITY_NOT_FOUND' | 'OIDC_LAST_SIGN_IN_METHOD';
const oidcRefusals: Record<OidcIdentityErrorCode, [403 | 404 | 409, string]> = {
  OIDC_EMAIL_UNVERIFIED: [403, 'This provider cannot create an account here: it did not confirm a verified email, or it is not trusted to.'],
  OIDC_ACCOUNT_EXISTS: [409, 'An account already uses this email. Sign in to it, then link the provider in account settings.'],
  OIDC_IDENTITY_IN_USE: [409, 'This provider identity is linked to another account.'],
  OIDC_IDENTITY_NOT_FOUND: [404, 'This provider identity is not linked to the account.'],
  OIDC_LAST_SIGN_IN_METHOD: [409, 'Set a password or link another provider before unlinking the last way to sign in.'],
};
/** A refusal of a linked-identity operation: `status` is the HTTP status that fits and `message` is safe to show. */
export class OidcIdentityError extends Error {
  readonly status: 403 | 404 | 409;
  readonly code: OidcIdentityErrorCode;
  constructor(code: OidcIdentityErrorCode) {
    const [status, message] = oidcRefusals[code];
    super(message);
    this.name = 'OidcIdentityError';
    this.status = status;
    this.code = code;
  }
}
/** A linked identity: the ID token's `iss` and `sub`, after the app verified the token. */
export type OidcIdentity = { issuer: string; subject: string };
/** The verified ID token claims `signInOidcUser` reads. */
export type OidcClaims = { iss: string; sub: string; email?: unknown; email_verified?: unknown; name?: unknown; [claim: string]: unknown };
/** The provider configuration's trust setting: only `trustVerifiedEmail: true` lets a verified email create an account. */
export type OidcProviderTrust = { trustVerifiedEmail?: boolean };

/** The account row key of an identity; TypeError for an issuer without a host or a `sub` that is not 1 to 255 characters. */
function identityKey(issuer: unknown, subject: unknown): { providerId: string; accountId: string } {
  if (!isOidcSubject(subject)) throw new TypeError('An OIDC subject is a string of 1 to 255 characters.');
  return { providerId: oidcProviderId(issuer as string), accountId: subject };
}
/** The user a by-id withLockedAuth transaction holds; TypeError outside one (by email included), as a programming error. */
function lockedUser(tx: unknown, operation: string): string {
  const userId = lockedAuthUser(tx);
  if (userId === undefined) throw new TypeError(`${operation} runs inside withLockedAuth, on its transaction, for the signed-in user it locked.`);
  return userId;
}
const linkedUser = async (db: AnyDatabase, key: { providerId: string; accountId: string }) =>
  (await db.select({ userId: accountTable.userId }).from(accountTable).where(and(eq(accountTable.providerId, key.providerId), eq(accountTable.accountId, key.accountId))).limit(1))[0]?.userId;
const uniqueViolation = (error: unknown) => [error, (error as { cause?: unknown } | null)?.cause].some(item => (item as { code?: unknown } | null)?.code === '23505');

/**
 * The provider sign-in (#143): the user linked to the identity in `claims` (`iss`, `sub`), or a new account for it.
 * It never links to an existing account. With no identity linked, an account is created only when `claims` carry
 * `email_verified === true` and an email, and `provider.trustVerifiedEmail` is true; otherwise OIDC_EMAIL_UNVERIFIED.
 * The account is created under the shared email lock (`pg_advisory_xact_lock(emailLockKey, hashtext(email))`, the team
 * controller's `lockEmail`), as every account-creation path is; an email that already has an account is refused with
 * OIDC_ACCOUNT_EXISTS (the user signs in and links, or accepts an invitation). The new account has a verified email, no
 * password and an account row with no provider tokens. `claims` must come from an ID token the app verified. The
 * account's usability (`closed_at`) is the app's check before it signs the user in with `completeOidcSession`.
 */
export async function signInOidcUser(db: AnyDatabase, claims: OidcClaims, provider: OidcProviderTrust, { emailLockKey = 109_859 }: { emailLockKey?: number } = {}): Promise<{ userId: string; created: boolean }> {
  refuseLockedAuth(db, 'signInOidcUser');
  // The schema check every locked call runs, once per database: without the account index one identity could link twice.
  await schemaOf(db);
  if (!Number.isInteger(emailLockKey) || emailLockKey < -INT32 || emailLockKey >= INT32) throw new TypeError('emailLockKey must be a 32-bit integer.');
  const key = identityKey(claims?.iss, claims?.sub);
  const found = await linkedUser(db, key);
  if (found !== undefined) return { userId: found, created: false };
  const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
  // Checked before any account lookup, so an untrusted or unverified provider learns nothing about which emails exist.
  if (claims.email_verified !== true || provider?.trustVerifiedEmail !== true || !isEmailAddress(email)) throw new OidcIdentityError('OIDC_EMAIL_UNVERIFIED');
  const given = typeof claims.name === 'string' ? claims.name.trim() : '';
  const name = given.length >= 1 && given.length <= 120 && !/[\u0000-\u001f\u007f]/.test(given) ? given : email;
  try {
    return await transaction(db, async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${emailLockKey}, hashtext(${email}))`);
      // A first sign-in of the same identity that held the lock first has linked it by now.
      const raced = await linkedUser(tx, key);
      if (raced !== undefined) return { userId: raced, created: false };
      if ((await tx.select({ id: userTable.id }).from(userTable).where(sql`lower(${userTable.email}) = lower(${email})`).limit(1)).length) throw new OidcIdentityError('OIDC_ACCOUNT_EXISTS');
      const userId = randomUUID();
      await tx.insert(userTable).values({ id: userId, name, email, emailVerified: true });
      await tx.insert(accountTable).values({ id: randomUUID(), userId, ...key });
      return { userId, created: true };
    });
  } catch (error) {
    // The same identity created under another email's lock at the same moment: that account is the one it links to.
    const raced = uniqueViolation(error) ? await linkedUser(db, key) : undefined;
    if (raced !== undefined) return { userId: raced, created: false };
    throw error;
  }
}

/**
 * Checks a TOTP code for an app's own account action, inside `withLockedAuth` on its `tx`, for the user it locked: true
 * only for a code of that user's verified factor whose step is newer than the last one accepted anywhere (sign-in,
 * enrolment, another action), and records that step, so the code is refused everywhere afterwards.
 */
export async function verifyCodeForAction(tx: AnyDatabase, userId: string, code: string): Promise<boolean> {
  return codeCheckOf(tx, 'verifyCodeForAction', userId).check(code);
}

/**
 * Links an identity to the signed-in user, the one `withLockedAuth` locked: call it inside that callback, on its `tx`,
 * after the app verified an ID token the user obtained while signed in. `linked` is false when the identity already
 * belongs to this user. An identity linked to another account is refused with OIDC_IDENTITY_IN_USE; nothing moves it.
 */
export async function linkOidcIdentity(tx: AnyDatabase, identity: OidcIdentity): Promise<{ linked: boolean }> {
  const userId = lockedUser(tx, 'linkOidcIdentity');
  const key = identityKey(identity?.issuer, identity?.subject);
  const inserted = await tx.insert(accountTable).values({ id: randomUUID(), userId, ...key })
    .onConflictDoNothing({ target: [accountTable.providerId, accountTable.accountId] }).returning({ id: accountTable.id });
  if (inserted.length) return { linked: true };
  if (await linkedUser(tx, key) !== userId) throw new OidcIdentityError('OIDC_IDENTITY_IN_USE');
  return { linked: false };
}

/** A stored password the preset can verify: better-auth's `salt:key` hash, or Campaign's legacy one when accepted. */
const MODERN_HASH = /^[0-9a-f]{32}:[0-9a-f]{128}$/;
const verifiablePassword = (hash: unknown, legacyPasswords: boolean) => typeof hash === 'string' && (MODERN_HASH.test(hash) || (legacyPasswords && isLegacyHash(hash)));

/** What `unlinkOidcIdentity` counts as another way to sign in. */
export type UnlinkOptions = {
  /** As `createTen98Auth`'s option: whether a legacy Campaign hash counts as a password (it is never verified otherwise). */
  legacyPasswords?: boolean;
  /** Whether an identity of this (normalised) issuer can still sign in, for an app that knows its providers; all can by default. */
  isIssuerUsable?(issuer: string): boolean | Promise<boolean>;
};

/**
 * Unlinks an identity from the user `withLockedAuth` locked (inside that callback, on its `tx`), deleting its account
 * row. Refused with OIDC_LAST_SIGN_IN_METHOD when the user would be left with no way to sign in. Only a way that can sign
 * in counts: a password the preset can verify (see `UnlinkOptions.legacyPasswords`; an empty, malformed or unaccepted hash
 * does not) or another linked OIDC identity whose issuer `isIssuerUsable` accepts. Account rows of any other provider do
 * not count, as the preset signs no one in through them. The user's sessions are not ended; pair it with
 * `revokeAllSessions()` where the app wants that.
 */
export async function unlinkOidcIdentity(tx: AnyDatabase, identity: OidcIdentity, { legacyPasswords = false, isIssuerUsable }: UnlinkOptions = {}): Promise<void> {
  const userId = lockedUser(tx, 'unlinkOidcIdentity');
  const key = identityKey(identity?.issuer, identity?.subject);
  // The user's credential rows, locked so the count below holds until COMMIT (locked auth's order: after the user row),
  // also against a writer that does not hold the user row.
  const rows = await tx.select({ id: accountTable.id, providerId: accountTable.providerId, accountId: accountTable.accountId, password: accountTable.password })
    .from(accountTable).where(eq(accountTable.userId, userId)).for('update');
  const target = rows.find(row => row.providerId === key.providerId && row.accountId === key.accountId);
  if (!target) throw new OidcIdentityError('OIDC_IDENTITY_NOT_FOUND');
  let remaining = false;
  for (const row of rows) {
    if (row === target) continue;
    if (row.providerId === 'credential' ? verifiablePassword(row.password, legacyPasswords)
      : row.providerId.startsWith('oidc:') && (!isIssuerUsable || await isIssuerUsable(row.providerId.slice('oidc:'.length)) === true)) { remaining = true; break; }
  }
  if (!remaining) throw new OidcIdentityError('OIDC_LAST_SIGN_IN_METHOD');
  await tx.delete(accountTable).where(eq(accountTable.id, target.id));
}

const revocationPasses = 5;
/**
 * Ends every session that began through `provider` (the key passed to `completeOidcSession`), when the app disables,
 * deletes or reconfigures it, and the two-factor challenges such a sign-in opened, with their attempt counters, so none
 * completes into a session later. The known devices of the users whose sessions it ended are forgotten too.
 *
 * Each pass is one transaction, challenges first: a challenge completing concurrently fails, or commits a session the
 * second statement deletes. A challenge opened while a pass runs never completes (its binding row is gone). Passes repeat
 * while one still removes something (at most 5), so a sign-in that commits during a pass is ended by the next; a pass a
 * deadlock or serialisation failure aborts is retried (5 times at most). Resolves the number of sessions ended. Disable the
 * provider first, so no new sign-in starts through it; a sign-in already past the app's check that commits after the last
 * pass is bound to the provider, and calling this again ends it.
 */
export async function revokeProviderSessions(db: AnyDatabase, provider: string): Promise<number> {
  refuseLockedAuth(db, 'revokeProviderSessions');
  await schemaOf(db);
  const key = providerKey(provider);
  if (key === undefined) throw new TypeError('A provider key is at most 256 characters, not blank, with no control characters.');
  const pass = () => transaction(db, async tx => {
    // Parameterised raw statements by necessity: verification has no Drizzle table in the common schema.
    const challenges = await tx.execute(sql`WITH bound AS (SELECT identifier, substr(identifier, ${challengeProviderPrefix.length + 1}) AS challenge FROM verification
        WHERE starts_with(identifier, ${challengeProviderPrefix}) AND value = ${key})
      DELETE FROM verification WHERE identifier IN (SELECT identifier FROM bound UNION ALL SELECT challenge FROM bound UNION ALL SELECT ${attemptsPrefix} || challenge FROM bound)`);
    const ended = await tx.delete(sessionTable).where(eq(sessionTable.oidcProvider, key)).returning({ userId: sessionTable.userId });
    const users = [...new Set(ended.map(row => row.userId))];
    if (users.length) await tx.execute(sql`DELETE FROM verification WHERE value IN ${users} AND starts_with(identifier, ${devicePrefix})`);
    return { sessions: ended.length, challenges: (challenges as unknown as { rowCount: number | null }).rowCount ?? 0 };
  });
  let total = 0;
  for (let passes = 0, retries = 0; passes < revocationPasses;) {
    let removed: { sessions: number; challenges: number };
    try { removed = await pass(); } catch (error) {
      if (retryable(error) && ++retries < revocationPasses) continue;
      throw error;
    }
    total += removed.sessions;
    passes++;
    if (!removed.sessions && !removed.challenges) break;
  }
  return total;
}

/** Both verifiers on every attempt, one of them against a dummy; true only for a stored hash the password matches. */
async function verifyStoredPassword(hash: string | null | undefined, candidate: string, legacyAccepted: boolean): Promise<boolean> {
  const present = typeof hash === 'string' && hash !== '', legacy = present && isLegacyHash(hash);
  const [legacyOk, modernOk] = await Promise.all([
    verifyLegacyScryptHash(legacy ? hash : DUMMY_LEGACY_HASH, candidate),
    modernDummy().then(dummy => verifyPassword({ hash: present && !legacy ? hash : dummy, password: candidate })).catch(() => false),
  ]);
  return present && (legacy ? legacyAccepted && legacyOk : modernOk);
}

/** A browser request from another site: an Origin other than the app's, or Sec-Fetch-Site cross-site or same-site. */
function crossSite(headers: HeadersInit | undefined, origin: string): boolean {
  if (headers === undefined) return false;
  const given = new Headers(headers), from = given.get('origin'), site = given.get('sec-fetch-site')?.toLowerCase();
  return (from !== null && from !== origin) || site === 'cross-site' || site === 'same-site';
}

const refusal = (status: number, code: string, message: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ code, message }), { status, headers: { 'content-type': 'application/json', ...headers } });
/** The wait a limiter's refusal names: its `retryAfterSeconds` when that is an integer from 1 to 86400, otherwise 60. */
function retryAfter(answer: unknown): number {
  const seconds = (answer as { retryAfterSeconds?: unknown } | null)?.retryAfterSeconds;
  return typeof seconds === 'number' && Number.isInteger(seconds) && seconds >= 1 && seconds <= 86_400 ? seconds : 60;
}
/** One answer for an unknown email, a wrong password and an account without a password. */
const refused = () => refusal(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password');

/**
 * At most `concurrency` holders at once and `queue` waiting, each for at most `waitMs`. Resolves a release function, or
 * undefined when no slot came in time or the queue is full, so a caller is answered instead of left waiting.
 */
function boundedSlots({ concurrency = 2, queue = 100, waitMs = 15_000 }: NonNullable<Ten98AuthOptions['passwordVerification']> = {}, label = 'passwordVerification') {
  for (const [name, value] of Object.entries({ concurrency, queue, waitMs })) {
    if (!Number.isInteger(value) || value < (name === 'concurrency' ? 1 : 0)) throw new TypeError(`${label}.${name} must be a whole number${name === 'concurrency' ? ' of at least 1' : ''}.`);
  }
  let active = 0;
  const waiting: (() => void)[] = [];
  const handOver = () => { const next = waiting.shift(); if (next) next(); else active--; };
  const once = () => { let done = false; return () => { if (!done) { done = true; handOver(); } }; };
  return (): Promise<(() => void) | undefined> => {
    if (active < concurrency) { active++; return Promise.resolve(once()); }
    if (waiting.length >= queue) return Promise.resolve(undefined);
    return new Promise(resolve => {
      const take = () => { clearTimeout(timer); resolve(once()); };
      const timer = setTimeout(() => { waiting.splice(waiting.indexOf(take), 1); resolve(undefined); }, waitMs);
      timer.unref();
      waiting.push(take);
    });
  };
}
