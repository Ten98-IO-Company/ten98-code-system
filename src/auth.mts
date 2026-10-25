// The Ten98 identity preset on better-auth, promoted from Discover src/server/auth.ts (dev, 2026-10-25) per decision #7/#97.
// It fixes the shared policy (passwords, sessions, two-factor, reset, error redaction) in one place. Each app supplies its
// database adapter, its URL and secret, its reset-email capture, and keeps its routes, transactions, rate limiters,
// first-boot claim, OIDC protocol and workspace authorization. better-auth is an exact, optional peer dependency.
import { createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { betterAuth, type BetterAuthOptions } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx, isAPIError } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { appOrigin } from './index.mjs';

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

export interface Ten98AuthOptions {
  /** The app's better-auth database adapter, such as `drizzleAdapter(db, { provider: 'pg', schema })`. */
  database: BetterAuthOptions['database'];
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
}

export interface Ten98AuthSession {
  session: { id: string; userId: string; token: string; expiresAt: Date; userAgent?: string | null; [field: string]: unknown };
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
    /** Signs in a user the app's OIDC flow verified; an account with two-factor enabled gets the TOTP challenge instead. */
    completeOidcSession: ServerCall<{ oidcUserId: string }>;
  };
  options: { readonly telemetry: { readonly enabled: false } };
}

type VerificationStore = {
  adapter: { deleteMany(query: { model: string; where: { field: string; value: string; operator?: 'eq' | 'starts_with' }[] }): Promise<number> };
};

/**
 * A better-auth instance with the Ten98 policy. Sign-up stays closed: the first-boot claim creates the owner in the
 * app's own transaction (hash with `hashPassword` from 'better-auth/crypto') and then signs in. Origin and CSRF checks
 * are pinned on, so no environment variable can turn them off.
 */
export function createTen98Auth({ database, appUrl, secret, appName, sendResetPassword, legacyPasswords = false, allowPasswordless = false, cookiePrefix }: Ten98AuthOptions): Ten98Auth {
  const origin = appOrigin(appUrl);
  if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('The auth secret must be at least 32 characters.');
  if (typeof appName !== 'string' || !appName.trim()) throw new TypeError('appName is required.');
  const prefix = cookiePrefix ?? `ten98-${createHash('sha256').update(origin).digest('hex').slice(0, 16)}`;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(prefix)) throw new TypeError('cookiePrefix must be 1 to 64 letters, digits, hyphens or underscores.');
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
  const issue = async (context: Parameters<Parameters<typeof createAuthEndpoint.serverOnly>[1]>[0], user: Awaited<ReturnType<typeof verifiedUser>>) => {
    const created = await context.context.internalAdapter.createSession(user.id, false);
    if (!created) throw APIError.fromStatus('INTERNAL_SERVER_ERROR');
    await setSessionCookie(context, { user, session: created });
    return context.json({ ok: true });
  };
  const oidcSessions = {
    id: 'ten98-oidc-session',
    endpoints: {
      rotateVerifiedSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async context => {
        const user = await verifiedUser(context, 'verifiedUserId');
        // Only the account's own current session can be rotated; this never signs anyone in.
        const current = await getSessionFromCtx(context);
        if (!current || current.user.id !== user.id) throw APIError.fromStatus('UNAUTHORIZED');
        const response = await issue(context, user);
        await context.context.internalAdapter.deleteSession(current.session.token);
        return response;
      }),
      completeOidcSession: createAuthEndpoint.serverOnly({ method: 'POST' }, async context => issue(context, await verifiedUser(context, 'oidcUserId'))),
    },
  } as const;

  // With legacy hashes accepted, every password check runs one legacy derive and one current derive, whichever hash is
  // stored or none, so response time does not reveal which accounts are unmigrated.
  let dummyModern: Promise<string> | undefined;
  const modernDummy = () => (dummyModern ??= hashPassword('ten98-timing-equaliser'));
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

  let store: Promise<VerificationStore> | undefined;
  const auth = betterAuth({
    database, baseURL: origin, secret, appName, trustedOrigins: [origin],
    // better-auth skips these checks when NODE_ENV=test or TEST is set unless they are pinned.
    advanced: { disableOriginCheck: false, disableCSRFCheck: false, cookiePrefix: prefix },
    // Self-hosted installs send no data to Ten98 or third parties.
    telemetry: { enabled: false },
    // Adapter failures can contain query parameters, and better-call logs non-API exceptions even with the logger off,
    // so every unexpected error becomes a bare 500 before it can expose SQL, hashes or tokens.
    logger: { disabled: true },
    onAPIError: { onError(error) { if (isAPIError(error)) throw error; throw APIError.fromStatus('INTERNAL_SERVER_ERROR'); } },
    session: { expiresIn: session.expiresInSeconds, updateAge: session.updateAgeSeconds, cookieCache: { enabled: false } },
    plugins: [factors, oidcSessions],
    emailAndPassword: {
      enabled: true,
      disableSignUp: true,
      minPasswordLength: password.minLength,
      maxPasswordLength: password.maxLength,
      resetPasswordTokenExpiresIn: reset.expiresInSeconds,
      revokeSessionsOnPasswordReset: reset.revokesSessions,
      ...(sendResetPassword ? { sendResetPassword: async ({ user, token }: { user: { id: string; email: string }; token: string }) => { await sendResetPassword({ userId: user.id, email: user.email, token }); } } : {}),
      // A reset also ends trusted devices and pending two-factor challenges, so the new password alone never skips the factor.
      onPasswordReset: async ({ user }: { user: { id: string } }) => {
        // deleteMany has no row cap (findMany defaults to 100). Challenge rows hold the user id; their attempt counters
        // ('2fa-attempts-…', value '0') expire with the challenge they belonged to.
        const { adapter } = await (store ??= (auth as unknown as { $context: Promise<VerificationStore> }).$context);
        for (const prefix of ['trust-device-', '2fa-']) {
          await adapter.deleteMany({ model: 'verification', where: [{ field: 'value', value: user.id }, { field: 'identifier', operator: 'starts_with', value: prefix }] });
        }
      },
      ...(legacyPassword ? { password: legacyPassword } : {}),
    },
    rateLimit: { enabled: false },
    ...(legacyPasswords ? { hooks: { after: createAuthMiddleware(async context => {
      // After a successful password sign-in (with or without a pending two-factor challenge), replace a legacy hash.
      // Best effort: a failure leaves the legacy hash for the next sign-in and never blocks this one.
      if (context.path !== '/sign-in/email' || isAPIError(context.context.returned)) return;
      const { email, password: candidate } = (context.body ?? {}) as { email?: unknown; password?: unknown };
      if (typeof email !== 'string' || typeof candidate !== 'string') return;
      try {
        const found = await context.context.internalAdapter.findUserByEmail(email.toLowerCase(), { includeAccounts: true });
        const credential = found?.accounts.find(account => account.providerId === 'credential');
        if (found && credential?.password && isLegacyHash(credential.password)) await context.context.internalAdapter.updatePassword(found.user.id, await hashPassword(candidate));
      } catch { /* retried on the next successful sign-in */ }
    }) } } : {}),
  });
  return auth as unknown as Ten98Auth;
}
