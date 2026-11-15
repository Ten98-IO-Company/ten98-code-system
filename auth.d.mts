import { type BetterAuthOptions } from 'better-auth';
import { type AnyDatabase, type ScopedTransaction } from './db.mjs';
export { LockedAuthTransactionError } from './locked-auth.mjs';
export { normaliseOidcIssuer, normaliseOidcIssuerSql, oidcProviderId } from './oidc-issuer.mjs';
/** The shared identity policy. Apps read it for forms and route limiters, so the numbers never drift between them. */
export declare const ten98AuthPolicy: Readonly<{
    password: Readonly<{
        minLength: 12;
        maxLength: 128;
    }>;
    /** Seven days, extended at most once a day of use. */
    session: Readonly<{
        expiresInSeconds: 604800;
        updateAgeSeconds: 86400;
    }>;
    /**
     * TOTP (RFC 6238, SHA-1). `replaySeconds` is the window in which an accepted code is refused again; the app keeps that
     * ledger. Recovery codes are `backupCodes` codes matching `backupCodePattern` (a string, so it survives JSON), each
     * `backupCodeInputLength` characters as typed, with the hyphen.
     * The lockout counts failures during sign-in challenges only; session-bound step-up checks are limited per user by the
     * app (`rateLimits.accountSecurityWritesPerUser`).
     */
    twoFactor: Readonly<{
        digits: 6;
        periodSeconds: 30;
        replaySeconds: 90;
        backupCodes: 10;
        backupCodePattern: "^[A-Za-z0-9]{5}-[A-Za-z0-9]{15}$";
        backupCodeInputLength: 21;
        maxFailedAttempts: 10;
        lockoutSeconds: 900;
    }>;
    reset: Readonly<{
        expiresInSeconds: 3600;
        revokesSessions: true;
    }>;
    /**
     * Counts per `windowSeconds` for each app's route limiter. better-auth's own limiter stays off because it cannot see
     * the trusted client address; apps key these with clientLimitKey (per client) or the email, token or user.
     */
    rateLimits: Readonly<{
        windowSeconds: 60;
        signInPerClient: 60;
        signInPerEmail: 5;
        twoFactorPerClient: 60;
        twoFactorPerChallenge: 10;
        resetRequestPerClient: 20;
        resetRequestPerEmail: 3;
        resetPerClient: 60;
        resetPerToken: 5;
        accountSecurityReadsPerUser: 120;
        accountSecurityWritesPerUser: 30;
    }>;
}>;
export type ResetPasswordMessage = {
    userId: string;
    email: string;
    token: string;
};
/** Verifies a Campaign `scrypt$salt$key` hash; any other format is not legacy and returns false. */
export declare function verifyLegacyScryptHash(hash: string, password: string): Promise<boolean>;
/**
 * The `verification.identifier` the preset stores for a raw identifier, for an app that locks or reads the row with its
 * own SQL. Prefer the instance method, which needs no secret.
 */
export declare function storedVerificationIdentifier(secret: string, identifier: string): string;
/**
 * The `session.token` the preset stores (a `v1.` handle) for a raw session token, the cookie's value without its
 * signature. For an app's own read of session liveness; prefer the instance method, which needs no secret.
 */
export declare function sessionTokenKey(secret: string, token: string): string;
/**
 * The statements every app's numbered migration runs once when it adopts runtime 0.29.0's auth storage, separated as
 * drizzle-kit separates statements. Rows stored in plain text before it would never match again: every session ends,
 * and reset links, trusted devices and pending two-factor challenges (with their `2fa-otp-` and `2fa-attempts-` rows) go
 * with them. Then the session gains its provider binding, `oidcProvider`, and emails are stored lower-case
 * (`user_email_lowercase`): the migration stops, listing the account ids and never an address, while two accounts share
 * an email ignoring case, so an operator resolves them first. Rows an app writes with its own SQL are its own decision.
 */
export declare const tokenStorageUpgradeStatements: string;
/** The user `withLockedAuth` was asked to lock does not exist; answer it as not found. */
export declare class LockedAuthUserNotFoundError extends Error {
    readonly status: 404;
    readonly code: 'USER_NOT_FOUND';
    constructor();
}
/**
 * A locked-auth instance or transaction was used after its callback returned (an un-awaited call, say), or a second
 * locked-auth transaction was opened inside one. Either would run outside, or wait on, the lock: a programming error.
 */
export declare class LockedAuthClosedError extends Error {
    readonly code: 'LOCKED_AUTH_CLOSED';
    constructor(message?: string);
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
    passwordVerification?: {
        concurrency?: number;
        queue?: number;
        waitMs?: number;
        knownDevices?: {
            concurrency?: number;
            queue?: number;
            waitMs?: number;
        };
    };
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
     * Whether an account may sign in with its password, asked under the account's lock in `signInWithPassword`; anything
     * but `true` gets the uniform 401. Defaults to refusing a closed account (`closedAt` set).
     */
    isAccountUsable?(account: {
        id: string;
        email: string;
        closedAt: Date | null;
    }): boolean | Promise<boolean>;
    /**
     * Re-enables better-auth's own password sign-in (`POST /sign-in/email` and `api.signInEmail`) on the instance the
     * app holds. It has no rate limit, no lock and no constant-cost check: do not use it outside tests and migrations.
     */
    allowRawPasswordSignIn?: boolean;
}
export interface Ten98AuthSession {
    /** `oidcProvider`: the app's provider key when the session began with a provider sign-in (`completeOidcSession`). */
    session: {
        id: string;
        userId: string;
        token: string;
        expiresAt: Date;
        userAgent?: string | null;
        oidcProvider?: string | null;
        [field: string]: unknown;
    };
    user: {
        id: string;
        email: string;
        name: string;
        twoFactorEnabled?: boolean | null;
        [field: string]: unknown;
    };
}
type ServerCall<Body> = (input: {
    body: Body;
    headers?: HeadersInit;
    asResponse: true;
}) => Promise<Response>;
/**
 * The surface apps use, declared here because better-auth's inferred type names its internal packages. Reach `handler`
 * only through an app router that allowlists the auth paths it serves. The OIDC session endpoints are server-only.
 */
export interface Ten98Auth {
    handler(request: Request): Promise<Response>;
    api: {
        getSession(input: {
            headers: HeadersInit;
            query?: {
                disableRefresh?: boolean;
            };
        }): Promise<Ten98AuthSession | null>;
        signInEmail: ServerCall<{
            email: string;
            password: string;
            rememberMe?: boolean;
        }>;
        /** Replaces the caller's own session with a fresh one and revokes the old one (after the app verified a factor); needs that session's cookie. */
        rotateVerifiedSession: ServerCall<{
            verifiedUserId: string;
        }>;
        /**
         * Signs in a user the app's OIDC flow verified (`signInOidcUser`); an account with two-factor enabled gets the TOTP
         * challenge instead. `provider` is the app's key for the provider configuration it signed in through (1 to 256
         * characters, no control characters): the session, or the session the challenge later creates, stores it as
         * `oidcProvider`, so `revokeProviderSessions` can end it.
         */
        completeOidcSession: ServerCall<{
            oidcUserId: string;
            provider: string;
        }>;
        /**
         * Revokes the caller's other live sessions by id and keeps the current one (found from the cookie in `headers`).
         * `revoked` counts the sessions it ended. The same endpoint serves POST /revoke-other-sessions.
         */
        revokeOtherSessions(input: {
            headers: HeadersInit;
        }): Promise<{
            status: true;
            revoked: number;
        }>;
    };
    options: {
        readonly telemetry: {
            readonly enabled: false;
        };
    };
    /** The stored `verification.identifier` for a raw identifier; see the standalone `storedVerificationIdentifier`. */
    storedVerificationIdentifier(identifier: string): string;
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
     * cross-site Sec-Fetch-Site in `headers`) is answered 403 first. Then, in order: whether the browser's known-device
     * cookie holds a live device of the account behind `email` (`knownDevice`; see the guide); `limit` (the app's
     * per-source and per-account limits, evaluated and counted before any hash; anything but `true` answers 429; with
     * `knownDevice` the app may skip only its account-wide bucket); a slot among the bounded verifications (503 when none is
     * free in time); one short pool read of the credential, its connection released; both the modern and the legacy
     * verifier, one of them against a fixed dummy, outside any transaction. A wrong password, an unknown email and an
     * account without a password all get the same 401. Only a correct password enters `withLockedAuthByEmail`, where
     * better-auth verifies again under the lock and creates the session (a legacy hash is replaced there once); if the
     * password changed in between, the answer is the same 401 and no session is created. The response carries the
     * session cookie, or the two-factor challenge, as `/sign-in/email` does.
     */
    signInWithPassword(db: AnyDatabase, input: PasswordSignIn, limit: (attempt: PasswordAttempt) => boolean | Promise<boolean>): Promise<Response>;
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
     * Completes a sign-in's two-factor challenge (`/two-factor/verify-totp`, `-backup-code` or `-otp`, with the signed
     * `two_factor` cookie) under the challenged account's lock: an account `isAccountUsable` refuses, or a challenge that is
     * unknown or expired, gets one uniform 401, and a session for any other account rolls back. The instance the app holds
     * refuses a challenge outside it. Pass the request as received; verification with a session (enabling two-factor) still
     * goes to `handler`.
     */
    verifyTwoFactor(db: AnyDatabase, request: Request): Promise<Response>;
}
/** `signInWithPassword`'s input; `headers` are the request's: its origin, its cookies, its user agent and address. */
export type PasswordSignIn = {
    email: string;
    password: string;
    source: string;
    rememberMe?: boolean;
    headers?: HeadersInit;
};
/**
 * What `signInWithPassword` gives the app's limiter, before any hash and before the verification queue: the normalised
 * email; `source`, the client address the app derived for the request (`clientLimitKey` of its trusted address), so it
 * counts per source as well as per account; and `knownDevice`, whether this browser is a known device of that account.
 * A known device may skip only the account-wide bucket: never the per-source or per-pair limits, and never the password.
 */
export type PasswordAttempt = {
    email: string;
    source: string;
    knownDevice: boolean;
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
/**
 * A better-auth instance with the Ten98 policy. Sign-up stays closed: the first-boot claim creates the owner in the
 * app's own transaction (hash with `hashPassword` from 'better-auth/crypto') and then signs in. Origin and CSRF checks
 * are pinned on, so no environment variable can turn them off. Session tokens and verification identifiers are stored
 * as keyed hashes; the cookie cache stays off and no secondary storage is used, so no token is kept anywhere else.
 */
export declare function createTen98Auth(options: Ten98AuthOptions): Ten98Auth;
/** More than one account matches an email: the unique index on lower(email) is missing. Nothing is picked. */
export declare class AmbiguousAccountError extends Error {
    readonly code: 'AMBIGUOUS_ACCOUNT';
    constructor();
}
/** The user table has no valid unique index on lower(email), which the locked lookups need to find one account. */
export declare class MissingEmailIndexError extends Error {
    readonly code: 'MISSING_EMAIL_INDEX';
    constructor();
}
/** The schema is not the one locked auth uses: the tables or columns it names are missing. */
export declare class SchemaMismatchError extends Error {
    readonly code: 'AUTH_SCHEMA_MISMATCH';
    readonly missing: readonly string[];
    constructor(missing: readonly string[]);
}
export type OidcIdentityErrorCode = 'OIDC_EMAIL_UNVERIFIED' | 'OIDC_ACCOUNT_EXISTS' | 'OIDC_IDENTITY_IN_USE' | 'OIDC_IDENTITY_NOT_FOUND' | 'OIDC_LAST_SIGN_IN_METHOD';
/** A refusal of a linked-identity operation: `status` is the HTTP status that fits and `message` is safe to show. */
export declare class OidcIdentityError extends Error {
    readonly status: 403 | 404 | 409;
    readonly code: OidcIdentityErrorCode;
    constructor(code: OidcIdentityErrorCode);
}
/** A linked identity: the ID token's `iss` and `sub`, after the app verified the token. */
export type OidcIdentity = {
    issuer: string;
    subject: string;
};
/** The verified ID token claims `signInOidcUser` reads. */
export type OidcClaims = {
    iss: string;
    sub: string;
    email?: unknown;
    email_verified?: unknown;
    name?: unknown;
    [claim: string]: unknown;
};
/** The provider configuration's trust setting: only `trustVerifiedEmail: true` lets a verified email create an account. */
export type OidcProviderTrust = {
    trustVerifiedEmail?: boolean;
};
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
export declare function signInOidcUser(db: AnyDatabase, claims: OidcClaims, provider: OidcProviderTrust, { emailLockKey }?: {
    emailLockKey?: number;
}): Promise<{
    userId: string;
    created: boolean;
}>;
/**
 * Links an identity to the signed-in user, the one `withLockedAuth` locked: call it inside that callback, on its `tx`,
 * after the app verified an ID token the user obtained while signed in. `linked` is false when the identity already
 * belongs to this user. An identity linked to another account is refused with OIDC_IDENTITY_IN_USE; nothing moves it.
 */
export declare function linkOidcIdentity(tx: AnyDatabase, identity: OidcIdentity): Promise<{
    linked: boolean;
}>;
/**
 * Unlinks an identity from the user `withLockedAuth` locked (inside that callback, on its `tx`), deleting its account
 * row. Refused with OIDC_LAST_SIGN_IN_METHOD when the user would be left with no way to sign in: no password and no
 * other linked identity. The user's sessions are not ended; pair it with `revokeAllSessions()` where the app wants that.
 */
export declare function unlinkOidcIdentity(tx: AnyDatabase, identity: OidcIdentity): Promise<void>;
/**
 * Ends every session that began through `provider` (the key passed to `completeOidcSession`), when the app disables,
 * deletes or reconfigures it, and the two-factor challenges such a sign-in opened, with their attempt counters, so none
 * completes into a session later. Challenges go first, in one transaction, so a challenge completing concurrently fails,
 * or commits a session the second statement deletes, or one of the two aborts on a deadlock (SQLSTATE 40P01; a failed
 * revocation is retried). Resolves the number of sessions ended. Disable the provider first, so no new sign-in starts
 * through it meanwhile.
 */
export declare function revokeProviderSessions(db: AnyDatabase, provider: string): Promise<number>;
