import { type BetterAuthOptions } from 'better-auth';
import { type AnyDatabase, type ScopedTransaction } from './db.mjs';
export { LockedAuthTransactionError } from './locked-auth.mjs';
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
 * The statements every app's numbered migration runs once when it adopts hashed token storage, separated as drizzle-kit
 * separates statements. Rows stored in plain text before it would never match again: every session ends, and reset
 * links, trusted devices and pending two-factor challenges (with their `2fa-otp-` and `2fa-attempts-` rows) go with them.
 * Rows an app writes with its own SQL are its own decision.
 */
export declare const tokenStorageUpgradeStatements: string;
/** The user `withLockedAuth` was asked to lock does not exist; answer it as not found. */
export declare class LockedAuthUserNotFoundError extends Error {
    readonly status: 404;
    readonly code: 'USER_NOT_FOUND';
    constructor();
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
    session: {
        id: string;
        userId: string;
        token: string;
        expiresAt: Date;
        userAgent?: string | null;
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
        /** Signs in a user the app's OIDC flow verified; an account with two-factor enabled gets the TOTP challenge instead. */
        completeOidcSession: ServerCall<{
            oidcUserId: string;
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
     * Runs `run` in one transaction (`transaction` from ./db) whose first statement locks the user row FOR NO KEY UPDATE,
     * with a better-auth instance bound to that transaction. A missing user throws LockedAuthUserNotFoundError (404). The
     * callback runs its own statements on `tx` and may lock that user's session, credential and verification rows, in
     * that order; tenancy helpers and workspace-level team operations refuse the transaction. When `run` throws, or the
     * transaction fails, nothing it did persists and the error is rethrown; Set-Cookie headers from inside are lost with it.
     */
    withLockedAuth<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>) => Promise<T>): Promise<T>;
    /**
     * `withLockedAuth` for a flow that knows only an email (password sign-in, reset request): takes the email advisory
     * lock (`pg_advisory_xact_lock(emailLockKey, hashtext(email))`, the team controller's `lockEmail`) first, then locks
     * that account's user row if there is one. `userId` is undefined when no account has the email.
     */
    withLockedAuthByEmail<TDatabase extends AnyDatabase, T>(db: TDatabase, email: string, run: (auth: LockedTen98Auth, tx: ScopedTransaction<TDatabase>, userId: string | undefined) => Promise<T>): Promise<T>;
}
/** The transaction-bound instance `withLockedAuth` hands out. It opens no further locked-auth transactions. */
export interface LockedTen98Auth extends Omit<Ten98Auth, 'withLockedAuth' | 'withLockedAuthByEmail'> {
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
