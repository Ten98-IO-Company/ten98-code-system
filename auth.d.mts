import { type BetterAuthOptions } from 'better-auth';
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
    };
    options: {
        readonly telemetry: {
            readonly enabled: false;
        };
    };
}
/**
 * A better-auth instance with the Ten98 policy. Sign-up stays closed: the first-boot claim creates the owner in the
 * app's own transaction (hash with `hashPassword` from 'better-auth/crypto') and then signs in. Origin and CSRF checks
 * are pinned on, so no environment variable can turn them off.
 */
export declare function createTen98Auth({ database, appUrl, secret, appName, sendResetPassword, legacyPasswords, allowPasswordless, cookiePrefix }: Ten98AuthOptions): Ten98Auth;
export {};
