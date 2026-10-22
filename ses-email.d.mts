/** Commercial AWS regions with an SES v2 API endpoint. */
export declare const SES_REGIONS: readonly string[];
export interface AwsCredentials {
    readonly accessKeyId: string;
    readonly secretAccessKey: string;
    readonly sessionToken?: string;
}
export interface SesMessage {
    readonly from: string;
    readonly to: string;
    readonly subject: string;
    readonly text?: string;
    readonly html?: string;
    readonly replyTo?: string;
    readonly headers?: Readonly<Record<string, string>>;
}
/** Thrown by `sendSesEmail`. `uncertain` means SES may have sent the email; `retryable` means it definitely did not and may be retried later. */
export interface SesSendError extends Error {
    code: string;
    uncertain: boolean;
    retryable: boolean;
    status?: number;
}
/** SigV4 signing key: HMAC chain kSecret → kDate → kRegion → kService → kSigning. */
export declare function deriveAwsV4SigningKey(secretAccessKey: string, dateStamp: string, region: string, service: string): Uint8Array;
/**
 * Signs a request without a query string using AWS Signature Version 4 in the Authorization header.
 * Returns `headers` plus `x-amz-date`, `x-amz-security-token` (with a session token) and `authorization`; `host` is
 * signed but not returned because fetch derives it from the URL.
 */
export declare function signAwsV4Request({ method, host, path, headers, body, credentials, region, service, date }: {
    method: string;
    host: string;
    path: string;
    headers?: Readonly<Record<string, string>>;
    body?: string;
    credentials: AwsCredentials;
    region: string;
    service: string;
    date: Date;
}): Record<string, string>;
/** The fixed SES v2 API origin for an allowlisted region; anything else throws INVALID_REGION. */
export declare function sesOrigin(region: unknown): string;
/**
 * Sends one email through SES v2 SendEmail and resolves `{ accepted: true, messageId }` on acceptance.
 * Failures throw `SesSendError`, whose message never contains credentials, addresses or the response body:
 * - `uncertain: true` after the request may have reached SES (network failure, abort or timeout, 5xx, unreadable 2xx);
 *   reconcile before resending, for example through the `idempotency-key` email tag in SES event publishing.
 * - `retryable: true` for throttling (429, ThrottlingException, TooManyRequestsException), which SES did not process.
 * - otherwise a definite rejection whose `code` is the SES error type (such as MessageRejected).
 * SES has no request idempotency token; `idempotencyKey` is only a correlation tag and does not deduplicate.
 * The default deadline is 30 seconds; pass `signal` to share a deadline.
 */
export declare function sendSesEmail({ region, credentials, message, configurationSetName, idempotencyKey, fetch: send, now, signal }: {
    region: string;
    credentials: AwsCredentials;
    message: SesMessage;
    configurationSetName?: string;
    idempotencyKey?: string;
    fetch?: typeof globalThis.fetch;
    now?: () => Date;
    signal?: AbortSignal;
}): Promise<{
    accepted: true;
    messageId: string;
}>;
