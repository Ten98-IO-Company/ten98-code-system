import { type EmailMessage } from './email-message.mjs';
export interface CloudflareEmailMessage extends EmailMessage {
}
/** How Cloudflare reported the one recipient: sent, accepted for later delivery, bounced permanently, or on its suppression list. */
export type CloudflareEmailStatus = 'delivered' | 'queued' | 'failed' | 'suppressed';
/**
 * Thrown by `sendCloudflareEmail`. `uncertain` means Cloudflare may have sent the email; `retryable` means it definitely did
 * not and may be retried later. `providerCode` is Cloudflare's first numeric error code, when the error body has one.
 */
export interface CloudflareSendError extends Error {
    code: string;
    uncertain: boolean;
    retryable: boolean;
    status?: number;
    providerCode?: number;
}
/**
 * Sends one email through Cloudflare Email Sending and resolves `{ status, messageId }`, where `messageId` is null when the
 * receipt has none. Failures throw `CloudflareSendError`, whose message never contains the token, addresses or the body:
 * - `uncertain: true` after the request may have reached Cloudflare: a network failure, abort or timeout, a 5xx, or a 2xx
 *   that is unreadable or reports another recipient. Reconcile before resending.
 * - `retryable: true` for 429, which Cloudflare did not process.
 * - otherwise a definite rejection with `code` `HTTP_<status>`.
 * Invalid input throws a TypeError with `code: 'INVALID_INPUT'` before anything is sent. The default deadline is 30 seconds.
 */
export declare function sendCloudflareEmail({ accountId, token, message, signal, timeoutMs, fetch: send }: {
    accountId: string;
    token: string;
    message: CloudflareEmailMessage;
    signal?: AbortSignal;
    timeoutMs?: number;
    fetch?: (url: string, init: RequestInit) => Promise<Response>;
}): Promise<{
    status: CloudflareEmailStatus;
    messageId: string | null;
}>;
