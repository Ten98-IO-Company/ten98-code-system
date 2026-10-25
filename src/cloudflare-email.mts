// Cloudflare Email Sending over fetch, the counterpart of sendSesEmail. Promoted from Campaign server/direct-providers.ts
// (v0.32.1) and Discover src/server/email.ts (v0.7.4), which parsed the same receipt with different recipient checks.
// Callers retain the token, sender identity, which outcomes they accept, suppression/consent policy, retries and accounting.
import { checkEmailMessage, invalidEmailInput, type EmailMessage } from './email-message.mjs';
import { providerFetchJson } from './provider-fetch.mjs';

export interface CloudflareEmailMessage extends EmailMessage {}
/** How Cloudflare reported the one recipient: sent, accepted for later delivery, bounced permanently, or on its suppression list. */
export type CloudflareEmailStatus = 'delivered' | 'queued' | 'failed' | 'suppressed';
/**
 * Thrown by `sendCloudflareEmail`. `uncertain` means Cloudflare may have sent the email; `retryable` means it definitely did
 * not and may be retried later. `providerCode` is Cloudflare's first numeric error code, when the error body has one.
 */
export interface CloudflareSendError extends Error { code: string; uncertain: boolean; retryable: boolean; status?: number; providerCode?: number }

const HOSTS = ['api.cloudflare.com'];
// Receipt buckets in the order the status is reported; suppressed_recipients is absent from older receipts.
const BUCKETS = [['delivered', 'delivered'], ['queued', 'queued'], ['permanent_bounces', 'failed'], ['suppressed_recipients', 'suppressed']] as const;
const MESSAGE_ID = /^[!-~]{1,256}$/;

function sendError(message: string, code: string, uncertain: boolean, retryable: boolean, extra: { status?: number; providerCode?: number } = {}): CloudflareSendError {
  return Object.assign(new Error(message), { code, uncertain, retryable, ...extra });
}
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The status the receipt reports for `to`, or undefined when it names anyone else, several recipients, or no bucket. */
function receiptStatus(result: Record<string, unknown>, to: string): CloudflareEmailStatus | undefined {
  const reported: CloudflareEmailStatus[] = [];
  for (const [key, status] of BUCKETS) {
    const values = result[key] ?? (key === 'suppressed_recipients' ? [] : undefined);
    // Addresses are compared case-insensitively, as Campaign did; the domain is case-insensitive and providers fold the local part.
    if (!Array.isArray(values) || values.length > 1 || values.some(value => typeof value !== 'string' || value.toLowerCase() !== to.toLowerCase())) return undefined;
    if (values.length) reported.push(status);
  }
  return reported.length === 1 ? reported[0] : undefined;
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
export async function sendCloudflareEmail({ accountId, token, message, signal, timeoutMs = 30_000, fetch: send }: {
  accountId: string; token: string; message: CloudflareEmailMessage; signal?: AbortSignal; timeoutMs?: number;
  fetch?: (url: string, init: RequestInit) => Promise<Response>;
}): Promise<{ status: CloudflareEmailStatus; messageId: string | null }> {
  if (typeof accountId !== 'string' || !/^[a-f0-9]{32}$/i.test(accountId)) invalidEmailInput('Cloudflare', 'account ID');
  if (typeof token !== 'string' || !/^[!-~]{1,4096}$/.test(token)) invalidEmailInput('Cloudflare', 'token');
  if (send !== undefined && typeof send !== 'function') invalidEmailInput('Cloudflare', 'fetch');
  const { from, to, subject, text, html, replyTo, headers } = checkEmailMessage(message, 'Cloudflare');
  if (signal?.aborted) throw sendError('The Cloudflare request was aborted before it was sent.', 'ABORTED', false, false);
  // Request shape: https://developers.cloudflare.com/api/resources/email_sending/methods/send/
  const body = JSON.stringify({
    from: from.name === undefined ? from.address : { address: from.address, name: from.name }, to: [to], subject,
    ...(text ? { text } : {}), ...(html ? { html } : {}), ...(replyTo === undefined ? {} : { reply_to: replyTo }),
    ...(headers.length ? { headers: Object.fromEntries(headers.map(({ name, value }) => [name, value])) } : {}),
  });

  let reply: Awaited<ReturnType<typeof providerFetchJson>>;
  try {
    reply = await providerFetchJson(`https://api.cloudflare.com/client/v4/accounts/${accountId.toLowerCase()}/email/sending/send`, {
      hosts: HOSTS, timeoutMs, maxBytes: 65_536, ...(signal ? { signal } : {}), ...(send ? { fetch: send } : {}),
      init: { method: 'POST', credentials: 'omit', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' }, body },
    });
  } catch (error) {
    // A caller abort comes back as the caller's own reason, so it is recognised by the signal, not by a code.
    if (signal?.aborted) throw sendError('The Cloudflare request was aborted; the email may have been sent.', 'ABORTED', true, false);
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'PROVIDER_RESPONSE_INVALID') throw sendError('Cloudflare returned an unreadable acceptance; the email may have been sent.', 'INVALID_RESPONSE', true, false);
    if (code === 'PROVIDER_TIMEOUT') throw sendError('The Cloudflare request timed out; the email may have been sent.', 'TIMEOUT', true, false);
    if (code === 'PROVIDER_UNAVAILABLE') throw sendError('The Cloudflare request failed in transit; the email may have been sent.', 'NETWORK_ERROR', true, false);
    throw error;
  }

  const { status } = reply;
  if (reply.ok) {
    const result = plain(reply.body) && reply.body.success === true && plain(reply.body.result) ? reply.body.result : undefined;
    const reported = result && receiptStatus(result, to);
    const messageId = result?.message_id ?? null;
    if (!reported || messageId !== null && (typeof messageId !== 'string' || !MESSAGE_ID.test(messageId))) {
      throw sendError('Cloudflare returned an unreadable acceptance; the email may have been sent.', 'INVALID_RESPONSE', true, false, { status });
    }
    return { status: reported, messageId: messageId as string | null };
  }
  const first = plain(reply.body) && Array.isArray(reply.body.errors) ? (reply.body.errors[0] as { code?: unknown } | undefined)?.code : undefined;
  const extra = { status, ...(Number.isSafeInteger(first) ? { providerCode: first as number } : {}) };
  if (reply.class === 'rate_limit') throw sendError('Cloudflare throttled the email; it was not sent.', 'HTTP_429', false, true, extra);
  if (reply.class === 'server_error' || reply.class === 'other') throw sendError(`Cloudflare failed with HTTP ${status}; the email may have been sent.`, `HTTP_${status}`, true, false, extra);
  throw sendError(`Cloudflare rejected the email (HTTP ${status}).`, `HTTP_${status}`, false, false, extra);
}
