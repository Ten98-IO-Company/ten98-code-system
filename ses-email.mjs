// Amazon SES v2 SendEmail over fetch with in-house SigV4 signing, so apps need no AWS SDK.
// Every request goes to a constant regional origin chosen from an allowlist; no host is built from input.
// Callers retain credentials, sender identity, suppression/consent policy, retries and send accounting.
import { createHash, createHmac } from 'node:crypto';
import { readResponseText } from './browser.mjs';
import { checkEmailMessage } from './email-message.mjs';
/** SES v2 API origins for the commercial partition, from https://docs.aws.amazon.com/general/latest/gr/ses.html. */
const SES_ORIGINS = Object.freeze({
    'us-east-1': 'https://email.us-east-1.amazonaws.com',
    'us-east-2': 'https://email.us-east-2.amazonaws.com',
    'us-west-1': 'https://email.us-west-1.amazonaws.com',
    'us-west-2': 'https://email.us-west-2.amazonaws.com',
    'af-south-1': 'https://email.af-south-1.amazonaws.com',
    'ap-south-1': 'https://email.ap-south-1.amazonaws.com',
    'ap-south-2': 'https://email.ap-south-2.amazonaws.com',
    'ap-southeast-1': 'https://email.ap-southeast-1.amazonaws.com',
    'ap-southeast-2': 'https://email.ap-southeast-2.amazonaws.com',
    'ap-southeast-3': 'https://email.ap-southeast-3.amazonaws.com',
    'ap-southeast-5': 'https://email.ap-southeast-5.amazonaws.com',
    'ap-northeast-1': 'https://email.ap-northeast-1.amazonaws.com',
    'ap-northeast-2': 'https://email.ap-northeast-2.amazonaws.com',
    'ap-northeast-3': 'https://email.ap-northeast-3.amazonaws.com',
    'ca-central-1': 'https://email.ca-central-1.amazonaws.com',
    'ca-west-1': 'https://email.ca-west-1.amazonaws.com',
    'eu-central-1': 'https://email.eu-central-1.amazonaws.com',
    'eu-central-2': 'https://email.eu-central-2.amazonaws.com',
    'eu-west-1': 'https://email.eu-west-1.amazonaws.com',
    'eu-west-2': 'https://email.eu-west-2.amazonaws.com',
    'eu-west-3': 'https://email.eu-west-3.amazonaws.com',
    'eu-south-1': 'https://email.eu-south-1.amazonaws.com',
    'eu-north-1': 'https://email.eu-north-1.amazonaws.com',
    'il-central-1': 'https://email.il-central-1.amazonaws.com',
    'me-south-1': 'https://email.me-south-1.amazonaws.com',
    'me-central-1': 'https://email.me-central-1.amazonaws.com',
    'sa-east-1': 'https://email.sa-east-1.amazonaws.com',
});
/** Commercial AWS regions with an SES v2 API endpoint. */
export const SES_REGIONS = Object.freeze(Object.keys(SES_ORIGINS));
const SEND_PATH = '/v2/email/outbound-emails';
const THROTTLING = new Set(['ThrottlingException', 'TooManyRequestsException', 'Throttling']);
function invalid(field, code = 'INVALID_INPUT') {
    throw Object.assign(new TypeError(`Invalid SES ${field}.`), { code });
}
function sendError(message, code, uncertain, retryable, status) {
    return Object.assign(new Error(message), { code, uncertain, retryable, ...(status === undefined ? {} : { status }) });
}
const sha256 = (data) => createHash('sha256').update(data, 'utf8').digest('hex');
const hmac = (key, data) => createHmac('sha256', key).update(data, 'utf8').digest();
/** SigV4 signing key: HMAC chain kSecret → kDate → kRegion → kService → kSigning. */
export function deriveAwsV4SigningKey(secretAccessKey, dateStamp, region, service) {
    return hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, dateStamp), region), service), 'aws4_request');
}
/**
 * Signs a request without a query string using AWS Signature Version 4 in the Authorization header.
 * Returns `headers` plus `x-amz-date`, `x-amz-security-token` (with a session token) and `authorization`; `host` is
 * signed but not returned because fetch derives it from the URL.
 */
export function signAwsV4Request({ method, host, path, headers = {}, body = '', credentials, region, service, date }) {
    if (!/^\/[A-Za-z0-9\-._~/]*$/.test(path))
        invalid('request path');
    if (Number.isNaN(date.getTime()))
        invalid('signing date');
    const amzDate = date.toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[-:]/g, '');
    const dateStamp = amzDate.slice(0, 8);
    const signed = { ...headers, 'x-amz-date': amzDate };
    if (credentials.sessionToken !== undefined)
        signed['x-amz-security-token'] = credentials.sessionToken;
    const canonical = new Map([['host', host]]);
    for (const [name, value] of Object.entries(signed))
        canonical.set(name.toLowerCase(), value.trim().replace(/ +/g, ' '));
    const names = [...canonical.keys()].sort();
    const signedHeaders = names.join(';');
    const canonicalRequest = [method, path, '', ...names.map(name => `${name}:${canonical.get(name)}`), '', signedHeaders, sha256(body)].join('\n');
    const scope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
    const signature = createHmac('sha256', deriveAwsV4SigningKey(credentials.secretAccessKey, dateStamp, region, service)).update(stringToSign, 'utf8').digest('hex');
    return { ...signed, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}
/** The fixed SES v2 API origin for an allowlisted region; anything else throws INVALID_REGION. */
export function sesOrigin(region) {
    if (typeof region !== 'string' || !Object.hasOwn(SES_ORIGINS, region))
        invalid('region', 'INVALID_REGION');
    return SES_ORIGINS[region];
}
function credentialsOf(value) {
    const { accessKeyId, secretAccessKey, sessionToken } = (value ?? {});
    if (typeof accessKeyId !== 'string' || !/^[A-Z0-9]{16,128}$/.test(accessKeyId))
        invalid('credentials');
    if (typeof secretAccessKey !== 'string' || !/^[!-~]{1,256}$/.test(secretAccessKey))
        invalid('credentials');
    if (sessionToken !== undefined && (typeof sessionToken !== 'string' || !/^[!-~]{1,4096}$/.test(sessionToken)))
        invalid('credentials');
    return { accessKeyId, secretAccessKey, ...(sessionToken === undefined ? {} : { sessionToken }) };
}
function requestBody(message, configurationSetName, idempotencyKey) {
    const { from, to, subject, text, html, replyTo, headers } = checkEmailMessage(message, 'SES', { reservedHeaderPrefix: 'x-ses-' });
    if (configurationSetName !== undefined && (typeof configurationSetName !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(configurationSetName)))
        invalid('configuration set name');
    // MessageTag values allow only letters, digits, underscore and dash: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_MessageTag.html
    if (idempotencyKey !== undefined && (typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(idempotencyKey)))
        invalid('idempotency key');
    const content = (data) => ({ Data: data, Charset: 'UTF-8' });
    const simpleHeaders = headers.map(({ name, value }) => ({ Name: name, Value: value }));
    // Request shape: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html
    return JSON.stringify({
        FromEmailAddress: from.raw,
        Destination: { ToAddresses: [to] },
        ...(replyTo === undefined ? {} : { ReplyToAddresses: [replyTo] }),
        Content: { Simple: {
                Subject: content(subject),
                Body: { ...(text ? { Text: content(text) } : {}), ...(html ? { Html: content(html) } : {}) },
                ...(simpleHeaders.length ? { Headers: simpleHeaders } : {}),
            } },
        ...(configurationSetName === undefined ? {} : { ConfigurationSetName: configurationSetName }),
        ...(idempotencyKey === undefined ? {} : { EmailTags: [{ Name: 'idempotency-key', Value: idempotencyKey }] }),
    });
}
/** The SES error type from `x-amzn-ErrorType` or the JSON body, restricted to a plain identifier. */
async function errorType(response, signal) {
    let type = response.headers.get('x-amzn-errortype')?.split(':')[0];
    if (!type) {
        try {
            const parsed = JSON.parse(await readResponseText(response, { maxBytes: 65_536, signal }));
            const raw = parsed.__type ?? parsed.code ?? parsed.Code;
            if (typeof raw === 'string')
                type = raw.slice(raw.lastIndexOf('#') + 1);
        }
        catch {
            return undefined;
        }
    }
    else
        void response.body?.cancel().catch(() => { });
    return type && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(type) ? type : undefined;
}
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
export async function sendSesEmail({ region, credentials, message, configurationSetName, idempotencyKey, fetch: send = globalThis.fetch, now = () => new Date(), signal }) {
    const origin = sesOrigin(region);
    if (typeof send !== 'function')
        invalid('fetch');
    const keys = credentialsOf(credentials);
    const body = requestBody(message, configurationSetName, idempotencyKey);
    const date = now();
    if (!(date instanceof Date))
        invalid('clock');
    const headers = signAwsV4Request({
        method: 'POST', host: origin.slice('https://'.length), path: SEND_PATH, headers: { 'content-type': 'application/json' },
        body, credentials: keys, region, service: 'ses', date,
    });
    const deadline = signal ?? AbortSignal.timeout(30_000);
    if (deadline.aborted)
        throw sendError('The SES request was aborted before it was sent.', 'ABORTED', false, false);
    let response;
    try {
        response = await send(origin + SEND_PATH, { method: 'POST', headers, body, redirect: 'error', credentials: 'omit', signal: deadline });
    }
    catch {
        const timedOut = deadline.aborted && deadline.reason?.name === 'TimeoutError';
        if (deadline.aborted)
            throw sendError(`The SES request ${timedOut ? 'timed out' : 'was aborted'}; the email may have been sent.`, timedOut ? 'TIMEOUT' : 'ABORTED', true, false);
        throw sendError('The SES request failed in transit; the email may have been sent.', 'NETWORK_ERROR', true, false);
    }
    const { status } = response;
    if (response.ok) {
        let messageId;
        try {
            messageId = JSON.parse(await readResponseText(response, { maxBytes: 65_536, signal: deadline }))?.MessageId;
        }
        catch {
            messageId = undefined;
        }
        if (typeof messageId !== 'string' || !/^[!-~]{1,256}$/.test(messageId))
            throw sendError('SES returned an unreadable acceptance; the email may have been sent.', 'INVALID_RESPONSE', true, false, status);
        return { accepted: true, messageId };
    }
    const type = await errorType(response, deadline);
    if (status === 429 || type !== undefined && THROTTLING.has(type))
        throw sendError('SES throttled the email; it was not sent.', type ?? 'TooManyRequestsException', false, true, status);
    if (status >= 500)
        throw sendError(`SES failed with HTTP ${status}; the email may have been sent.`, type ?? `HTTP_${status}`, true, false, status);
    const code = type ?? `HTTP_${status}`;
    throw sendError(`SES rejected the email (${code}).`, code, false, false, status);
}
