// Fixed-host provider JSON calls. Promoted from Campaign server/provider-core.ts providerRequest and assertProviderPath
// (v0.32.1) and Discover src/server/google-http.ts googleRequest (v0.7.4). Apps keep credentials, idempotency, which
// failures are uncertain, and how an outcome becomes their own error type.
import { readResponseText } from './browser.mjs';
const failure = (code, message, cause) => Object.assign(code === 'PROVIDER_URL_INVALID' ? new TypeError(message) : new Error(message, { cause }), { code });
// What the bounded reader reports about the body itself; any other read failure is the connection's.
const bodyCodes = new Set(['RESPONSE_TOO_LARGE', 'CONTENT_LENGTH_INVALID', 'RESPONSE_INCOMPLETE', 'RESPONSE_DECODE_INVALID']);
// The allowed hosts receive the caller's credentials, so an ID inside the path must not change which endpoint is called.
// URL parsing resolves dot segments even when encoded as %2e and turns a backslash into a slash, so the URL is checked as
// written. Each segment is checked again with %2e, %2f and %5c decoded, as a provider that decodes once would see it,
// and '..;' and double-encoded forms are refused for servers that treat them as '..'.
function unsafePath(written) {
    const path = written.replace(/^https:\/\/[^/\\?#]*/i, '').split('?')[0];
    if (path.includes('\\') || /%25(?:2e|2f|5c)/i.test(path))
        return true;
    return path.split('/').some(segment => {
        const once = segment.replace(/%(?:2e|2f|5c)/gi, escape => decodeURIComponent(escape));
        return once.includes('\\') || once.split('/').some(part => /^\.\.?(?:;|$)/.test(part));
    });
}
/**
 * Calls an allowed provider host and reads a bounded JSON reply.
 *
 * `url` is a string, checked as written: https on one of `hosts` (lowercase hostnames), with no port, credentials,
 * fragment, control character, surrounding whitespace, backslash or dot segment. Build it from constant text and
 * `encodeURIComponent` for each ID; a URL object's href is already resolved, so it is refused rather than checked.
 * The request goes to a rebuilt `https://host/path?query` and is aborted after `timeoutMs`. `init` supplies the method,
 * headers and body, and may not set a Host header or a dispatcher. Redirects are refused with the default `fetch`; a
 * custom transport that returns a 3xx gets class `other`.
 *
 * A non-2xx status is returned, not thrown, with the error body parsed when it is readable JSON. A 2xx body of zero
 * length gives `body: undefined`; any other 2xx body must be strict JSON (no BOM) of at most `maxBytes`, or the call
 * throws `PROVIDER_RESPONSE_INVALID`. `PROVIDER_TIMEOUT` means the deadline passed, while connecting or reading;
 * `PROVIDER_UNAVAILABLE` means the connection failed. An abort from the caller's `signal` rethrows its reason, before
 * anything is sent if it was already aborted. Invalid options throw a TypeError without a code.
 */
export async function providerFetchJson(url, { hosts, timeoutMs, maxBytes, signal, init = {}, fetch: transport = fetch }) {
    if (!Array.isArray(hosts) || hosts.length === 0 || hosts.some(host => typeof host !== 'string' || URL.parse(`https://${host}`)?.hostname !== host)) {
        throw new TypeError('hosts must list lowercase hostnames.');
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)
        throw new TypeError('timeoutMs must be a positive safe integer.');
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
        throw new TypeError('maxBytes must be a nonnegative safe integer.');
    if ('dispatcher' in init || new Headers(init.headers).has('host'))
        throw new TypeError('init may not set a Host header or a dispatcher.');
    // The parser drops tab, LF and CR anywhere and trims the ends before resolving dot segments, which would hide them here.
    const target = typeof url === 'string' && !/[\u0000-\u001f\u007f]/.test(url) && url === url.trim() ? URL.parse(url) : null;
    if (!target || target.protocol !== 'https:' || !hosts.includes(target.hostname) || target.port || target.username || target.password
        || url.includes('#') || unsafePath(url))
        throw failure('PROVIDER_URL_INVALID', 'The provider endpoint is invalid.');
    const destination = `https://${target.hostname}${target.pathname}${target.search}`;
    signal?.throwIfAborted();
    const deadline = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const interrupted = (error) => {
        if (signal?.aborted)
            return signal.reason;
        return deadline.aborted ? failure('PROVIDER_TIMEOUT', 'The provider did not answer in time.', error) : failure('PROVIDER_UNAVAILABLE', 'The provider could not be reached.', error);
    };
    let response;
    try {
        response = await transport(destination, { ...init, redirect: 'error', signal: combined });
    }
    catch (error) {
        throw interrupted(error);
    }
    const { status, ok, headers } = response;
    const statusClass = ok ? 'success' : status === 429 ? 'rate_limit' : status >= 500 && status <= 599 ? 'server_error'
        : status >= 400 && status <= 499 ? 'client_error' : 'other';
    let text;
    try {
        text = await readResponseText(response, { maxBytes, signal: combined, contentLength: 'limit', preserveBOM: true });
    }
    catch (error) {
        if (signal?.aborted)
            throw signal.reason;
        if (!ok)
            return { ok, status, class: statusClass, headers, body: undefined };
        if (bodyCodes.has(error?.code ?? ''))
            throw failure('PROVIDER_RESPONSE_INVALID', 'The provider returned an unreadable response.', error);
        throw interrupted(error);
    }
    let body;
    try {
        body = text === '' ? undefined : JSON.parse(text);
    }
    catch (error) {
        if (ok)
            throw failure('PROVIDER_RESPONSE_INVALID', 'The provider returned an unreadable response.', error);
    }
    return { ok, status, class: statusClass, headers, body };
}
