// Fixed-host provider JSON calls. Promoted from Campaign server/provider-core.ts providerRequest and assertProviderPath
// (v0.32.1) and Discover src/server/google-http.ts googleRequest (v0.7.4). Apps keep credentials, idempotency, which
// failures are uncertain, and how an outcome becomes their own error type.
import { readResponseText } from './browser.mjs';
const failure = (code, message, cause) => Object.assign(code === 'PROVIDER_URL_INVALID' ? new TypeError(message) : new Error(message, { cause }), { code });
// The allowed hosts receive the caller's credentials, so an ID inside the path must not change which endpoint is called.
// URL parsing resolves dot segments even when encoded as %2e and turns a raw backslash into a slash, so the URL is checked
// as written, and each segment again after one decoding, so '..%2Fx' cannot become '../x' at the provider.
function unsafePath(written) {
    const path = written.replace(/^https:\/\/[^/?#]*/i, '').split('?')[0];
    const decoded = (segment) => { try {
        return decodeURIComponent(segment);
    }
    catch {
        return segment;
    } };
    return path.includes('\\') || path.split('/').some(segment => {
        const once = decoded(segment);
        return once.includes('\\') || once.split('/').some(part => part === '.' || part === '..');
    });
}
/**
 * Calls an allowed provider host and reads a bounded JSON reply. The URL must be https on one of `hosts` (lowercase
 * hostnames) with no port, credentials, fragment, backslash or dot segment; the request goes to a rebuilt
 * `https://host/path?query`, never follows redirects and is aborted after `timeoutMs`. `init` supplies the method,
 * headers and body. A non-2xx status is returned, not thrown, with the error body parsed when it is readable JSON.
 * A 2xx body must be strict JSON (no BOM) of at most `maxBytes`, or the call throws `PROVIDER_RESPONSE_INVALID`.
 * An abort from the caller's `signal` rethrows its reason.
 */
export async function providerFetchJson(url, { hosts, timeoutMs, maxBytes, signal, init = {}, fetch: transport = fetch }) {
    if (!Array.isArray(hosts) || hosts.length === 0 || hosts.some(host => typeof host !== 'string' || URL.parse(`https://${host}`)?.hostname !== host)) {
        throw new TypeError('hosts must list lowercase hostnames.');
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)
        throw new TypeError('timeoutMs must be a positive safe integer.');
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
        throw new TypeError('maxBytes must be a nonnegative safe integer.');
    const written = typeof url === 'string' ? url : url.href;
    const target = URL.parse(written);
    if (!target || target.protocol !== 'https:' || !hosts.includes(target.hostname) || target.port || target.username || target.password
        || written.includes('#') || unsafePath(written))
        throw failure('PROVIDER_URL_INVALID', 'The provider endpoint is invalid.');
    const destination = `https://${target.hostname}${target.pathname}${target.search}`;
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
    const status = response.status;
    const statusClass = response.ok ? 'success' : status === 429 ? 'rate_limit' : status >= 500 ? 'server_error' : 'client_error';
    let text;
    try {
        text = await readResponseText(response, { maxBytes, signal: combined, contentLength: 'limit', preserveBOM: true });
    }
    catch (error) {
        if (signal?.aborted || response.ok && deadline.aborted)
            throw interrupted(error);
        if (response.ok)
            throw failure('PROVIDER_RESPONSE_INVALID', 'The provider returned an unreadable response.', error);
        return { ok: false, status, class: statusClass, headers: response.headers, body: undefined };
    }
    let body;
    try {
        body = text === '' ? undefined : JSON.parse(text);
    }
    catch (error) {
        if (response.ok)
            throw failure('PROVIDER_RESPONSE_INVALID', 'The provider returned an unreadable response.', error);
    }
    return { ok: response.ok, status, class: statusClass, headers: response.headers, body };
}
