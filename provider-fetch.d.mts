/**
 * `success` for 2xx, `rate_limit` for 429, `server_error` for 5xx, `client_error` for any other 4xx, and `other` for
 * everything else a transport can return (status 0, 1xx, or a 3xx such as 304 that fetch passes through).
 */
export type ProviderStatusClass = 'success' | 'rate_limit' | 'server_error' | 'client_error' | 'other';
export interface ProviderJsonResult {
    ok: boolean;
    status: number;
    class: ProviderStatusClass;
    headers: Headers;
    /** Parsed JSON; `undefined` for a zero-length body, and for an error body that is unreadable or not JSON. */
    body: unknown;
}
/** `PROVIDER_URL_INVALID` (TypeError), `PROVIDER_TIMEOUT`, `PROVIDER_UNAVAILABLE` or `PROVIDER_RESPONSE_INVALID`. */
export type ProviderFetchError = Error & {
    code: 'PROVIDER_URL_INVALID' | 'PROVIDER_TIMEOUT' | 'PROVIDER_UNAVAILABLE' | 'PROVIDER_RESPONSE_INVALID';
};
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
export declare function providerFetchJson(url: string, { hosts, timeoutMs, maxBytes, signal, init, fetch: transport }: {
    hosts: readonly string[];
    timeoutMs: number;
    maxBytes: number;
    signal?: AbortSignal;
    init?: Omit<RequestInit, 'redirect' | 'signal'>;
    fetch?: (url: string, init: RequestInit) => Promise<Response>;
}): Promise<ProviderJsonResult>;
