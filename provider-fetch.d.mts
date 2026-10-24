/** `success` for 2xx; otherwise 429, 5xx or any other status, which callers map to their own retry rules. */
export type ProviderStatusClass = 'success' | 'rate_limit' | 'server_error' | 'client_error';
export interface ProviderJsonResult {
    ok: boolean;
    status: number;
    class: ProviderStatusClass;
    headers: Headers;
    /** Parsed JSON; `undefined` for an empty body, and for an error body that is unreadable or not JSON. */
    body: unknown;
}
/** `PROVIDER_URL_INVALID` (TypeError), `PROVIDER_TIMEOUT`, `PROVIDER_UNAVAILABLE` or `PROVIDER_RESPONSE_INVALID`. */
export type ProviderFetchError = Error & {
    code: 'PROVIDER_URL_INVALID' | 'PROVIDER_TIMEOUT' | 'PROVIDER_UNAVAILABLE' | 'PROVIDER_RESPONSE_INVALID';
};
/**
 * Calls an allowed provider host and reads a bounded JSON reply. The URL must be https on one of `hosts` (lowercase
 * hostnames) with no port, credentials, fragment, backslash or dot segment; the request goes to a rebuilt
 * `https://host/path?query`, never follows redirects and is aborted after `timeoutMs`. `init` supplies the method,
 * headers and body. A non-2xx status is returned, not thrown, with the error body parsed when it is readable JSON.
 * A 2xx body must be strict JSON (no BOM) of at most `maxBytes`, or the call throws `PROVIDER_RESPONSE_INVALID`.
 * An abort from the caller's `signal` rethrows its reason.
 */
export declare function providerFetchJson(url: string | URL, { hosts, timeoutMs, maxBytes, signal, init, fetch: transport }: {
    hosts: readonly string[];
    timeoutMs: number;
    maxBytes: number;
    signal?: AbortSignal;
    init?: Omit<RequestInit, 'redirect' | 'signal'>;
    fetch?: (url: string, init: RequestInit) => Promise<Response>;
}): Promise<ProviderJsonResult>;
