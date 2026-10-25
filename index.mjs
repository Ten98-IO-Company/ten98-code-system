// Callers retain provider parsing, authorization, accounting and error presentation.
export * from './browser.mjs';
export function openRouterFetch(path, { apiKey, title, body, signal, metadata } = {}, send = fetch) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\s#]/u.test(path))
        throw new TypeError('OpenRouter path must be an API-relative path.');
    const route = path.split('?')[0];
    const decoded = decodeURIComponent(route);
    if (decoded.includes('\\') || decoded.split('/').some(segment => segment === '.' || segment === '..'))
        throw new TypeError('OpenRouter path cannot traverse directories.');
    const url = new URL('https://openrouter.ai/api/v1' + path);
    if (url.origin !== 'https://openrouter.ai' || !url.pathname.startsWith('/api/v1/') || url.username || url.password || url.hash)
        throw new TypeError('Invalid OpenRouter API path.');
    // Header validation errors quote the value, so refuse control characters first without echoing the key or title.
    if (apiKey !== undefined && (typeof apiKey !== 'string' || /[\u0000-\u001f\u007f]/u.test(apiKey)))
        throw new TypeError('OpenRouter API key contains invalid characters.');
    if (title !== undefined && (typeof title !== 'string' || /[\u0000-\u001f\u007f]/u.test(title)))
        throw new TypeError('OpenRouter title contains invalid characters.');
    const headers = { accept: 'application/json' };
    if (apiKey)
        headers.Authorization = `Bearer ${apiKey}`;
    if (title)
        headers['x-openrouter-title'] = title;
    if (metadata)
        headers['x-openrouter-metadata'] = 'enabled';
    if (body !== undefined)
        headers['content-type'] = 'application/json';
    return send(url.href, {
        headers,
        ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
        redirect: 'error', credentials: 'omit',
        signal: signal ?? AbortSignal.timeout(body === undefined ? 10_000 : 60_000),
    });
}
// Hosts where plain http stays on this machine. Both apps already use exactly this set for APP_URL and local OIDC tests.
const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
const httpAllowed = (url, allowHttp) => url.protocol === 'http:' && (allowHttp === true || allowHttp === 'loopback' && loopbackHosts.has(url.hostname));
/**
 * An https OIDC endpoint without credentials or a fragment; issuers also refuse a query. `allowHttp: 'loopback'` admits
 * plain http only on localhost, 127.0.0.1 and [::1], for local providers; `allowHttp: true` admits it on any host.
 */
export function oidcEndpoint(raw, { allowHttp = false, issuer = false } = {}) {
    if (![true, false, 'loopback'].includes(allowHttp))
        throw new TypeError("allowHttp must be true, false or 'loopback'.");
    const url = new URL(raw);
    if ((url.protocol !== 'https:' && !httpAllowed(url, allowHttp)) || url.username || url.password || url.href.includes('#') || issuer && url.href.includes('?'))
        throw new TypeError('Invalid OIDC endpoint URL.');
    return url;
}
/**
 * The origin of an application's public URL (APP_URL): https, or http on localhost, 127.0.0.1 or [::1]; no credentials,
 * path, query or fragment; a single trailing slash is accepted. Throws a TypeError with `code: 'APP_URL_INVALID'`.
 */
export function appOrigin(raw) {
    const invalid = (message) => Object.assign(new TypeError(message), { code: 'APP_URL_INVALID' });
    let url;
    try {
        url = new URL(raw);
    }
    catch {
        throw invalid('APP_URL must be an absolute http(s) URL.');
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:')
        throw invalid('APP_URL must use https.');
    if (url.username || url.password || url.search || raw.includes('#') || url.pathname !== '/')
        throw invalid('APP_URL must be an origin, without credentials, path, query or fragment.');
    if (!httpAllowed(url, 'loopback') && url.protocol !== 'https:')
        throw invalid('APP_URL must use https outside localhost, 127.0.0.1 and [::1].');
    return url.origin;
}
export * from './migration-ledger.mjs';
export * from './client-address.mjs';
export * from './ses-email.mjs';
export * from './sns-notification.mjs';
export * from './email-feedback.mjs';
export * from './capability-token.mjs';
export * from './json-body.mjs';
export * from './cloudflare-email.mjs';
export * from './public-hostname.mjs';
export * from './provider-fetch.mjs';
