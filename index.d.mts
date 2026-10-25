export * from './browser.mjs';
export declare function openRouterFetch(path: string, { apiKey, title, body, signal, metadata }?: {
    apiKey?: string;
    title?: string;
    body?: unknown;
    signal?: AbortSignal;
    metadata?: boolean;
}, send?: typeof fetch): Promise<Response>;
/**
 * An https OIDC endpoint without credentials or a fragment; issuers also refuse a query. `allowHttp: 'loopback'` admits
 * plain http only on localhost, 127.0.0.1 and [::1], for local providers; `allowHttp: true` admits it on any host.
 */
export declare function oidcEndpoint(raw: string | URL, { allowHttp, issuer }?: {
    allowHttp?: boolean | 'loopback';
    issuer?: boolean;
}): URL;
/**
 * The origin of an application's public URL (APP_URL): https, or http on localhost, 127.0.0.1 or [::1]; no credentials,
 * path, query or fragment; a single trailing slash is accepted. Throws a TypeError with `code: 'APP_URL_INVALID'`.
 */
export declare function appOrigin(raw: string): string;
export * from './migration-ledger.mjs';
export * from './client-address.mjs';
export * from './ses-email.mjs';
export * from './sns-notification.mjs';
export * from './email-feedback.mjs';
export * from './capability-token.mjs';
export * from './json-body.mjs';
export * from './public-hostname.mjs';
export * from './provider-fetch.mjs';
