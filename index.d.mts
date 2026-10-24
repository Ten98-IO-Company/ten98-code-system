export declare const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'];
export type WorkspaceRole = typeof workspaceRoles[number];
export declare function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean;
export declare function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean;
/** Options for {@link readResponseText}; {@link readResponseBytes} takes the same limits. */
export interface ReadResponseTextOptions {
    maxBytes: number;
    signal?: AbortSignal;
    preserveBOM?: boolean;
    /**
     * `'limit'` checks a declared Content-Length (plain decimal, at most `maxBytes`) before reading. `'exact'`, or `true`,
     * also requires an identity-encoded body to match the declaration exactly.
     */
    contentLength?: boolean | 'limit' | 'exact';
    /** Refuse a body delivered in more than this many chunks, so a slow trickle of tiny chunks cannot hold the reader. */
    maxChunks?: number;
}
/**
 * Errors carry `code`: `RESPONSE_TOO_LARGE` or `RESPONSE_TOO_MANY_CHUNKS` (RangeError); `CONTENT_LENGTH_INVALID`,
 * `RESPONSE_INCOMPLETE` or `RESPONSE_DECODE_INVALID` for malformed UTF-8 (TypeError). Stream and network failures are
 * rethrown as they are, so a caller can tell an unreadable body from an interrupted one.
 */
export declare function readResponseText(response: Response, options: ReadResponseTextOptions): Promise<string>;
/** Options for {@link readResponseBytes}: the same limits as {@link readResponseText}, without text decoding. */
export type ReadResponseBytesOptions = Omit<ReadResponseTextOptions, 'preserveBOM'>;
/**
 * Reads the exact response bytes under the same limits and error codes as {@link readResponseText}, for bodies that are
 * hashed, signed, saved or decoded by the caller (CSV and zip downloads, HMAC-verified webhooks, media).
 */
export declare function readResponseBytes(response: Response, options: ReadResponseBytesOptions): Promise<Uint8Array>;
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
