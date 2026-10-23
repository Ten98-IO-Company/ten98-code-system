export declare const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'];
export type WorkspaceRole = typeof workspaceRoles[number];
export declare function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean;
export declare function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean;
/** Options for {@link readResponseText}. */
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
export declare function openRouterFetch(path: string, { apiKey, title, body, signal, metadata }?: {
    apiKey?: string;
    title?: string;
    body?: unknown;
    signal?: AbortSignal;
    metadata?: boolean;
}, send?: typeof fetch): Promise<Response>;
export declare function oidcEndpoint(raw: string | URL, { allowHttp, issuer }?: {
    allowHttp?: boolean;
    issuer?: boolean;
}): URL;
export * from './migration-ledger.mjs';
export * from './client-address.mjs';
export * from './ses-email.mjs';
export * from './sns-notification.mjs';
export * from './email-feedback.mjs';
export * from './bootstrap-token.mjs';
