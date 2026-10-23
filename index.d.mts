export declare const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'];
export type WorkspaceRole = typeof workspaceRoles[number];
export declare function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean;
export declare function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean;
/**
 * With `contentLength: true`, a declared Content-Length must be a plain decimal, a declaration above `maxBytes` is refused
 * before any byte is read, and an identity-encoded body must match the declaration exactly. Errors carry `code`:
 * `RESPONSE_TOO_LARGE` (RangeError), `CONTENT_LENGTH_INVALID` or `RESPONSE_INCOMPLETE` (TypeError); malformed UTF-8 is a plain TypeError.
 */
export declare function readResponseText(response: Response, options: {
    maxBytes: number;
    signal?: AbortSignal;
    preserveBOM?: boolean;
    contentLength?: boolean;
}): Promise<string>;
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
