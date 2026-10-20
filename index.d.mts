export declare const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'];
export type WorkspaceRole = typeof workspaceRoles[number];
export declare function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean;
export declare function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean;
export declare function readResponseText(response: Response, options: {
    maxBytes: number;
    signal?: AbortSignal;
    preserveBOM?: boolean;
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
