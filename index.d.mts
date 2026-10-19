export const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'];
export type WorkspaceRole = typeof workspaceRoles[number];
export function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean;
export function readResponseText(response: Response, options: { maxBytes: number; signal?: AbortSignal; preserveBOM?: boolean }): Promise<string>;
export function openRouterFetch(path: string, options?: {
  apiKey?: string;
  title?: string;
  body?: unknown;
  signal?: AbortSignal;
  metadata?: boolean;
}, send?: typeof fetch): Promise<Response>;
export function oidcEndpoint(raw: string | URL, options?: { allowHttp?: boolean; issuer?: boolean }): URL;
