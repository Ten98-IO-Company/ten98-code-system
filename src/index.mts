// Callers retain provider parsing, authorization, accounting and error presentation.
export const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'] = Object.freeze(['owner', 'admin', 'editor', 'viewer']);
export type WorkspaceRole = typeof workspaceRoles[number];
export function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean {
  return workspaceRoles.some(value => value === role) && (actor === 'owner' || actor === 'admin' && (role === 'editor' || role === 'viewer'));
}
export function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean {
  return mayGrantWorkspaceRole(actor, previousRole) && (nextRole === undefined || mayGrantWorkspaceRole(actor, nextRole));
}

export function readResponseText(response: Response, options: { maxBytes: number; signal?: AbortSignal; preserveBOM?: boolean }): Promise<string>;
export async function readResponseText(response: Response, { maxBytes, signal, preserveBOM = false }: { maxBytes?: number; signal?: AbortSignal; preserveBOM?: boolean } = {}): Promise<string> {
  if (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes must be a nonnegative safe integer.');
  const reader = response.body?.getReader();
  if (!reader) { signal?.throwIfAborted(); return ''; }
  const abort = () => { void reader.cancel(signal?.reason).catch(() => {}); };
  signal?.addEventListener('abort', abort, { once: true });
  try {
    signal?.throwIfAborted();
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: preserveBOM });
    let bytes = 0, text = '';
    while (true) {
      const { value, done } = await reader.read();
      signal?.throwIfAborted();
      if (done) return text + decoder.decode();
      bytes += value.byteLength;
      if (bytes > maxBytes) throw new RangeError('Response exceeds the byte limit.');
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    signal?.removeEventListener('abort', abort);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function openRouterFetch(path: string, { apiKey, title, body, signal, metadata }: {
  apiKey?: string; title?: string; body?: unknown; signal?: AbortSignal; metadata?: boolean;
} = {}, send: typeof fetch = fetch): Promise<Response> {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\s#]/u.test(path)) throw new TypeError('OpenRouter path must be an API-relative path.');
  const route = path.split('?')[0];
  const decoded = decodeURIComponent(route);
  if (decoded.includes('\\') || decoded.split('/').some(segment => segment === '.' || segment === '..')) throw new TypeError('OpenRouter path cannot traverse directories.');
  const url = new URL('https://openrouter.ai/api/v1' + path);
  if (url.origin !== 'https://openrouter.ai' || !url.pathname.startsWith('/api/v1/') || url.username || url.password || url.hash) throw new TypeError('Invalid OpenRouter API path.');
  const headers: Record<string, string> = { accept: 'application/json' };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  if (title) headers['x-openrouter-title'] = title;
  if (metadata) headers['x-openrouter-metadata'] = 'enabled';
  if (body !== undefined) headers['content-type'] = 'application/json';
  return send(url.href, {
    headers,
    ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
    redirect: 'error', credentials: 'omit',
    signal: signal ?? AbortSignal.timeout(body === undefined ? 10_000 : 60_000),
  });
}

export function oidcEndpoint(raw: string | URL, { allowHttp = false, issuer = false }: { allowHttp?: boolean; issuer?: boolean } = {}): URL {
  const url = new URL(raw);
  if ((url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) || url.username || url.password || url.href.includes('#') || issuer && url.href.includes('?')) throw new TypeError('Invalid OIDC endpoint URL.');
  return url;
}
