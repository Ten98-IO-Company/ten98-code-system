// Callers retain provider parsing, authorization, accounting and error presentation.
export const workspaceRoles = Object.freeze(['owner', 'admin', 'editor', 'viewer']);
export function mayGrantWorkspaceRole(actor, role) {
  return workspaceRoles.includes(role) && (actor === 'owner' || actor === 'admin' && (role === 'editor' || role === 'viewer'));
}
export function mayManageWorkspaceMember(actor, previousRole, nextRole) {
  return mayGrantWorkspaceRole(actor, previousRole) && (nextRole === undefined || mayGrantWorkspaceRole(actor, nextRole));
}

export async function readResponseText(response, { maxBytes, signal, preserveBOM = false } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes must be a nonnegative safe integer.');
  const reader = response.body?.getReader();
  if (!reader) { signal?.throwIfAborted(); return ''; }
  const abort = () => { void reader.cancel(signal.reason).catch(() => {}); };
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

export function openRouterFetch(path, { apiKey, title, body, signal, metadata } = {}, send = fetch) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\s#]/u.test(path)) throw new TypeError('OpenRouter path must be an API-relative path.');
  const route = path.split('?')[0];
  const decoded = decodeURIComponent(route);
  if (decoded.includes('\\') || decoded.split('/').some(segment => segment === '.' || segment === '..')) throw new TypeError('OpenRouter path cannot traverse directories.');
  const url = new URL('https://openrouter.ai/api/v1' + path);
  if (url.origin !== 'https://openrouter.ai' || !url.pathname.startsWith('/api/v1/') || url.username || url.password || url.hash) throw new TypeError('Invalid OpenRouter API path.');
  const headers = { accept: 'application/json' };
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

export function oidcEndpoint(raw, { allowHttp = false, issuer = false } = {}) {
  const url = new URL(raw);
  if ((url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) || url.username || url.password || url.href.includes('#') || issuer && url.href.includes('?')) throw new TypeError('Invalid OIDC endpoint URL.');
  return url;
}
