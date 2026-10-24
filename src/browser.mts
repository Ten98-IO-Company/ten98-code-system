// The browser entry: no Node built-ins, so client bundles can import it without a bundler shim.
// Callers retain provider parsing, authorization, accounting and error presentation.
export const workspaceRoles: readonly ['owner', 'admin', 'editor', 'viewer'] = Object.freeze(['owner', 'admin', 'editor', 'viewer']);
export type WorkspaceRole = typeof workspaceRoles[number];
export function mayGrantWorkspaceRole(actor: unknown, role: unknown): boolean {
  return workspaceRoles.some(value => value === role) && (actor === 'owner' || actor === 'admin' && (role === 'editor' || role === 'viewer'));
}
export function mayManageWorkspaceMember(actor: unknown, previousRole: unknown, nextRole?: unknown): boolean {
  return mayGrantWorkspaceRole(actor, previousRole) && (nextRole === undefined || mayGrantWorkspaceRole(actor, nextRole));
}

const lengthError = (code: 'CONTENT_LENGTH_INVALID' | 'RESPONSE_INCOMPLETE' | 'RESPONSE_DECODE_INVALID', message: string) => Object.assign(new TypeError(message), { code });

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
export function readResponseText(response: Response, options: ReadResponseTextOptions): Promise<string>;
export async function readResponseText(response: Response, { preserveBOM = false, ...options }: Partial<ReadResponseTextOptions> = {}): Promise<string> {
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: preserveBOM });
  const decode = (value?: Uint8Array): string => {
    try { return value ? decoder.decode(value, { stream: true }) : decoder.decode(); }
    catch { throw lengthError('RESPONSE_DECODE_INVALID', 'Response body is not valid UTF-8.'); }
  };
  let text = '';
  await readBounded(response, options, value => { text += decode(value); });
  return text + decode();
}

/** Options for {@link readResponseBytes}: the same limits as {@link readResponseText}, without text decoding. */
export type ReadResponseBytesOptions = Omit<ReadResponseTextOptions, 'preserveBOM'>;

/**
 * Reads the exact response bytes under the same limits and error codes as {@link readResponseText}, for bodies that are
 * hashed, signed, saved or decoded by the caller (CSV and zip downloads, HMAC-verified webhooks, media).
 */
export function readResponseBytes(response: Response, options: ReadResponseBytesOptions): Promise<Uint8Array>;
export async function readResponseBytes(response: Response, options: Partial<ReadResponseBytesOptions> = {}): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const total = await readBounded(response, options, value => { parts.push(value); });
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  return bytes;
}

// One read loop for both readers, so limits, codes and error precedence cannot drift apart. Returns the byte count.
async function readBounded(response: Response, { maxBytes, signal, contentLength = false, maxChunks }: Partial<ReadResponseBytesOptions>, onChunk: (value: Uint8Array) => void): Promise<number> {
  if (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes must be a nonnegative safe integer.');
  if (maxChunks !== undefined && (!Number.isSafeInteger(maxChunks) || maxChunks < 1)) throw new TypeError('maxChunks must be a positive safe integer.');
  if (![false, true, 'limit', 'exact'].includes(contentLength)) throw new TypeError("contentLength must be true, false, 'limit' or 'exact'.");
  const tooLarge = () => Object.assign(new RangeError('Response exceeds the byte limit.'), { code: 'RESPONSE_TOO_LARGE' });
  let declared: number | undefined;
  if (contentLength) {
    const header = response.headers.get('content-length');
    if (header !== null) {
      if (!/^(?:0|[1-9]\d{0,15})$/u.test(header)) { void response.body?.cancel().catch(() => {}); throw lengthError('CONTENT_LENGTH_INVALID', 'Response Content-Length is invalid.'); }
      if (Number(header) > maxBytes) { void response.body?.cancel().catch(() => {}); throw tooLarge(); }
      // Fetch decodes compressed bodies, so only an identity-encoded body can be compared byte for byte.
      const encoding = response.headers.get('content-encoding');
      if (contentLength !== 'limit' && (encoding === null || encoding.trim().toLowerCase() === 'identity')) declared = Number(header);
    }
  }
  const reader = response.body?.getReader();
  if (!reader) {
    signal?.throwIfAborted();
    if (declared) throw lengthError('RESPONSE_INCOMPLETE', 'Response body is shorter than its Content-Length.');
    return 0;
  }
  const abort = () => { void reader.cancel(signal?.reason).catch(() => {}); };
  signal?.addEventListener('abort', abort, { once: true });
  try {
    signal?.throwIfAborted();
    let bytes = 0, chunks = 0;
    while (true) {
      const { value, done } = await reader.read();
      signal?.throwIfAborted();
      if (done) {
        if (declared !== undefined && bytes !== declared) throw lengthError('RESPONSE_INCOMPLETE', 'Response body is shorter than its Content-Length.');
        return bytes;
      }
      // A stream of strings or other objects has no byteLength, which would silently disable every byte limit.
      if (!(value instanceof Uint8Array)) throw new TypeError('Response body chunks must be bytes.');
      bytes += value.byteLength;
      if (bytes > maxBytes) throw tooLarge();
      if (maxChunks !== undefined && ++chunks > maxChunks) throw Object.assign(new RangeError('Response arrived in too many chunks.'), { code: 'RESPONSE_TOO_MANY_CHUNKS' });
      if (declared !== undefined && bytes > declared) throw lengthError('RESPONSE_INCOMPLETE', 'Response body is longer than its Content-Length.');
      onChunk(value);
    }
  } finally {
    signal?.removeEventListener('abort', abort);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
