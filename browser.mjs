// The browser entry: no Node built-ins, so client bundles can import it without a bundler shim.
// Callers retain provider parsing, authorization, accounting and error presentation.
export const workspaceRoles = Object.freeze(['owner', 'admin', 'editor', 'viewer']);
export function mayGrantWorkspaceRole(actor, role) {
    return workspaceRoles.some(value => value === role) && (actor === 'owner' || actor === 'admin' && (role === 'editor' || role === 'viewer'));
}
export function mayManageWorkspaceMember(actor, previousRole, nextRole) {
    return mayGrantWorkspaceRole(actor, previousRole) && (nextRole === undefined || mayGrantWorkspaceRole(actor, nextRole));
}
const lengthError = (code, message) => Object.assign(new TypeError(message), { code });
export async function readResponseText(response, { preserveBOM = false, ...options } = {}) {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: preserveBOM });
    const decode = (value) => {
        try {
            return value ? decoder.decode(value, { stream: true }) : decoder.decode();
        }
        catch {
            throw lengthError('RESPONSE_DECODE_INVALID', 'Response body is not valid UTF-8.');
        }
    };
    let text = '';
    await readBounded(response, options, value => { text += decode(value); });
    return text + decode();
}
export async function readResponseBytes(response, options = {}) {
    const parts = [];
    const total = await readBounded(response, options, value => { parts.push(value); });
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.byteLength;
    }
    return bytes;
}
// One read loop for both readers, so limits, codes and error precedence cannot drift apart. Returns the byte count.
async function readBounded(response, { maxBytes, signal, contentLength = false, maxChunks }, onChunk) {
    if (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 0)
        throw new TypeError('maxBytes must be a nonnegative safe integer.');
    if (maxChunks !== undefined && (!Number.isSafeInteger(maxChunks) || maxChunks < 1))
        throw new TypeError('maxChunks must be a positive safe integer.');
    if (![false, true, 'limit', 'exact'].includes(contentLength))
        throw new TypeError("contentLength must be true, false, 'limit' or 'exact'.");
    const tooLarge = () => Object.assign(new RangeError('Response exceeds the byte limit.'), { code: 'RESPONSE_TOO_LARGE' });
    let declared;
    if (contentLength) {
        const header = response.headers.get('content-length');
        if (header !== null) {
            if (!/^(?:0|[1-9]\d{0,15})$/u.test(header)) {
                void response.body?.cancel().catch(() => { });
                throw lengthError('CONTENT_LENGTH_INVALID', 'Response Content-Length is invalid.');
            }
            if (Number(header) > maxBytes) {
                void response.body?.cancel().catch(() => { });
                throw tooLarge();
            }
            // Fetch decodes compressed bodies, so only an identity-encoded body can be compared byte for byte.
            const encoding = response.headers.get('content-encoding');
            if (contentLength !== 'limit' && (encoding === null || encoding.trim().toLowerCase() === 'identity'))
                declared = Number(header);
        }
    }
    const reader = response.body?.getReader();
    if (!reader) {
        signal?.throwIfAborted();
        if (declared)
            throw lengthError('RESPONSE_INCOMPLETE', 'Response body is shorter than its Content-Length.');
        return 0;
    }
    const abort = () => { void reader.cancel(signal?.reason).catch(() => { }); };
    signal?.addEventListener('abort', abort, { once: true });
    try {
        signal?.throwIfAborted();
        let bytes = 0, chunks = 0;
        while (true) {
            const { value, done } = await reader.read();
            signal?.throwIfAborted();
            if (done) {
                if (declared !== undefined && bytes !== declared)
                    throw lengthError('RESPONSE_INCOMPLETE', 'Response body is shorter than its Content-Length.');
                return bytes;
            }
            // A stream of strings or other objects has no byteLength, which would silently disable every byte limit.
            if (!(value instanceof Uint8Array))
                throw new TypeError('Response body chunks must be bytes.');
            bytes += value.byteLength;
            if (bytes > maxBytes)
                throw tooLarge();
            if (maxChunks !== undefined && ++chunks > maxChunks)
                throw Object.assign(new RangeError('Response arrived in too many chunks.'), { code: 'RESPONSE_TOO_MANY_CHUNKS' });
            if (declared !== undefined && bytes > declared)
                throw lengthError('RESPONSE_INCOMPLETE', 'Response body is longer than its Content-Length.');
            onChunk(value);
        }
    }
    finally {
        signal?.removeEventListener('abort', abort);
        void reader.cancel().catch(() => { });
        reader.releaseLock();
    }
}
