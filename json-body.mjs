// Byte-limited JSON request bodies. Promoted from Discover src/server/validation.ts readJson (v0.7.4), generalised to take
// a body stream and headers so Campaign's Node handlers can pass `Readable.toWeb(req)`. Apps keep schema validation and
// how a coded error becomes their HTTP response.
import { readResponseText } from './browser.mjs';
const refuse = (code, status, message) => Object.assign(new Error(message), { code, status });
/**
 * Reads a JSON request body of at most `maxBytes`. The media type must be `application/json` (parameters allowed), a
 * declared Content-Length must be a plain decimal no larger than `maxBytes`, and the body must be strict UTF-8 JSON.
 * With `allowEmpty`, a request without a body returns `undefined` before the media type is checked: no stream,
 * Content-Length 0, or neither Content-Length nor Transfer-Encoding (RFC 9112 §6.3; Node handlers always pass a
 * stream). Every refusal throws a {@link JsonBodyError} carrying `code` and `status`.
 */
export async function readJsonBody(body, headers, { maxBytes, allowEmpty = false }) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0)
        throw new TypeError('maxBytes must be a positive safe integer.');
    if (!(headers instanceof Headers))
        throw new TypeError('headers must be a Headers object.');
    const length = headers.get('content-length');
    if (allowEmpty && (body === null || length === '0' || (length === null && !headers.has('transfer-encoding')))) {
        void body?.cancel().catch(() => { });
        return undefined;
    }
    const type = headers.get('content-type');
    if (type === null || type.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
        void body?.cancel().catch(() => { });
        throw refuse('BODY_MEDIA_TYPE', 415, 'The request body must be application/json.');
    }
    if (body === null)
        throw refuse('BODY_EMPTY', 400, 'The request body is empty.');
    const declared = new Headers(length === null ? {} : { 'content-length': length });
    let text;
    try {
        text = await readResponseText(new Response(body, { headers: declared }), { maxBytes, contentLength: 'limit' });
    }
    catch (error) {
        const code = error?.code;
        if (code === 'RESPONSE_TOO_LARGE')
            throw refuse('BODY_TOO_LARGE', 413, 'The request body is too large.');
        if (code === 'CONTENT_LENGTH_INVALID')
            throw refuse('BODY_LENGTH_INVALID', 400, 'The request Content-Length is invalid.');
        if (code === 'RESPONSE_DECODE_INVALID')
            throw refuse('BODY_NOT_UTF8', 400, 'The request body is not valid UTF-8.');
        throw refuse('BODY_READ_FAILED', 400, 'The request body could not be read.');
    }
    if (text.trim() === '') {
        if (allowEmpty)
            return undefined;
        throw refuse('BODY_EMPTY', 400, 'The request body is empty.');
    }
    try {
        return JSON.parse(text);
    }
    catch {
        throw refuse('BODY_NOT_JSON', 400, 'The request body is not valid JSON.');
    }
}
