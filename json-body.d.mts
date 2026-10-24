/** Why a request body was refused, and the HTTP status that fits. */
export type JsonBodyError = Error & {
    code: 'BODY_MEDIA_TYPE' | 'BODY_TOO_LARGE' | 'BODY_LENGTH_INVALID' | 'BODY_EMPTY' | 'BODY_NOT_UTF8' | 'BODY_NOT_JSON' | 'BODY_READ_FAILED';
    status: 400 | 413 | 415;
};
/**
 * Reads a JSON request body of at most `maxBytes`. The media type must be `application/json` (parameters allowed), a
 * declared Content-Length must be a plain decimal no larger than `maxBytes`, and the body must be strict UTF-8 JSON.
 * With `allowEmpty`, a request without a body returns `undefined` before the media type is checked: no stream,
 * Content-Length 0, or neither Content-Length nor Transfer-Encoding (RFC 9112 §6.3; Node handlers always pass a
 * stream). Every refusal throws a {@link JsonBodyError} carrying `code` and `status`.
 */
export declare function readJsonBody(body: ReadableStream<Uint8Array> | null, headers: Headers, { maxBytes, allowEmpty }: {
    maxBytes: number;
    allowEmpty?: boolean;
}): Promise<unknown>;
