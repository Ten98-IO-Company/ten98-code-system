import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import test from 'node:test';
import { readJsonBody } from '../index.mjs';

const json = { 'content-type': 'application/json' };
const stream = (text: string | Uint8Array<ArrayBuffer>) => new Response(text).body;
const refused = (code: string, status: number) => (error: unknown) => (error as { code?: string; status?: number }).code === code && (error as { status?: number }).status === status;

test('a JSON body within the limit is parsed', async () => {
  assert.deepEqual(await readJsonBody(stream('{"a":1}'), new Headers(json), { maxBytes: 64 }), { a: 1 });
  assert.deepEqual(await readJsonBody(stream('[1]'), new Headers({ 'content-type': 'Application/JSON; charset=utf-8', 'content-length': '3' }), { maxBytes: 3 }), [1]);
  // A Node request stream works through Readable.toWeb.
  const node = Readable.toWeb(Readable.from([Buffer.from('{"b":'), Buffer.from('2}')])) as ReadableStream<Uint8Array>;
  assert.deepEqual(await readJsonBody(node, new Headers(json), { maxBytes: 64 }), { b: 2 });
});

test('media type, size, length, encoding and JSON refusals carry a code and status', async () => {
  await assert.rejects(readJsonBody(stream('{}'), new Headers({ 'content-type': 'text/plain' }), { maxBytes: 64 }), refused('BODY_MEDIA_TYPE', 415));
  await assert.rejects(readJsonBody(stream('{}'), new Headers({ 'content-type': 'application/jsonx' }), { maxBytes: 64 }), refused('BODY_MEDIA_TYPE', 415));
  await assert.rejects(readJsonBody(stream('{}'), new Headers(), { maxBytes: 64 }), refused('BODY_MEDIA_TYPE', 415));
  await assert.rejects(readJsonBody(stream('{"a":1}'), new Headers(json), { maxBytes: 4 }), refused('BODY_TOO_LARGE', 413));
  const untouched = new ReadableStream<Uint8Array>({ pull() { assert.fail('An over-limit declaration must refuse before reading.'); } });
  await assert.rejects(readJsonBody(untouched, new Headers({ ...json, 'content-length': '999' }), { maxBytes: 64 }), refused('BODY_TOO_LARGE', 413));
  await assert.rejects(readJsonBody(stream('{}'), new Headers({ ...json, 'content-length': 'abc' }), { maxBytes: 64 }), refused('BODY_LENGTH_INVALID', 400));
  await assert.rejects(readJsonBody(stream(Uint8Array.of(0x7b, 0xc0, 0xaf, 0x7d)), new Headers(json), { maxBytes: 64 }), refused('BODY_NOT_UTF8', 400));
  await assert.rejects(readJsonBody(stream('{nope'), new Headers(json), { maxBytes: 64 }), refused('BODY_NOT_JSON', 400));
  await assert.rejects(readJsonBody(stream('  '), new Headers(json), { maxBytes: 64 }), refused('BODY_EMPTY', 400));
  await assert.rejects(readJsonBody(null, new Headers(json), { maxBytes: 64 }), refused('BODY_EMPTY', 400));
  const broken = new ReadableStream<Uint8Array>({ start(controller) { controller.error(new Error('connection reset')); } });
  await assert.rejects(readJsonBody(broken, new Headers(json), { maxBytes: 64 }), refused('BODY_READ_FAILED', 400));
});

test('allowEmpty returns undefined for a request without a body, before the media type is checked', async () => {
  assert.equal(await readJsonBody(null, new Headers(), { maxBytes: 64, allowEmpty: true }), undefined);
  assert.equal(await readJsonBody(stream(''), new Headers({ 'content-length': '0' }), { maxBytes: 64, allowEmpty: true }), undefined);
  // RFC 9112: neither Content-Length nor Transfer-Encoding means no body, even when a Node handler passes a stream.
  assert.equal(await readJsonBody(stream(''), new Headers(), { maxBytes: 64, allowEmpty: true }), undefined);
  assert.equal(await readJsonBody(stream(' '), new Headers({ ...json, 'content-length': '1' }), { maxBytes: 64, allowEmpty: true }), undefined);
  // A body that is present still needs the JSON media type.
  await assert.rejects(readJsonBody(stream('{}'), new Headers({ 'transfer-encoding': 'chunked' }), { maxBytes: 64, allowEmpty: true }), refused('BODY_MEDIA_TYPE', 415));
  await assert.rejects(readJsonBody(stream('{}'), new Headers({ 'content-length': '2' }), { maxBytes: 64, allowEmpty: true }), refused('BODY_MEDIA_TYPE', 415));
  // Without allowEmpty a body-less request is still refused.
  await assert.rejects(readJsonBody(stream(''), new Headers(json), { maxBytes: 64 }), refused('BODY_EMPTY', 400));
});

test('configuration errors throw a TypeError', async () => {
  await assert.rejects(readJsonBody(null, new Headers(json), { maxBytes: 0 }), TypeError);
  await assert.rejects(readJsonBody(null, { 'content-type': 'application/json' } as unknown as Headers, { maxBytes: 8 }), TypeError);
});
