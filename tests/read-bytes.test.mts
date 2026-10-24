import assert from 'node:assert/strict';
import test from 'node:test';
import { readResponseBytes, readResponseText } from '../index.mjs';

const code = (expected: string) => (error: unknown) => (error as { code?: string }).code === expected;
const chunked = (...parts: number[][]) => new Response(new ReadableStream({ start(controller) { for (const part of parts) controller.enqueue(Uint8Array.from(part)); controller.close(); } }));

test('readResponseBytes returns the exact bytes, including ones that are not valid UTF-8', async () => {
  // An invalid UTF-8 sequence and a BOM survive untouched, which is what HMAC checks and file downloads need.
  const bytes = await readResponseBytes(chunked([0xef, 0xbb, 0xbf, 0x61], [0xc0, 0xaf]), { maxBytes: 6 });
  assert.deepEqual([...bytes], [0xef, 0xbb, 0xbf, 0x61, 0xc0, 0xaf]);
  assert.deepEqual([...await readResponseBytes(new Response(null), { maxBytes: 0 })], []);
  await assert.rejects(readResponseText(chunked([0xc0, 0xaf]), { maxBytes: 2 }), code('RESPONSE_DECODE_INVALID'));
});

test('readResponseBytes applies the same limits and codes as readResponseText', async () => {
  await assert.rejects(readResponseBytes(chunked([1, 2, 3]), { maxBytes: 2 }), code('RESPONSE_TOO_LARGE'));
  await assert.rejects(readResponseBytes(chunked([1], [2], [3]), { maxBytes: 9, maxChunks: 2 }), code('RESPONSE_TOO_MANY_CHUNKS'));
  const untouched = new ReadableStream({ pull() { assert.fail('An over-limit declaration must refuse before reading.'); } });
  await assert.rejects(readResponseBytes(new Response(untouched, { headers: { 'content-length': '99' } }), { maxBytes: 9, contentLength: 'limit' }), code('RESPONSE_TOO_LARGE'));
  await assert.rejects(readResponseBytes(new Response('ab', { headers: { 'content-length': 'x' } }), { maxBytes: 9, contentLength: true }), code('CONTENT_LENGTH_INVALID'));
  await assert.rejects(readResponseBytes(new Response('ab', { headers: { 'content-length': '3' } }), { maxBytes: 9, contentLength: 'exact' }), code('RESPONSE_INCOMPLETE'));
  assert.equal((await readResponseBytes(new Response('ab', { headers: { 'content-length': '3' } }), { maxBytes: 9, contentLength: 'limit' })).byteLength, 2);
  await assert.rejects(readResponseBytes(new Response('ab'), { maxBytes: -1 }), TypeError);
  const controller = new AbortController(); controller.abort(new Error('stop'));
  await assert.rejects(readResponseBytes(new Response('ab'), { maxBytes: 9, signal: controller.signal }), /stop/u);
});

test('a body stream that yields non-byte chunks is refused instead of bypassing the byte limit', async () => {
  const strings = () => new Response(new ReadableStream({ start(controller) { controller.enqueue('x'.repeat(100)); controller.close(); } }));
  await assert.rejects(readResponseBytes(strings(), { maxBytes: 10 }), /chunks must be bytes/u);
  await assert.rejects(readResponseText(strings(), { maxBytes: 10 }), /chunks must be bytes/u);
});

test('readResponseText keeps its error precedence after sharing the read loop', async () => {
  // Invalid UTF-8 in the first chunk is reported before a later chunk crosses the byte limit, as before.
  await assert.rejects(readResponseText(chunked([0xc0, 0xaf], [0x61, 0x61, 0x61]), { maxBytes: 3 }), code('RESPONSE_DECODE_INVALID'));
  await assert.rejects(readResponseText(chunked([0x61, 0x61], [0x61, 0x61]), { maxBytes: 3 }), code('RESPONSE_TOO_LARGE'));
});
