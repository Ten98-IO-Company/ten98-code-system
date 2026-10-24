import assert from 'node:assert/strict';
import test from 'node:test';
import { providerFetchJson } from '../index.mjs';

const hosts = ['api.example.com', 'oauth.example.com'];
type Call = { url: string; init: RequestInit };
const codeOf = (code: string) => (error: unknown) => (error as { code?: string }).code === code;

function transport(reply: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  return { calls, fetch: async (url: string, init: RequestInit) => { const call = { url, init }; calls.push(call); return reply(call); } };
}
const json = (status: number, value: unknown, headers: Record<string, string> = {}) => new Response(value === undefined ? null : JSON.stringify(value), { status, headers });

test('providerFetchJson refuses foreign hosts, ports, credentials, fragments, backslashes and dot segments before sending', async () => {
  const sink = transport(() => json(200, {}));
  for (const url of [
    'https://evil.example/x', 'http://api.example.com/x', 'https://api.example.com:8443/x', 'https://user:pass@api.example.com/x',
    'https://api.example.com/x#frag', 'https://api.example.com/a/../admin', 'https://api.example.com/a/%2e%2e/admin',
    'https://api.example.com/items/..%2Fadmin', 'https://api.example.com/a\\b', 'https://api.example.com/a/%5Cb', 'not a url',
  ]) await assert.rejects(providerFetchJson(url, { hosts, timeoutMs: 1000, maxBytes: 100, fetch: sink.fetch }), (error: unknown) => error instanceof TypeError && codeOf('PROVIDER_URL_INVALID')(error), url);
  assert.equal(sink.calls.length, 0);
  // An encoded slash inside one segment is an ordinary ID and stays encoded.
  await providerFetchJson('https://api.example.com/products/gid%3A%2F%2Fshop%2F1?view=full', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: sink.fetch });
  assert.equal(sink.calls[0]!.url, 'https://api.example.com/products/gid%3A%2F%2Fshop%2F1?view=full');
});

test('providerFetchJson sends to a rebuilt origin without redirects and keeps the caller init', async () => {
  const sink = transport(() => json(200, { id: 1 }));
  const result = await providerFetchJson(new URL('https://API.example.com/v1/items?q=a b'), {
    hosts, timeoutMs: 1000, maxBytes: 100, fetch: sink.fetch,
    init: { method: 'POST', headers: { authorization: 'Bearer t' }, body: '{}', redirect: 'follow' } as RequestInit,
  });
  assert.deepEqual(result.body, { id: 1 });
  assert.equal(result.ok, true);
  assert.equal(result.class, 'success');
  const { url, init } = sink.calls[0]!;
  assert.equal(url, 'https://api.example.com/v1/items?q=a%20b');
  assert.equal(init.redirect, 'error');
  assert.equal(init.method, 'POST');
  assert.ok(init.signal instanceof AbortSignal);
  // A string is sent as the rebuilt URL, not as written.
  await providerFetchJson('HTTPS://API.EXAMPLE.COM/v1/items?q=a b', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: sink.fetch });
  assert.equal(sink.calls[1]!.url, 'https://api.example.com/v1/items?q=a%20b');
  // A redirect, refused by fetch itself, or any network failure is PROVIDER_UNAVAILABLE.
  const refused = transport(() => { throw new TypeError('fetch failed: unexpected redirect'); });
  await assert.rejects(providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: refused.fetch }), codeOf('PROVIDER_UNAVAILABLE'));
});

test('providerFetchJson classifies each status and parses readable error bodies', async () => {
  const cases: [number, string, unknown][] = [[200, 'success', { a: 1 }], [429, 'rate_limit', { error: 'slow down' }], [503, 'server_error', { error: 'down' }], [404, 'client_error', { code: 'not_found' }]];
  for (const [status, expected, body] of cases) {
    const result = await providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: transport(() => json(status, body, { 'retry-after': '7' })).fetch });
    assert.deepEqual([result.status, result.class, result.ok, result.body, result.headers.get('retry-after')], [status, expected, status === 200, body, '7']);
  }
  // Error bodies that are not JSON, or too large, still return the status.
  const html = await providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: transport(() => new Response('<html>', { status: 502 })).fetch });
  assert.deepEqual([html.class, html.body], ['server_error', undefined]);
  const huge = await providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 10, fetch: transport(() => new Response('x'.repeat(50), { status: 400 })).fetch });
  assert.deepEqual([huge.class, huge.body], ['client_error', undefined]);
  // 204 and an empty 200 have no body.
  for (const status of [200, 204]) assert.equal((await providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 10, fetch: transport(() => new Response(null, { status })).fetch })).body, undefined);
});

test('providerFetchJson rejects oversized, non-JSON and BOM-prefixed success bodies', async () => {
  const reply = (body: string, headers: Record<string, string> = {}) => providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 20, fetch: transport(() => new Response(body, { status: 200, headers })).fetch });
  await assert.rejects(reply(JSON.stringify({ text: 'x'.repeat(40) })), (error: unknown) => codeOf('PROVIDER_RESPONSE_INVALID')(error) && (error as { cause?: { code?: string } }).cause?.code === 'RESPONSE_TOO_LARGE');
  await assert.rejects(reply('{}', { 'content-length': '999' }), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply('not json'), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply('﻿{}'), codeOf('PROVIDER_RESPONSE_INVALID'));
});

test('providerFetchJson times out after timeoutMs and rethrows a caller abort', async () => {
  const hang = transport(({ init }) => new Promise<Response>((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })));
  await assert.rejects(providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 20, maxBytes: 100, fetch: hang.fetch }), codeOf('PROVIDER_TIMEOUT'));
  const controller = new AbortController();
  const reason = new Error('user cancelled');
  setTimeout(() => controller.abort(reason), 10);
  await assert.rejects(providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 5000, maxBytes: 100, signal: controller.signal, fetch: hang.fetch }), error => error === reason);
  // A body that stalls past the deadline also times out.
  const stall = transport(({ init }) => new Response(new ReadableStream({ start(stream) { stream.enqueue(new TextEncoder().encode('{')); init.signal!.addEventListener('abort', () => stream.error(init.signal!.reason), { once: true }); } }), { status: 200 }));
  await assert.rejects(providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 20, maxBytes: 100, fetch: stall.fetch }), codeOf('PROVIDER_TIMEOUT'));
});

test('providerFetchJson rejects configuration errors', async () => {
  const sink = transport(() => json(200, {}));
  for (const options of [{ hosts: [] }, { hosts: ['API.example.com'] }, { hosts: ['api.example.com:443'] }, { timeoutMs: 0 }, { timeoutMs: 1.5 }, { maxBytes: -1 }]) {
    await assert.rejects(providerFetchJson('https://api.example.com/x', { hosts, timeoutMs: 1000, maxBytes: 100, fetch: sink.fetch, ...options }), TypeError, JSON.stringify(options));
  }
  assert.equal(sink.calls.length, 0);
});
