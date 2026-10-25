import assert from 'node:assert/strict';
import test from 'node:test';
import { providerFetchJson } from '../index.mjs';

const hosts = ['api.example.com', 'oauth.example.com'];
type Call = { url: string; init: RequestInit };
const codeOf = (code: string) => (error: unknown) => (error as { code?: string }).code === code;
// Invisible characters are built from code points so a reviewer can see each one.
const [TAB, LF, CR, BACKSLASH, BOM, NUL] = [9, 10, 13, 92, 0xfeff, 0].map(code => String.fromCharCode(code));

function transport(reply: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  return { calls, fetch: async (url: string, init: RequestInit) => { const call = { url, init }; calls.push(call); return reply(call); } };
}
const json = (status: number, value: unknown, headers: Record<string, string> = {}) => new Response(value === undefined ? null : JSON.stringify(value), { status, headers });
const call = (url: string, options: Partial<Parameters<typeof providerFetchJson>[1]> = {}) => providerFetchJson(url, { hosts, timeoutMs: 1000, maxBytes: 100, ...options });

test('providerFetchJson refuses endpoints outside the allowed hosts and paths before sending', async () => {
  const sink = transport(() => json(200, {}));
  const refused = [
    'https://evil.example/x', 'http://api.example.com/x', 'https://api.example.com:8443/x', 'https://user:pass@api.example.com/x',
    'https://api.example.com/x#frag', 'not a url',
    // Dot segments as written, encoded, or decoded once by the provider.
    'https://api.example.com/a/../admin', 'https://api.example.com/a/./admin', 'https://api.example.com/a/%2e%2e/admin', 'https://api.example.com/a/%2E./admin',
    'https://api.example.com/items/..%2Fadmin', 'https://api.example.com/items/..%2F..%2Fadmin%2Fkeys%FF/profile', 'https://api.example.com/items/..%2Fadmin%',
    'https://api.example.com/items/..%5Cadmin%FF',
    // Characters the URL parser drops or trims before it resolves dot segments.
    `https://api.example.com/v1/users/.${TAB}./.${TAB}./admin`, `https://api.example.com/v1/users/.${LF}./profile`,
    `https://api.example.com/v1/users/%2${CR}e%2${CR}e/profile`, `https://api.example.com/v1/items/${NUL}`, 'https://api.example.com/v1/items/.. ', ' https://api.example.com/x',
    // Backslashes, which the parser treats as '/', including straight after the host.
    `https://api.example.com/a${BACKSLASH}b`, 'https://api.example.com/a/%5Cb', `https://api.example.com${BACKSLASH}..${BACKSLASH}admin`,
    `https://api.example.com${BACKSLASH}v1${BACKSLASH}items${BACKSLASH}..${BACKSLASH}admin`,
    // Forms that some servers or proxies resolve as '..'.
    'https://api.example.com/items/..;/admin', 'https://api.example.com/items/%252e%252e/admin',
  ];
  for (const url of refused) await assert.rejects(call(url, { fetch: sink.fetch }), (error: unknown) => error instanceof TypeError && codeOf('PROVIDER_URL_INVALID')(error), JSON.stringify(url));
  // Only strings are checked as written; a URL object is already resolved, so it is refused.
  for (const url of [new URL('https://api.example.com/x'), null, 42]) await assert.rejects(call(url as unknown as string, { fetch: sink.fetch }), codeOf('PROVIDER_URL_INVALID'));
  assert.equal(sink.calls.length, 0);
  // An encoded slash inside one segment is an ordinary ID, and spaces in a query are encoded.
  for (const [url, sent] of [
    ['https://api.example.com/products/gid%3A%2F%2Fshop%2F1?view=full', 'https://api.example.com/products/gid%3A%2F%2Fshop%2F1?view=full'],
    ['https://api.example.com/files/.hidden/v1..2', 'https://api.example.com/files/.hidden/v1..2'],
    ['https://api.example.com/search?q=a b&path=../x', 'https://api.example.com/search?q=a%20b&path=../x'],
  ]) { await call(url!, { fetch: sink.fetch }); assert.equal(sink.calls.at(-1)!.url, sent); }
});

test('providerFetchJson sends to a rebuilt origin without redirects and keeps the caller init', async () => {
  const sink = transport(() => json(201, { id: 1 }));
  const result = await call('HTTPS://API.EXAMPLE.COM/v1/items', {
    fetch: sink.fetch, init: { method: 'POST', headers: { authorization: 'Bearer t' }, body: '{}', redirect: 'follow' } as RequestInit,
  });
  assert.deepEqual([result.ok, result.status, result.class, result.body], [true, 201, 'success', { id: 1 }]);
  const { url, init } = sink.calls[0]!;
  assert.equal(url, 'https://api.example.com/v1/items');
  assert.deepEqual([init.redirect, init.method, init.body], ['error', 'POST', '{}']);
  assert.ok(init.signal instanceof AbortSignal);
  // A Host header or a dispatcher would let init change where the request goes.
  for (const init of [{ headers: { Host: 'evil.example' } }, { headers: [['host', 'evil.example']] }, { dispatcher: {} }]) {
    await assert.rejects(call('https://api.example.com/x', { fetch: sink.fetch, init: init as RequestInit }), TypeError);
  }
  assert.equal(sink.calls.length, 1);
  // A redirect refused by fetch, or any other network failure, is PROVIDER_UNAVAILABLE.
  const refused = transport(() => { throw new TypeError('fetch failed: unexpected redirect'); });
  await assert.rejects(call('https://api.example.com/x', { fetch: refused.fetch }), codeOf('PROVIDER_UNAVAILABLE'));
});

test('providerFetchJson classifies each status and parses readable error bodies', async () => {
  const cases: [number, string, unknown][] = [
    [200, 'success', { a: 1 }], [429, 'rate_limit', { error: 'slow down' }], [500, 'server_error', { error: 'boom' }],
    [503, 'server_error', { error: 'down' }], [400, 'client_error', { code: 'bad' }], [404, 'client_error', { code: 'not_found' }],
    [499, 'client_error', {}], [304, 'other', undefined], [302, 'other', undefined],
  ];
  for (const [status, expected, body] of cases) {
    const result = await call('https://api.example.com/x', { fetch: transport(() => json(status, body, { 'retry-after': '7' })).fetch });
    assert.deepEqual([result.status, result.class, result.ok, result.body, result.headers.get('retry-after')], [status, expected, status === 200, body, '7'], String(status));
  }
  const failed = await call('https://api.example.com/x', { fetch: transport(() => Response.error()).fetch });
  assert.deepEqual([failed.status, failed.class, failed.ok], [0, 'other', false]);
  // Error bodies that are not JSON, or too large, still return the status.
  const html = await call('https://api.example.com/x', { fetch: transport(() => new Response('<html>', { status: 502 })).fetch });
  assert.deepEqual([html.class, html.body], ['server_error', undefined]);
  const huge = await call('https://api.example.com/x', { maxBytes: 10, fetch: transport(() => new Response('x'.repeat(50), { status: 400 })).fetch });
  assert.deepEqual([huge.class, huge.body], ['client_error', undefined]);
  // A zero-length 2xx has no body.
  for (const status of [200, 201, 204]) assert.equal((await call('https://api.example.com/x', { fetch: transport(() => new Response(null, { status })).fetch })).body, undefined);
});

test('providerFetchJson rejects malformed success bodies and reports a dropped connection as unavailable', async () => {
  const reply = (body: BodyInit, headers: Record<string, string> = {}) => call('https://api.example.com/x', { maxBytes: 20, fetch: transport(() => new Response(body, { status: 200, headers })).fetch });
  await assert.rejects(reply(JSON.stringify({ text: 'x'.repeat(40) })), (error: unknown) => codeOf('PROVIDER_RESPONSE_INVALID')(error) && (error as { cause?: { code?: string } }).cause?.code === 'RESPONSE_TOO_LARGE');
  await assert.rejects(reply('{}', { 'content-length': '999' }), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply('not json'), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply('  '), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply(`${BOM}{}`), codeOf('PROVIDER_RESPONSE_INVALID'));
  await assert.rejects(reply(new Uint8Array([0x22, 0xff, 0x22])), codeOf('PROVIDER_RESPONSE_INVALID'));
  // A socket reset mid-body is the connection's failure, not the provider's reply.
  const reset = new ReadableStream({ start(stream) { stream.enqueue(new TextEncoder().encode('{"a"')); stream.error(new TypeError('terminated')); } });
  await assert.rejects(reply(reset), codeOf('PROVIDER_UNAVAILABLE'));
});

test('providerFetchJson times out after timeoutMs, while connecting or reading', { timeout: 2000 }, async () => {
  const hang = transport(({ init }) => new Promise<Response>((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })));
  await assert.rejects(call('https://api.example.com/x', { timeoutMs: 20, fetch: hang.fetch }), codeOf('PROVIDER_TIMEOUT'));
  // The body stream ignores every signal, so only the reader's own deadline can end the call.
  const stall = transport(() => new Response(new ReadableStream({ start(stream) { stream.enqueue(new TextEncoder().encode('{')); } }), { status: 200 }));
  const started = performance.now();
  await assert.rejects(call('https://api.example.com/x', { timeoutMs: 50, fetch: stall.fetch }), codeOf('PROVIDER_TIMEOUT'));
  assert.ok(performance.now() - started < 1000);
});

test('providerFetchJson rethrows a caller abort at once, and sends nothing if it was already aborted', { timeout: 2000 }, async () => {
  const hang = transport(({ init }) => new Promise<Response>((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })));
  const controller = new AbortController();
  const reason = new Error('user cancelled');
  setTimeout(() => controller.abort(reason), 10);
  const started = performance.now();
  await assert.rejects(call('https://api.example.com/x', { timeoutMs: 5000, signal: controller.signal, fetch: hang.fetch }), error => error === reason);
  assert.ok(performance.now() - started < 1000);
  const sink = transport(() => json(200, {}));
  const cancelled = new AbortController();
  cancelled.abort(reason);
  await assert.rejects(call('https://api.example.com/x', { signal: cancelled.signal, init: { method: 'POST', body: '{}' }, fetch: sink.fetch }), error => error === reason);
  assert.equal(sink.calls.length, 0);
});

test('providerFetchJson rejects configuration errors without a code', async () => {
  const sink = transport(() => json(200, {}));
  for (const options of [{ hosts: [] }, { hosts: ['API.example.com'] }, { hosts: ['api.example.com:443'] }, { timeoutMs: 0 }, { timeoutMs: 1.5 }, { maxBytes: -1 }]) {
    await assert.rejects(call('https://api.example.com/x', { fetch: sink.fetch, ...options }), (error: unknown) => error instanceof TypeError && (error as { code?: string }).code === undefined, JSON.stringify(options));
  }
  assert.equal(sink.calls.length, 0);
});
