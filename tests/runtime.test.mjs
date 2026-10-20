import assert from 'node:assert/strict';
import test from 'node:test';
import { readResponseText, openRouterFetch, oidcEndpoint, workspaceRoles, mayGrantWorkspaceRole, mayManageWorkspaceMember } from '../index.mjs';

test('workspace grants fail closed across every actor/target pair', () => {
  const allowed = { owner: ['owner', 'admin', 'editor', 'viewer'], admin: ['editor', 'viewer'], editor: [], viewer: [] };
  assert.deepEqual(workspaceRoles, ['owner', 'admin', 'editor', 'viewer']);
  assert.equal(Object.isFrozen(workspaceRoles), true);
  for (const actor of [...workspaceRoles, undefined, 'operator', 'constructor']) for (const target of [...workspaceRoles, undefined, 'operator', 'constructor']) {
    assert.equal(mayGrantWorkspaceRole(actor, target), Object.hasOwn(allowed, actor) && allowed[actor].includes(target), `${actor} -> ${target}`);
  }
});

test('member changes require authority over both saved and requested roles, and unknown roles fail closed', () => {
  assert.equal(mayManageWorkspaceMember('admin', 'owner', 'viewer'), false);
  assert.equal(mayManageWorkspaceMember('admin', 'editor', 'owner'), false);
  assert.equal(mayManageWorkspaceMember('admin', 'editor', 'viewer'), true);
  assert.equal(mayManageWorkspaceMember('admin', 'viewer'), true);
  assert.equal(mayManageWorkspaceMember('owner', 'owner', 'admin'), true);
  for (const unknown of [undefined, null, 'operator', 'constructor', {}, 0]) {
    assert.equal(mayManageWorkspaceMember(unknown, 'viewer', 'editor'), false);
    assert.equal(mayManageWorkspaceMember('owner', unknown, 'editor'), false);
    if (unknown !== undefined) assert.equal(mayManageWorkspaceMember('owner', 'viewer', unknown), false);
  }
});

test('bounded response reading counts bytes and decodes split UTF-8 strictly', async () => {
  const response = new Response(new ReadableStream({ start(controller) {
    controller.enqueue(Uint8Array.of(0x61, 0xf0, 0x9f));
    controller.enqueue(Uint8Array.of(0x98, 0x80)); controller.close();
  } }));
  assert.equal(await readResponseText(response, { maxBytes: 5 }), 'a😀');
  assert.equal(response.body.locked, false);
  await assert.rejects(readResponseText(new Response('😀'), { maxBytes: 3 }), RangeError);
  await assert.rejects(readResponseText(new Response(Uint8Array.of(0xc0, 0xaf)), { maxBytes: 2 }), TypeError);
  await assert.rejects(readResponseText(new Response(Uint8Array.of(0xe2)), { maxBytes: 1 }), TypeError);
  await assert.rejects(readResponseText(new Response(''), { maxBytes: -1 }), TypeError);
  assert.equal(await readResponseText(new Response(null), { maxBytes: 0 }), '');
  assert.equal(await readResponseText(new Response('ok', { headers: { 'content-length': '9999999' } }), { maxBytes: 2 }), 'ok');
});

test('BOM preservation is explicit, including split BOM bytes and exact-empty JSON semantics', async () => {
  for (const suffix of ['', '{}']) for (const preserveBOM of [false, true]) {
    const response = new Response(new ReadableStream({ start(controller) {
      controller.enqueue(Uint8Array.of(0xef)); controller.enqueue(Uint8Array.of(0xbb, 0xbf));
      controller.enqueue(new TextEncoder().encode(suffix)); controller.close();
    } }));
    const text = await readResponseText(response, { maxBytes: 5, preserveBOM });
    assert.equal(text, (preserveBOM ? '\ufeff' : '') + suffix);
    if (preserveBOM) assert.throws(() => JSON.parse(text), SyntaxError);
    assert.equal(response.body.locked, false);
  }
});

test('response failures and pending-read abort cancel the stream and release its lock', async () => {
  for (const value of [Uint8Array.of(1, 2), Uint8Array.of(0xff)]) {
    let cancelled = 0;
    const response = new Response(new ReadableStream({ start(c) { c.enqueue(value); }, cancel() { cancelled++; } }));
    await assert.rejects(readResponseText(response, { maxBytes: 1 }));
    assert.equal(cancelled, 1); assert.equal(response.body.locked, false);
  }
  for (const before of [false, true]) {
    let cancelled = 0;
    const response = new Response(new ReadableStream({ cancel() { cancelled++; } }));
    const controller = new AbortController(), reason = new Error('stop');
    if (before) controller.abort(reason);
    const pending = readResponseText(response, { maxBytes: 10, signal: controller.signal });
    if (!before) controller.abort(reason);
    await assert.rejects(pending, error => error === reason);
    assert.equal(cancelled, 1); assert.equal(response.body.locked, false);
  }
  const failed = new Response(new ReadableStream({ start(c) { c.error(new Error('stream failed')); } }));
  await assert.rejects(readResponseText(failed, { maxBytes: 10 }), /stream failed/);
  assert.equal(failed.body.locked, false);
});

test('uncooperative stream cancellation cannot hold byte-limit or pre-abort failures open', async () => {
  for (const aborted of [false, true]) {
    let timer, cancelled = 0;
    const response = new Response(new ReadableStream({
      start(controller) { controller.enqueue(Uint8Array.of(1, 2)); },
      cancel() { cancelled++; return new Promise(() => {}); },
    }));
    const controller = new AbortController(); if (aborted) controller.abort();
    try {
      const result = await Promise.race([
        readResponseText(response, { maxBytes: 1, signal: controller.signal }).then(() => 'accepted', error => error),
        new Promise(resolve => { timer = setTimeout(() => resolve('stalled cancellation'), 200); }),
      ]);
      assert.ok(result instanceof Error, String(result));
      assert.equal(cancelled, 1); assert.equal(response.body.locked, false);
    } finally { clearTimeout(timer); }
  }
});

test('OpenRouter fixes destination, JSON transport and finite deadlines without retries', async () => {
  const calls = [], result = new Response('{}');
  const send = async (...args) => { calls.push(args); return result; };
  const signal = new AbortController().signal;
  assert.equal(await openRouterFetch('/chat/completions', { apiKey: 'test', title: 'ten98 Test', body: { messages: [] }, signal, metadata: true }, send), result);
  const [url, options] = calls[0];
  assert.equal(url, 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(options.method, 'POST'); assert.deepEqual(JSON.parse(options.body), { messages: [] });
  assert.deepEqual(options.headers, { accept: 'application/json', Authorization: 'Bearer test', 'x-openrouter-title': 'ten98 Test', 'x-openrouter-metadata': 'enabled', 'content-type': 'application/json' });
  assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit'); assert.equal(options.signal, signal);
  const deadlines = [], original = AbortSignal.timeout;
  try {
    AbortSignal.timeout = milliseconds => { deadlines.push(milliseconds); return signal; };
    for (const path of ['/key', '/generation?id=test', '/models?category=text', '/models/meta%2Fmodel']) await openRouterFetch(path, {}, send);
    await openRouterFetch('/chat/completions', { body: null }, send);
  } finally { AbortSignal.timeout = original; }
  assert.deepEqual(deadlines, [10_000, 10_000, 10_000, 10_000, 60_000]);
  assert.equal(calls[1][1].method ?? 'GET', 'GET'); assert.equal(Object.hasOwn(calls[1][1], 'body'), false);
  assert.deepEqual(calls[1][1].headers, { accept: 'application/json' });
  let attempts = 0;
  await assert.rejects(openRouterFetch('/key', {}, async () => { attempts++; throw new Error('network'); }), /network/);
  assert.equal(attempts, 1);
});

test('OpenRouter rejects absolute and traversing paths before sending credentials', () => {
  const send = () => { assert.fail('invalid path reached fetch'); };
  for (const path of ['key', 'https://example.com/key', '//example.com', '/../key', '/a/../key', '/%2e%2e/key', '/a%2f..%2fkey', '/a\\key', '/key#', '/key#fragment', '/key\n', '/bad%']) {
    assert.throws(() => openRouterFetch(path, { apiKey: 'test' }, send), undefined, path);
  }
});

test('OIDC URLs reject insecure or ambiguous endpoints and issuer queries', () => {
  assert.equal(oidcEndpoint('https://identity.example/application/o/test/').href, 'https://identity.example/application/o/test/');
  assert.equal(oidcEndpoint('https://identity.example/token?tenant=1').search, '?tenant=1');
  assert.equal(oidcEndpoint('http://localhost:9999', { allowHttp: true, issuer: true }).origin, 'http://localhost:9999');
  for (const raw of ['http://identity.example', 'ftp://identity.example', 'https://user:password@identity.example', 'https://identity.example/#', 'https://identity.example/#fragment', '/relative']) assert.throws(() => oidcEndpoint(raw), TypeError);
  for (const raw of ['https://identity.example/?', 'https://identity.example/?tenant=1']) assert.throws(() => oidcEndpoint(raw, { issuer: true }), TypeError);
});
