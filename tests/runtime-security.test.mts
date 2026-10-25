import assert from 'node:assert/strict';
import test from 'node:test';
import { openRouterFetch } from '../index.mjs';

// A pasted key with an embedded line break or control character must fail without echoing the credential,
// because callers log errors and some surface their messages.
test('OpenRouter refuses unsafe API key header values before transport and never echoes the credential', async () => {
  const secret = 'sk-or-v1-0123456789abcdef';
  for (const apiKey of [`${secret}\nNEXT_SETTING=value`, `${secret}\r\nX-Injected: 1`, `${secret}\u0000`]) {
    let sent = 0;
    // Request construction applies the same header validation as fetch without touching the network.
    const send: typeof fetch = async (url, init) => { sent++; return new Response(new Request(url, init).url); };
    const error = await (async () => { await openRouterFetch('/key', { apiKey }, send); })().then(() => undefined, failure => failure);
    assert.ok(error instanceof TypeError, 'unsafe header values are rejected');
    assert.equal(String(error.message).includes(secret), false, `error message leaks the credential: ${JSON.stringify(error.message)}`);
    assert.equal(sent, 0, 'unsafe header values never reach the transport');
  }
});
