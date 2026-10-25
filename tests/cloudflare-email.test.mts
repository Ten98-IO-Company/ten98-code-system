import assert from 'node:assert/strict';
import test from 'node:test';
import { sendCloudflareEmail } from '../index.mjs';

// Every test uses a stubbed transport; nothing reaches Cloudflare.
const accountId = '0123456789abcdef0123456789abcdef';
const token = 'test-token';
const message = { from: 'Ten98 <noreply@example.com>', to: 'Person@Example.com', subject: 'Hello', text: 'Hi', replyTo: 'help@example.com', headers: { 'List-ID': '<p.example.com>' } };
type Call = { url: string; init: RequestInit };
const CR = String.fromCharCode(13);

function transport(reply: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  return { calls, fetch: async (url: string, init: RequestInit) => { const call = { url, init }; calls.push(call); return reply(call); } };
}
const receipt = (result: unknown, status = 200) => () => new Response(JSON.stringify({ success: true, errors: [], result }), { status, headers: { 'content-type': 'application/json' } });
const send = (fetch: (url: string, init: RequestInit) => Promise<Response>, extra: Record<string, unknown> = {}) =>
  sendCloudflareEmail({ accountId, token, message, fetch, ...extra });
const failure = (code: string, uncertain: boolean, retryable = false) => (error: unknown) => {
  const e = error as { code?: string; uncertain?: boolean; retryable?: boolean; message?: string };
  return e.code === code && e.uncertain === uncertain && e.retryable === retryable && !e.message!.includes(token) && !e.message!.toLowerCase().includes('person@');
};

test('sendCloudflareEmail sends one message and reports each receipt status', async () => {
  const shapes: [Record<string, unknown>, string, string | null][] = [
    [{ delivered: ['person@example.com'], queued: [], permanent_bounces: [], suppressed_recipients: [], message_id: '<m1@cf>' }, 'delivered', '<m1@cf>'],
    [{ delivered: [], queued: ['PERSON@example.com'], permanent_bounces: [] }, 'queued', null],
    [{ delivered: [], queued: [], permanent_bounces: ['Person@Example.com'], message_id: 'm3' }, 'failed', 'm3'],
    [{ delivered: [], queued: [], permanent_bounces: [], suppressed_recipients: ['person@example.com'] }, 'suppressed', null],
  ];
  for (const [result, status, messageId] of shapes) {
    const stub = transport(receipt(result));
    assert.deepEqual(await send(stub.fetch), { status, messageId });
    const { url, init } = stub.calls[0]!;
    assert.equal(url, `https://api.cloudflare.com/client/v4/accounts/${accountId}/email/sending/send`);
    assert.deepEqual([init.method, init.redirect, init.credentials], ['POST', 'error', 'omit']);
    assert.equal((init.headers as Record<string, string>).authorization, `Bearer ${token}`);
    assert.deepEqual(JSON.parse(init.body as string), {
      from: { address: 'noreply@example.com', name: 'Ten98' }, to: ['Person@Example.com'], subject: 'Hello', text: 'Hi',
      reply_to: 'help@example.com', headers: { 'List-ID': '<p.example.com>' },
    });
  }
  // A bare sender stays a string, and an uppercase account ID is sent in lowercase.
  const bare = transport(receipt({ delivered: ['person@example.com'], queued: [], permanent_bounces: [] }));
  await sendCloudflareEmail({ accountId: accountId.toUpperCase(), token, message: { from: 'noreply@example.com', to: 'person@example.com', subject: 'Hi', html: '<p>Hi</p>' }, fetch: bare.fetch });
  assert.equal(bare.calls[0]!.url, `https://api.cloudflare.com/client/v4/accounts/${accountId}/email/sending/send`);
  assert.deepEqual(JSON.parse(bare.calls[0]!.init.body as string), { from: 'noreply@example.com', to: ['person@example.com'], subject: 'Hi', html: '<p>Hi</p>' });
});

test('sendCloudflareEmail treats a receipt that does not report exactly this recipient as uncertain', async () => {
  for (const result of [
    { delivered: ['other@example.com'], queued: [], permanent_bounces: [] },
    { delivered: ['person@example.com', 'other@example.com'], queued: [], permanent_bounces: [] },
    { delivered: ['person@example.com', 'Person@Example.com'], queued: [], permanent_bounces: [] },
    { delivered: ['person@example.com'], queued: ['person@example.com'], permanent_bounces: [] },
    { delivered: [], queued: [], permanent_bounces: [] },
    { delivered: ['person@example.com'], queued: [] },
    { delivered: 'person@example.com', queued: [], permanent_bounces: [] },
    { delivered: [42], queued: [], permanent_bounces: [] },
    { delivered: ['person@example.com'], queued: [], permanent_bounces: [], suppressed_recipients: 'person@example.com' },
    { delivered: ['person@example.com'], queued: [], permanent_bounces: [], message_id: 'has space' },
    { delivered: ['person@example.com'], queued: [], permanent_bounces: [], message_id: 7 },
  ]) await assert.rejects(send(transport(receipt(result)).fetch), failure('INVALID_RESPONSE', true), JSON.stringify(result));
  for (const reply of [
    () => new Response(JSON.stringify({ success: false, errors: [], result: { delivered: ['person@example.com'], queued: [], permanent_bounces: [] } })),
    () => new Response(JSON.stringify({ success: true })), () => new Response('<html>'), () => new Response('x'.repeat(70_000)),
  ]) await assert.rejects(send(transport(reply).fetch), failure('INVALID_RESPONSE', true));
});

test('sendCloudflareEmail reports network, timeout, abort and 5xx failures as uncertain', { timeout: 5000 }, async () => {
  await assert.rejects(send(transport(() => { throw new TypeError('fetch failed'); }).fetch), failure('NETWORK_ERROR', true));
  for (const status of [500, 502, 503]) {
    await assert.rejects(send(transport(() => new Response(JSON.stringify({ success: false, errors: [{ code: 10000 }] }), { status })).fetch), (error: unknown) =>
      failure(`HTTP_${status}`, true)(error) && (error as { status?: number; providerCode?: number }).status === status && (error as { providerCode?: number }).providerCode === 10000);
  }
  const hang = transport(({ init }) => new Promise<Response>((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })));
  await assert.rejects(send(hang.fetch, { timeoutMs: 20 }), failure('TIMEOUT', true));
  const controller = new AbortController();
  setTimeout(() => controller.abort(new Error('stop')), 10);
  await assert.rejects(send(hang.fetch, { signal: controller.signal }), failure('ABORTED', true));
  // Aborted before sending: certain that nothing was sent.
  const unsent = transport(receipt({}));
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(send(unsent.fetch, { signal: aborted.signal }), failure('ABORTED', false));
  assert.equal(unsent.calls.length, 0);
});

test('sendCloudflareEmail reports throttling as retryable and other statuses as definite rejections', async () => {
  await assert.rejects(send(transport(() => new Response('{}', { status: 429 })).fetch), failure('HTTP_429', false, true));
  for (const status of [400, 401, 403, 422]) {
    await assert.rejects(send(transport(() => new Response(JSON.stringify({ success: false, errors: [{ code: 10001, message: 'bad person@example.com' }] }), { status })).fetch), (error: unknown) =>
      failure(`HTTP_${status}`, false)(error) && (error as { providerCode?: number }).providerCode === 10001);
  }
  // A non-numeric provider code is left out.
  await assert.rejects(send(transport(() => new Response(JSON.stringify({ errors: [{ code: 'x' }] }), { status: 400 })).fetch), (error: unknown) => !('providerCode' in (error as object)));
  // A passed-through 3xx is not a confirmed rejection.
  await assert.rejects(send(transport(() => new Response(null, { status: 304 })).fetch), failure('HTTP_304', true));
});

test('sendCloudflareEmail refuses invalid input before sending', async () => {
  const unsent = transport(receipt({}));
  for (const input of [
    { accountId: 'not-an-id' }, { accountId: `${accountId}0` }, { token: '' }, { token: 'has space' }, { fetch: 'nope' },
    { message: { ...message, to: 'a@b.com, c@d.com' } }, { message: { ...message, to: 'nobody' } }, { message: { ...message, from: 'Bad, Name <a@b.com>' } },
    { message: { ...message, subject: `Hi${CR}Bcc: x@y.com` } }, { message: { ...message, text: '', html: undefined } },
    { message: { ...message, headers: { Bcc: 'x@y.com' } } }, { message: { ...message, headers: { 'X-A': `a${CR}b` } } }, { message: { ...message, replyTo: 'nope' } },
  ]) {
    await assert.rejects(sendCloudflareEmail({ accountId, token, message, fetch: unsent.fetch, ...input } as Parameters<typeof sendCloudflareEmail>[0]),
      (error: unknown) => error instanceof TypeError && (error as { code?: string }).code === 'INVALID_INPUT', JSON.stringify(input));
  }
  assert.equal(unsent.calls.length, 0);
});
