import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspect } from 'node:util';
import { EmailDeliveryError, getEmailStatus, sendTransactionalEmail, withEmailTransportsForTests, type SmtpSender, type SmtpTransportOptions } from '../email.mjs';
import { sesOrigin } from '../index.mjs';

// Synthetic settings only; every transport below is an injected adapter, so no request leaves the process.
const smtp = { EMAIL_TRANSPORT: 'smtp', EMAIL_FROM: 'sender@example.com', EMAIL_SMTP_HOST: 'smtp.example.com', EMAIL_SMTP_USER: 'login', EMAIL_SMTP_PASSWORD: 'short-password' };
const cloudflare = { EMAIL_TRANSPORT: 'cloudflare', EMAIL_FROM: 'sender@example.com', EMAIL_CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32), EMAIL_CLOUDFLARE_API_TOKEN: 'test-token' };
const ses = { EMAIL_TRANSPORT: 'ses', EMAIL_FROM: 'sender@example.com', EMAIL_SES_REGION: 'eu-west-1', EMAIL_SES_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE', EMAIL_SES_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };
const message = { to: 'recipient@example.com', subject: 'Reset your password', text: 'Use this link once:\nhttps://app.example.com/reset?token=private-token' };
const unconfirmed = { name: 'EmailDeliveryError', message: 'Email acceptance could not be confirmed. No automatic retry was made.', status: 503 };
const accepted = { accepted: true, delivery: 'unconfirmed' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const receipt = (delivered: string[] = [], queued = [message.to], permanent_bounces: string[] = [], suppressed_recipients: string[] = []) => ({ success: true, errors: [], messages: [], result: { delivered, queued, permanent_bounces, suppressed_recipients } });
const sesReply = () => json({ MessageId: 'synthetic-message-id' });
const smtpSender = (reply: unknown = { accepted: [message.to], rejected: [] }, onClose = () => {}): SmtpSender => ({ async sendMail() { return reply; }, close: onClose });

// Each transport with an adapter that accepts, and counts the provider calls it receives.
function transports() {
  const calls = { fetch: 0, smtp: 0 };
  const adapters = {
    fetch: async (url: string) => { calls.fetch++; return url.startsWith('https://api.cloudflare.com/') ? json(receipt()) : sesReply(); },
    smtp: () => { calls.smtp++; return smtpSender(); },
  };
  return { calls, adapters };
}
const everyTransport = [['smtp', smtp], ['cloudflare', cloudflare], ['ses', ses]] as const;

const directory = mkdtempSync(join(tmpdir(), 'ten98-email-'));
test.after(() => rmSync(directory, { recursive: true, force: true }));
const file = (name: string, contents: string) => { const path = join(directory, name); writeFileSync(path, contents); return path; };

test('getEmailStatus is disabled by default, reports each configured transport and is configuration only', () => {
  assert.deepEqual(getEmailStatus({}), { configured: false, transport: 'disabled' });
  assert.deepEqual(getEmailStatus({ EMAIL_TRANSPORT: '' }), { configured: false, transport: 'disabled' });
  assert.deepEqual(getEmailStatus({ EMAIL_TRANSPORT: 'disabled' }), { configured: false, transport: 'disabled' });
  for (const [transport, env] of everyTransport) assert.deepEqual(getEmailStatus(env), { configured: true, transport });
  assert.deepEqual(getEmailStatus({ ...ses, EMAIL_SES_CONFIGURATION_SET: 'transactional-1' }), { configured: true, transport: 'ses' });
});

test('getEmailStatus never throws: malformed, missing or unreadable configuration is reported as not configured', () => {
  const refused = [
    { EMAIL_TRANSPORT: 'other' }, { ...smtp, EMAIL_SMTP_TLS: 'plaintext' }, { ...smtp, EMAIL_SMTP_HOST: 'https://smtp.example.com' },
    { ...smtp, EMAIL_SMTP_PORT: '0' }, { ...smtp, EMAIL_SMTP_PORT: '70000' }, { ...smtp, EMAIL_SMTP_USER: '' }, { ...smtp, EMAIL_SMTP_PASSWORD: '' },
    { ...smtp, EMAIL_SMTP_PASSWORD: 'line\nbreak' }, { ...smtp, EMAIL_FROM: 'Name <sender@example.com>' }, { ...smtp, EMAIL_FROM: undefined },
    { ...cloudflare, EMAIL_CLOUDFLARE_ACCOUNT_ID: 'wrong' }, { ...cloudflare, EMAIL_CLOUDFLARE_API_TOKEN: 'has space' },
    { ...ses, EMAIL_SES_REGION: 'eu-west-9' }, { ...ses, EMAIL_SES_REGION: 'email.eu-west-1.amazonaws.com' }, { ...ses, EMAIL_SES_REGION: '' },
    { ...ses, EMAIL_SES_ACCESS_KEY_ID: 'not a key' }, { ...ses, EMAIL_SES_SECRET_ACCESS_KEY: 'short' }, { ...ses, EMAIL_SES_CONFIGURATION_SET: 'bad set' },
    { ...smtp, EMAIL_SMTP_PASSWORD: '', EMAIL_SMTP_PASSWORD_FILE: join(directory, 'absent') },
  ];
  for (const env of refused) assert.deepEqual(getEmailStatus(env), { configured: false, transport: 'disabled' }, JSON.stringify(env));
  const hostile = new Proxy({}, { get() { throw new Error('environment unavailable'); } });
  assert.deepEqual(getEmailStatus(hostile), { configured: false, transport: 'disabled' });
});

test('the SMTP host must be a name: IPv4, IPv6 and bracketed literals are refused', () => {
  for (const host of ['127.0.0.1', '10.0.0.1', '::1', '[::1]', '2001:db8::1', 'smtp.example.com:25', '-smtp.example.com', 'smtp_example.com']) {
    assert.equal(getEmailStatus({ ...smtp, EMAIL_SMTP_HOST: host }).configured, false, host);
  }
  assert.equal(getEmailStatus({ ...smtp, EMAIL_SMTP_HOST: 'mail' }).configured, true);
});

test('FROM, HOST, USER and PASSWORD accept _FILE through readEnvironment, which refuses both set', async () => {
  const values = { EMAIL_FROM: 'file-sender@example.com', EMAIL_SMTP_HOST: 'file-smtp.example.com', EMAIL_SMTP_USER: 'file-login', EMAIL_SMTP_PASSWORD: 'file-password' };
  const env: Record<string, string> = { EMAIL_TRANSPORT: 'smtp' };
  for (const [name, value] of Object.entries(values)) env[`${name}_FILE`] = file(name.toLowerCase(), `  ${value}\n`);
  assert.deepEqual(getEmailStatus(env), { configured: true, transport: 'smtp' });
  let seen: SmtpTransportOptions | undefined, from = '';
  const result = await withEmailTransportsForTests({ smtp(options) { seen = options; return { async sendMail(mail) { from = mail.from; return { accepted: [message.to], rejected: [] }; }, close() {} }; } },
    () => sendTransactionalEmail(message, { env }));
  assert.deepEqual(result, accepted);
  assert.equal(from, values.EMAIL_FROM);
  assert.equal(seen?.host, values.EMAIL_SMTP_HOST);
  assert.deepEqual(seen?.auth, { user: values.EMAIL_SMTP_USER, pass: values.EMAIL_SMTP_PASSWORD });
  for (const name of Object.keys(values)) assert.equal(getEmailStatus({ ...env, [name]: 'also-set' }).configured, false, `${name} and ${name}_FILE`);
});

test('every send failure is one EmailDeliveryError with status 503, disabled and bad configuration included', async () => {
  const error = new EmailDeliveryError();
  assert.ok(error instanceof Error); assert.equal(error.status, 503); assert.equal(error.cause, undefined);
  await assert.rejects(sendTransactionalEmail(message, { env: {} }), unconfirmed);
  await assert.rejects(sendTransactionalEmail(message, { env: { EMAIL_TRANSPORT: 'smtp' } }), unconfirmed);
  await assert.rejects(sendTransactionalEmail(message, { env: { ...smtp, EMAIL_SMTP_HOST: '127.0.0.1' } }), unconfirmed);
  await assert.rejects(sendTransactionalEmail(message, { env: { ...smtp, EMAIL_SMTP_PASSWORD_FILE: file('both', 'x') } }), unconfirmed);
  // An adapter that throws anything, a non-Error included, still surfaces as the same error.
  await assert.rejects(withEmailTransportsForTests({ smtp() { throw 'raw string'; } }, () => sendTransactionalEmail(message, { env: smtp })), unconfirmed);
});

test('input is strict: one bare mailbox, a subject of at most 200 characters without control characters, text of at most 65,536 bytes', async () => {
  const { calls, adapters } = transports();
  await withEmailTransportsForTests(adapters, async () => {
    for (const to of ['recipient@example.com,other@example.com', 'Name <recipient@example.com>', 'recipient@example.com\r\nBcc:other@example.com', ' recipient@example.com', 'recipient', `${'a'.repeat(250)}@example.com`]) {
      await assert.rejects(sendTransactionalEmail({ ...message, to }, { env: cloudflare }), unconfirmed, to);
    }
    for (const subject of ['', 'x\r\nBcc:other@example.com', 'bad\0subject', 'tab\tsubject', 'bad subject', 'bad‮subject', 'x'.repeat(201), '\ud800']) {
      await assert.rejects(sendTransactionalEmail({ ...message, subject }, { env: cloudflare }), unconfirmed, JSON.stringify(subject));
    }
    for (const text of ['', '\udfff', 'bad\0text', 'bell\u0007', '😀'.repeat(16_385), 'é'.repeat(32_768) + 'a']) {
      await assert.rejects(sendTransactionalEmail({ ...message, text }, { env: cloudflare }), unconfirmed, text.slice(0, 20));
    }
    // @ts-expect-error An untrusted caller cannot add a raw HTML part or another field.
    await assert.rejects(sendTransactionalEmail({ ...message, html: '<img src="https://outside.example/">' }, { env: cloudflare }), unconfirmed);
    // @ts-expect-error Neither can it add a second recipient field.
    await assert.rejects(sendTransactionalEmail({ ...message, cc: 'other@example.com' }, { env: cloudflare }), unconfirmed);
    assert.equal(calls.fetch, 0, 'Refused input reaches no provider.');
    // The limits themselves are accepted: 200 characters, and 65,536 UTF-8 bytes of two-byte characters with tabs and line breaks.
    assert.deepEqual(await sendTransactionalEmail({ ...message, subject: 'x'.repeat(200) }, { env: cloudflare }), accepted);
    assert.deepEqual(await sendTransactionalEmail({ ...message, text: 'é'.repeat(32_767) + '\t\n' }, { env: cloudflare }), accepted);
  });
  assert.equal(calls.fetch, 2);
});

test('isSuppressed is consulted for every transport before any provider call; true, a throw or a rejection refuses', async () => {
  for (const [transport, env] of everyTransport) {
    const { calls, adapters } = transports();
    const looked: string[] = [];
    await withEmailTransportsForTests(adapters, async () => {
      await assert.rejects(sendTransactionalEmail(message, { env, isSuppressed: async address => { looked.push(address); return true; } }), unconfirmed, transport);
      await assert.rejects(sendTransactionalEmail(message, { env, isSuppressed: () => true }), unconfirmed, transport);
      await assert.rejects(sendTransactionalEmail(message, { env, isSuppressed: () => { throw new Error('database unavailable'); } }), unconfirmed, transport);
      await assert.rejects(sendTransactionalEmail(message, { env, isSuppressed: async () => { throw new Error('database unavailable'); } }), unconfirmed, transport);
      assert.deepEqual(calls, { fetch: 0, smtp: 0 }, `${transport}: a suppressed recipient reaches no provider`);
      assert.deepEqual(await sendTransactionalEmail(message, { env, isSuppressed: async address => { looked.push(address); return false; } }), accepted, transport);
    });
    assert.deepEqual(looked, [message.to, message.to]);
    assert.equal(calls.fetch + calls.smtp, 1, `${transport}: one provider call after a negative lookup`);
  }
});

test('SES sends one SigV4-signed SendEmail to the fixed regional origin through sendSesEmail', async () => {
  let calls = 0;
  const result = await withEmailTransportsForTests({ fetch: async (url, init) => {
    calls++;
    assert.equal(url, sesOrigin('eu-west-1') + '/v2/email/outbound-emails');
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error'); assert.ok(init.signal instanceof AbortSignal);
    assert.match(new Headers(init.headers).get('authorization') ?? '', /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/\d{8}\/eu-west-1\/ses\/aws4_request, /);
    const body = JSON.parse(String(init.body));
    assert.equal(body.FromEmailAddress, 'sender@example.com'); assert.deepEqual(body.Destination, { ToAddresses: [message.to] });
    assert.equal(body.ConfigurationSetName, 'transactional-1');
    assert.equal(body.Content.Simple.Subject.Data, message.subject); assert.equal(body.Content.Simple.Body.Text.Data, message.text);
    assert.ok(!String(init.body).includes(ses.EMAIL_SES_SECRET_ACCESS_KEY));
    return sesReply();
  } }, () => sendTransactionalEmail(message, { env: { ...ses, EMAIL_SES_CONFIGURATION_SET: 'transactional-1' } }));
  assert.deepEqual(result, accepted); assert.equal(calls, 1);
});

test('Cloudflare sends one request with escaped generated HTML; delivered and queued are both reported as unconfirmed', async () => {
  let calls = 0;
  const text = '<script>"private" & \'link\'</script>\n😀';
  const result = await withEmailTransportsForTests({ fetch: async (url, init) => {
    calls++; assert.equal(url, 'https://api.cloudflare.com/client/v4/accounts/' + 'a'.repeat(32) + '/email/sending/send');
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error');
    assert.deepEqual(JSON.parse(String(init.body)), { from: 'sender@example.com', to: [message.to], subject: '😀', text, html: '<div>&lt;script&gt;&quot;private&quot; &amp; &#39;link&#39;&lt;/script&gt;<br>😀</div>' });
    return json(receipt());
  } }, () => sendTransactionalEmail({ ...message, subject: '😀', text }, { env: cloudflare }));
  assert.deepEqual(result, accepted); assert.equal(calls, 1);
  assert.deepEqual(await withEmailTransportsForTests({ fetch: async () => json(receipt([message.to], [])) }, () => sendTransactionalEmail(message, { env: cloudflare })), accepted);
  for (const reply of [receipt([], [], [message.to]), receipt([], [], [], [message.to]), receipt(['other@example.com'], []), { ...receipt(), success: false }]) {
    await assert.rejects(withEmailTransportsForTests({ fetch: async () => json(reply) }, () => sendTransactionalEmail(message, { env: cloudflare })), unconfirmed);
  }
});

test('SMTP forces authentication, requires TLS 1.2 or later on the configured name and closes its owned socket', async () => {
  let calls = 0, closes = 0;
  for (const tls of ['starttls', 'tls']) {
    let socket: Socket | undefined;
    const result = await withEmailTransportsForTests({ smtp(options) {
      calls++; socket = options.socket; assert.equal(socket.destroyed, false);
      assert.equal(options.host, 'smtp.example.com'); assert.equal(options.port, tls === 'tls' ? 465 : 587); assert.equal(options.secure, tls === 'tls');
      assert.equal(options.requireTLS, true); assert.equal(options.ignoreTLS, false); assert.equal(options.opportunisticTLS, false);
      assert.equal(options.forceAuth, true); assert.deepEqual(options.auth, { user: 'login', pass: 'short-password' });
      assert.deepEqual(options.tls, { minVersion: 'TLSv1.2', rejectUnauthorized: true, servername: 'smtp.example.com' });
      assert.equal(options.maxRecipients, 1); assert.equal(options.disableFileAccess, true); assert.equal(options.disableUrlAccess, true);
      assert.equal(options.logger, false); assert.equal(options.debug, false); assert.equal(options.transactionLog, false);
      return { async sendMail(mail) { assert.deepEqual({ ...mail, html: undefined }, { from: 'sender@example.com', ...message, html: undefined }); return { accepted: [message.to], rejected: [] }; }, close() { closes++; } };
    } }, () => sendTransactionalEmail(message, { env: { ...smtp, EMAIL_SMTP_TLS: tls } }));
    assert.deepEqual(result, accepted); assert.equal(socket?.destroyed, true);
  }
  assert.equal(calls, 2); assert.equal(closes, 2);
  let port = 0;
  await withEmailTransportsForTests({ smtp(options) { port = options.port; return smtpSender(); } }, () => sendTransactionalEmail(message, { env: { ...smtp, EMAIL_SMTP_PORT: '2525' } }));
  assert.equal(port, 2525);
});

test('one attempt and one recipient: a rejected, mismatched or failed send is not retried', async () => {
  let calls = 0, closes = 0;
  for (const reply of [{ accepted: [], rejected: [] }, { accepted: ['other@example.com'], rejected: [] }, { accepted: [message.to, 'other@example.com'], rejected: [] }, { accepted: [message.to], rejected: [message.to] }, { accepted: [message.to], rejected: [], pending: [message.to] }, null]) {
    await assert.rejects(withEmailTransportsForTests({ smtp() { calls++; return smtpSender(reply, () => { closes++; }); } }, () => sendTransactionalEmail(message, { env: smtp })), unconfirmed);
  }
  assert.equal(calls, 6); assert.equal(closes, 6);
  for (const response of [() => new Response('', { status: 500 }), () => new Response('', { status: 429 }), () => json({ success: false, errors: [{ code: 10001 }] }, 400)]) {
    let fetches = 0;
    await assert.rejects(withEmailTransportsForTests({ fetch: async () => { fetches++; return response(); } }, () => sendTransactionalEmail(message, { env: cloudflare })), unconfirmed);
    await assert.rejects(withEmailTransportsForTests({ fetch: async () => { fetches++; return response(); } }, () => sendTransactionalEmail(message, { env: ses })), unconfirmed);
    assert.equal(fetches, 2, 'One request per send; no automatic retry.');
  }
});

test('the 15-second limit covers the whole send: a stalled SMTP send, response body or suppression lookup', { timeout: 10_000 }, async context => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  let calls = 0, closes = 0, socket: Socket | undefined, rejectLate: ((reason: Error) => void) | undefined;
  const stalledSmtp = withEmailTransportsForTests({ smtp(options) { calls++; socket = options.socket; return { sendMail: () => new Promise((_, reject) => { rejectLate = reject; }), close() { closes++; } }; } },
    () => sendTransactionalEmail(message, { env: smtp }));
  assert.equal(calls, 1); context.mock.timers.tick(14_999); await Promise.resolve(); assert.equal(closes, 0);
  context.mock.timers.tick(1); await assert.rejects(stalledSmtp, unconfirmed);
  assert.equal(socket?.destroyed, true); assert.equal(closes, 1);
  const closed = socket!;
  assert.throws(() => closed.connect(587, 'smtp.example.com'), EmailDeliveryError, 'A late DNS callback cannot dial the destroyed socket.');
  rejectLate?.(new Error('late private-token rejection'));
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(calls, 1); assert.equal(closes, 1);

  let cancelled = 0;
  const response = new Response(new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { cancelled++; } }), { headers: { 'content-type': 'application/json' } });
  const stalledBody = withEmailTransportsForTests({ fetch: async () => response }, () => sendTransactionalEmail(message, { env: cloudflare }));
  for (let turn = 0; turn < 20 && !response.body?.locked; turn++) await Promise.resolve();
  assert.equal(response.body?.locked, true); context.mock.timers.tick(15_000); await assert.rejects(stalledBody, unconfirmed);
  assert.equal(cancelled, 1);

  const { calls: providerCalls, adapters } = transports();
  const stalledLookup = withEmailTransportsForTests(adapters, () => sendTransactionalEmail(message, { env: ses, isSuppressed: () => new Promise<boolean>(() => {}) }));
  context.mock.timers.tick(15_000); await assert.rejects(stalledLookup, unconfirmed);
  assert.deepEqual(providerCalls, { fetch: 0, smtp: 0 });
});

test('message contents, credentials and provider errors are never logged nor carried by the error', async context => {
  const secrets = [message.text, message.subject, 'private-token', 'short-password', 'test-token', ses.EMAIL_SES_SECRET_ACCESS_KEY, 'provider-detail'];
  const written: string[] = [];
  for (const method of ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const) context.mock.method(console, method, (...args: unknown[]) => { written.push(args.map(String).join(' ')); });
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write.bind(stream);
    context.mock.method(stream, 'write', (chunk: unknown, ...rest: never[]) => { written.push(String(chunk)); return original(chunk as string, ...rest); });
  }
  const failures: Promise<unknown>[] = [
    withEmailTransportsForTests({ smtp() { return { async sendMail() { throw new Error('provider-detail ' + message.text); }, close() {} }; } }, () => sendTransactionalEmail(message, { env: smtp })),
    withEmailTransportsForTests({ fetch: async () => new Response('provider-detail private-token ' + message.text, { status: 403 }) }, () => sendTransactionalEmail(message, { env: cloudflare })),
    withEmailTransportsForTests({ fetch: async () => { throw new Error('provider-detail ' + ses.EMAIL_SES_SECRET_ACCESS_KEY); } }, () => sendTransactionalEmail(message, { env: ses })),
    sendTransactionalEmail(message, { env: ses, isSuppressed: () => { throw new Error('provider-detail ' + message.to); } }),
  ];
  for (const failure of failures) {
    const error = await failure.then(() => assert.fail('the send succeeded'), (reason: unknown) => reason);
    assert.ok(error instanceof EmailDeliveryError); assert.equal(error.cause, undefined);
    const shown = inspect(error, { depth: 5 }) + JSON.stringify(error);
    for (const value of secrets) assert.ok(!shown.includes(value), `the error carries ${value}`);
  }
  for (const value of secrets) assert.ok(!written.some(line => line.includes(value)), `logged ${value}`);
});

test('nodemailer is an optional peer loaded by dynamic import, so the entry loads without it', async () => {
  const built = readFileSync(new URL('../email.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(built, /^\s*import\b[^(]*['"]nodemailer['"]/m, 'no static import of nodemailer');
  assert.match(built, /import\('nodemailer'\)/);
  assert.doesNotMatch(readFileSync(new URL('../email.d.mts', import.meta.url), 'utf8'), /nodemailer['"]/, 'the declarations do not need nodemailer types');
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const profile = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8')).profiles['@ten98/runtime'];
  assert.equal(manifest.peerDependencies.nodemailer, '10.1.4'); assert.deepEqual(manifest.peerDependenciesMeta.nodemailer, { optional: true });
  assert.equal(profile.peerDependencies.nodemailer, '10.1.4');
  assert.deepEqual(manifest.exports['./email'], { types: './email.d.mts', import: './email.mjs' });
  // The named ESM export the SMTP path relies on.
  assert.equal(typeof (await import('nodemailer')).createTransport, 'function');
});
